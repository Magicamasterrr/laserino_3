#!/usr/bin/env python3
"""Laserino-3: operator-side tooling for TheDivineNFT sanctified lanes, inventory slices, chain checks, and pulse telemetry."""

from __future__ import annotations

import argparse
import asyncio
import dataclasses
import hashlib
import hmac
import json
import logging
import os
import queue
import random
import secrets
import socket
import ssl
import struct
import sys
import threading
import time
import urllib.error
import urllib.request
import uuid
from collections import deque
from concurrent.futures import ThreadPoolExecutor, as_completed
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable, Deque, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple, Type, TypeVar

try:
    from eth_abi import encode as eth_abi_encode  # type: ignore
except Exception:  # pragma: no cover
    eth_abi_encode = None

try:
    from eth_account import Account
    from eth_account.messages import encode_defunct
except Exception:  # pragma: no cover
    Account = None
    encode_defunct = None

try:
    from web3 import Web3
except Exception:  # pragma: no cover
    Web3 = None

T = TypeVar("T")
LOG = logging.getLogger("laserino_3")


def keccak256(data: bytes) -> bytes:
    try:
        from Crypto.Hash import keccak

        k = keccak.new(digest_bits=256)
        k.update(data)
        return k.digest()
    except Exception:
        try:
            import sha3  # type: ignore

            k = sha3.keccak_256()
            k.update(data)
            return k.digest()
        except Exception:
            raise RuntimeError(
                "keccak256 requires pycryptodome or pysha3; pip install pycryptodome"
            ) from None


def pad32(b: bytes) -> bytes:
    return b.rjust(32, b"\x00")[-32:]


def addr_to_bytes(addr: str) -> bytes:
    hx = addr.lower().removeprefix("0x")
    if len(hx) != 40:
        raise ValueError("address length")
    return bytes.fromhex(hx)


def u256_bytes(x: int) -> bytes:
    if x < 0 or x >= 1 << 256:
        raise ValueError("u256 range")
    return x.to_bytes(32, "big")


def encode_divine_order_struct(
    order_typehash: bytes,
    token_id: int,
    price_wei: int,
    nonce: int,
    deadline: int,
    buyer: str,
) -> bytes:
    if eth_abi_encode is None:
        raise RuntimeError("eth_abi is required for precise struct hashing; pip install eth_abi")
    if Web3 is None:
        buyer_a = buyer
    else:
        buyer_a = Web3.to_checksum_address(buyer)
    payload = eth_abi_encode(
        ["bytes32", "uint256", "uint256", "uint256", "uint256", "address"],
        [order_typehash, token_id, price_wei, nonce, deadline, buyer_a],
    )
    return keccak256(payload)


def eip712_digest(domain_separator: bytes, struct_hash: bytes) -> bytes:
    if len(domain_separator) != 32 or len(struct_hash) != 32:
        raise ValueError("digest inputs")
    return keccak256(b"\x19\x01" + domain_separator + struct_hash)


@dataclasses.dataclass(frozen=True)
class RpcEndpoint:
    url: str
    weight: int = 1
    name: str = "rpc"


@dataclasses.dataclass
class LaserinoConfig:
    rpc_urls: Tuple[RpcEndpoint, ...]
    contract_address: str
    chain_id: int
    poll_interval_s: float = 1.25
    pulse_tag_seed: str = "divine-lane"
    http_timeout_s: float = 22.0
    max_retries: int = 5
    max_inflight: int = 8


class StructuredLogger:
    def __init__(self, name: str) -> None:
        self._log = logging.getLogger(name)

    def event(self, kind: str, **fields: Any) -> None:
        payload = {"kind": kind, "ts": time.time(), **fields}
        self._log.info(json.dumps(payload, default=str))


class RingBuffer:
    def __init__(self, capacity: int) -> None:
        self._cap = max(1, capacity)
        self._buf: Deque[Any] = deque(maxlen=self._cap)

    def push(self, item: Any) -> None:
        self._buf.append(item)

    def snapshot(self) -> List[Any]:
        return list(self._buf)


class ExponentialBackoff:
    def __init__(self, base: float = 0.35, factor: float = 1.85, max_sleep: float = 28.0) -> None:
        self.base = base
        self.factor = factor
        self.max_sleep = max_sleep
        self.attempt = 0

    def sleep_for_next(self) -> float:
        self.attempt += 1
        return min(self.max_sleep, self.base * (self.factor ** (self.attempt - 1)))

    def reset(self) -> None:
        self.attempt = 0


def stable_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str)


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def hmac_tag(secret: bytes, msg: bytes) -> str:
    return hmac.new(secret, msg, hashlib.sha256).hexdigest()


def pick_weighted_endpoints(endpoints: Sequence[RpcEndpoint]) -> RpcEndpoint:
    total = sum(e.weight for e in endpoints) or 1
    r = random.uniform(0, total)
    acc = 0.0
    for e in endpoints:
        acc += e.weight
        if r <= acc:
            return e
    return endpoints[-1]


class HttpJsonClient:
    def __init__(self, timeout_s: float) -> None:
        self.timeout_s = timeout_s

    def post_json(self, url: str, body: Mapping[str, Any]) -> Any:
        data = stable_json(body).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=data,
            headers={"Content-Type": "application/json", "User-Agent": "laserino_3/3"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout_s) as resp:
                raw = resp.read().decode("utf-8")
                return json.loads(raw)
        except urllib.error.HTTPError as e:
            raise RuntimeError(f"http_error status={e.code}") from e
        except urllib.error.URLError as e:
            raise RuntimeError(f"url_error {e}") from e


ABI_MIN: List[Dict[str, Any]] = [
    {
        "inputs": [],
        "name": "DOMAIN_SEPARATOR",
        "outputs": [{"internalType": "bytes32", "name": "", "type": "bytes32"}],
        "stateMutability": "view",
        "type": "function",
    },
    {
        "inputs": [
            {"internalType": "uint256", "name": "tokenId", "type": "uint256"},
            {"internalType": "uint256", "name": "priceWei", "type": "uint256"},
            {"internalType": "uint256", "name": "nonce", "type": "uint256"},
            {"internalType": "uint256", "name": "deadline", "type": "uint256"},
            {"internalType": "address", "name": "buyer", "type": "address"},
        ],
        "name": "hashOrder",
        "outputs": [{"internalType": "bytes32", "name": "", "type": "bytes32"}],
        "stateMutability": "view",
        "type": "function",
    },
    {
        "inputs": [],
        "name": "ORDER_TYPEHASH",
        "outputs": [{"internalType": "bytes32", "name": "", "type": "bytes32"}],
        "stateMutability": "view",
        "type": "function",
    },
    {
        "inputs": [],
        "name": "totalMinted",
        "outputs": [{"internalType": "uint256", "name": "", "type": "uint256"}],
        "stateMutability": "view",
        "type": "function",
    },
    {
        "inputs": [],
        "name": "circulatingSupply",
        "outputs": [{"internalType": "uint256", "name": "", "type": "uint256"}],
        "stateMutability": "view",
        "type": "function",
    },
    {
        "inputs": [],
        "name": "totalSupply",
        "outputs": [{"internalType": "uint256", "name": "", "type": "uint256"}],
        "stateMutability": "view",
        "type": "function",
    },
    {
        "inputs": [{"internalType": "uint256", "name": "index", "type": "uint256"}],
        "name": "tokenByIndex",
        "outputs": [{"internalType": "uint256", "name": "", "type": "uint256"}],
        "stateMutability": "view",
        "type": "function",
    },
]


def rpc_call(url: str, method: str, params: Any, timeout_s: float) -> Any:
    client = HttpJsonClient(timeout_s)
    payload = {"jsonrpc": "2.0", "id": secrets.randbelow(1_000_000), "method": method, "params": params}
    resp = client.post_json(url, payload)
    if "error" in resp:
        raise RuntimeError(str(resp["error"]))
    return resp["result"]


def eth_call_contract(url: str, to: str, data: str, timeout_s: float) -> bytes:
    res = rpc_call(url, "eth_call", [{"to": to, "data": data}, "latest"], timeout_s)
    hx = res.removeprefix("0x")
    if hx == "":
        return b""
    return bytes.fromhex(hx)


def selector(sig: str) -> bytes:
