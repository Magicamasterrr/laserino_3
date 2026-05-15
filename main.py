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
    return keccak256(sig.encode("ascii"))[:4]


def encode_call(sig: str, types: Sequence[str], values: Sequence[Any]) -> str:
    if eth_abi_encode is None:
        raise RuntimeError("eth_abi required")
    head = selector(sig)
    body = eth_abi_encode(list(types), list(values))
    return "0x" + (head + body).hex()


def encode_export_inventory_slice_call(start: int, count: int) -> str:
    """eth_call data for TheDivineNFT.exportInventorySlice(uint256,uint256)."""
    if eth_abi_encode is None:
        raise RuntimeError("eth_abi required")
    head = selector("exportInventorySlice(uint256,uint256)")
    body = eth_abi_encode(["uint256", "uint256"], [start, count])
    return "0x" + (head + body).hex()


def _read_u256_word(mem: bytes, word_index: int) -> int:
    off = word_index * 32
    chunk = mem[off : off + 32]
    if len(chunk) != 32:
        raise ValueError("short_abi_word")
    return int.from_bytes(chunk, "big")


def decode_uint256_array_abi(ret: bytes) -> List[int]:
    """Decode ABI-encoded uint256[] from eth_call return bytes (dynamic array layout)."""
    if len(ret) < 32:
        raise ValueError("return_too_short")
    offset = _read_u256_word(ret, 0)
    if offset % 32 != 0:
        raise ValueError("bad_offset_alignment")
    start_word = offset // 32
    if start_word >= len(ret) // 32:
        raise ValueError("offset_out_of_range")
    length = _read_u256_word(ret, start_word)
    first_el = start_word + 1
    need_words = first_el + length
    if need_words > len(ret) // 32:
        raise ValueError("length_out_of_range")
    out: List[int] = []
    for i in range(length):
        out.append(_read_u256_word(ret, first_el + i))
    return out


def decode_u256_return(ret: bytes) -> int:
    if len(ret) < 32:
        raise ValueError("u256_return_short")
    return _read_u256_word(ret, 0)


def parse_rpc_url_cli(spec: Optional[str], single_rpc: str) -> Tuple[RpcEndpoint, ...]:
    if spec:
        parts = [p.strip() for p in spec.split(",") if p.strip()]
        if not parts:
            raise ValueError("rpc_list_empty")
        return tuple(RpcEndpoint(u, 1, f"lane{i}") for i, u in enumerate(parts))
    return (RpcEndpoint(single_rpc, 1, "cli"),)


def load_runtime_profile(path: Path) -> Dict[str, Any]:
    blob = path.expanduser().read_text(encoding="utf-8")
    data = json.loads(blob)
    if not isinstance(data, dict):
        raise ValueError("profile_root_must_be_object")
    return data


def merge_runtime_profile(
    cfg: LaserinoConfig,
    prof: Mapping[str, Any],
    *,
    rpc_list_from_cli: bool,
) -> LaserinoConfig:
    urls: List[RpcEndpoint] = list(cfg.rpc_urls)
    if isinstance(prof.get("rpc_urls"), list) and not rpc_list_from_cli:
        urls = [RpcEndpoint(str(u), 1, "json_profile") for u in prof["rpc_urls"]]
    elif "rpc" in prof and not rpc_list_from_cli:
        urls = [RpcEndpoint(str(prof["rpc"]), 1, "json_profile")]
    patch: Dict[str, Any] = {"rpc_urls": tuple(urls)}
    if "contract" in prof:
        patch["contract_address"] = str(prof["contract"])
    if "chain_id" in prof:
        patch["chain_id"] = int(prof["chain_id"])
    if "pulse_tag_seed" in prof:
        patch["pulse_tag_seed"] = str(prof["pulse_tag_seed"])
    if "poll_interval_s" in prof:
        patch["poll_interval_s"] = float(prof["poll_interval_s"])
    if "http_timeout_s" in prof:
        patch["http_timeout_s"] = float(prof["http_timeout_s"])
    if "max_retries" in prof:
        patch["max_retries"] = int(prof["max_retries"])
    return dataclasses.replace(cfg, **patch)


def encode_sanctified_buy_with_data_call(
    token_id: int,
    price_wei: int,
    deadline: int,
    buyer: str,
    hook_data: bytes,
    v: int,
    r: bytes,
    s: bytes,
) -> str:
    """ABI calldata for TheDivineNFT.sanctifiedBuyWithData(uint256,uint256,uint256,address,bytes,uint8,bytes32,bytes32)."""
    if eth_abi_encode is None:
        raise RuntimeError("eth_abi required")
    if len(r) != 32 or len(s) != 32:
        raise ValueError("r_or_s_not_32_bytes")
    if v < 0 or v > 255:
        raise ValueError("v_byte_range")
    buyer_a = Web3.to_checksum_address(buyer) if Web3 is not None else buyer
    head = selector("sanctifiedBuyWithData(uint256,uint256,uint256,address,bytes,uint8,bytes32,bytes32)")
    body = eth_abi_encode(
        ["uint256", "uint256", "uint256", "address", "bytes", "uint8", "bytes32", "bytes32"],
        [token_id, price_wei, deadline, buyer_a, hook_data, v, r, s],
    )
    return "0x" + (head + body).hex()


class DivineBridge:
    def __init__(self, cfg: LaserinoConfig) -> None:
        self.cfg = cfg
        self.http = HttpJsonClient(cfg.http_timeout_s)
        self.slog = StructuredLogger("laserino_3.bridge")
        self.history = RingBuffer(640)
        self.backoff = ExponentialBackoff()

    def _rpc_url(self) -> str:
        return pick_weighted_endpoints(self.cfg.rpc_urls).url

    def snapshot_metrics(self) -> Dict[str, Any]:
        if Web3 is None:
            return self._snapshot_metrics_raw()
        w3 = Web3(Web3.HTTPProvider(self._rpc_url(), request_kwargs={"timeout": self.cfg.http_timeout_s}))
        c = w3.eth.contract(address=Web3.to_checksum_address(self.cfg.contract_address), abi=ABI_MIN)
        dom = c.functions.DOMAIN_SEPARATOR().call()
        minted = int(c.functions.totalMinted().call())
        circ = int(c.functions.circulatingSupply().call())
        supply = int(c.functions.totalSupply().call())
        out = {
            "domain_separator": dom.hex() if hasattr(dom, "hex") else Web3.to_hex(dom),
            "minted": minted,
            "circulating": circ,
            "inventory": supply,
        }
        self.history.push(out)
        return out

    def _snapshot_metrics_raw(self) -> Dict[str, Any]:
        url = self._rpc_url()
        to = self.cfg.contract_address
        ds = encode_call("DOMAIN_SEPARATOR()", [], [])
        raw = eth_call_contract(url, to, ds, self.cfg.http_timeout_s)
        out = {"domain_separator": raw.hex(), "minted": -1, "circulating": -1, "inventory": -1}
        self.history.push(out)
        return out

    def fetch_order_typehash(self) -> bytes:
        url = self._rpc_url()
        to = self.cfg.contract_address
        data = encode_call("ORDER_TYPEHASH()", [], [])
        raw = eth_call_contract(url, to, data, self.cfg.http_timeout_s)
        if len(raw) != 32:
            raise RuntimeError("ORDER_TYPEHASH bad length")
        return raw

    def fetch_domain_separator(self) -> bytes:
        url = self._rpc_url()
        to = self.cfg.contract_address
        data = encode_call("DOMAIN_SEPARATOR()", [], [])
        raw = eth_call_contract(url, to, data, self.cfg.http_timeout_s)
        if len(raw) != 32:
            raise RuntimeError("DOMAIN_SEPARATOR bad length")
        return raw

    def hash_order_local(
        self,
        token_id: int,
        price_wei: int,
        nonce: int,
        deadline: int,
        buyer: str,
    ) -> bytes:
        oth = self.fetch_order_typehash()
        dom = self.fetch_domain_separator()
        struct_hash = encode_divine_order_struct(oth, token_id, price_wei, nonce, deadline, buyer)
        return eip712_digest(dom, struct_hash)

    def hash_order_chain(
        self,
