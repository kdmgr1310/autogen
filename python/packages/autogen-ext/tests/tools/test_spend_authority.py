import asyncio
import base64
import hashlib
import json
import sqlite3
from collections.abc import Callable
from pathlib import Path
from typing import Any

import httpx
import pytest
from autogen_core import CancellationToken
from autogen_core.tools import FunctionTool, Tool
from autogen_ext.tools.spend_authority import (
    ReceiptChainError,
    SpendAuthorityTool,
    SpendAuthorizationError,
    verify_receipt_chain,
)
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def _canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _public_key_bytes(private_key: Ed25519PrivateKey) -> bytes:
    return private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def _signed_verdict(
    private_key: Ed25519PrivateKey,
    caller_id: str = "agent-1",
    operation_id: str = "call-1",
    decision: str = "allow",
    request_hash: str | None = None,
) -> dict[str, Any]:
    if request_hash is None:
        request = {
            "protocol_version": 1,
            "caller_id": caller_id,
            "operation_id": operation_id,
            "tool_name": "purchase",
            "arguments": {"item": "book"},
        }
        request_hash = hashlib.sha256(_canonical_json(request)).hexdigest()
    verdict: dict[str, Any] = {
        "protocol_version": 1,
        "caller_id": caller_id,
        "operation_id": operation_id,
        "request_hash": request_hash,
        "decision": decision,
        "key_id": "test-key",
    }
    verdict["signature"] = base64.b64encode(private_key.sign(_canonical_json(verdict))).decode("ascii")
    return verdict


def _wrapped_tool(
    ledger_path: Path,
    client: httpx.AsyncClient,
    private_key: Ed25519PrivateKey,
    tool: FunctionTool,
) -> SpendAuthorityTool:
    return SpendAuthorityTool(
        tool=tool,
        authority_url="https://authority.example/authorize",
        caller_id="agent-1",
        public_keys={"test-key": _public_key_bytes(private_key)},
        ledger_path=ledger_path,
        client=client,
    )


@pytest.mark.asyncio
async def test_signed_allow_runs_tool_and_persists_verifiable_receipts(tmp_path: Path) -> None:
    private_key = Ed25519PrivateKey.generate()
    tool_runs = 0
    seen_body: dict[str, Any] = {}

    async def purchase(item: str) -> str:
        nonlocal tool_runs
        tool_runs += 1
        return f"purchased {item}"

    async def handler(request: httpx.Request) -> httpx.Response:
        nonlocal seen_body
        seen_body = json.loads(request.content)
        return httpx.Response(
            200,
            json=_signed_verdict(private_key, operation_id="call-1"),
        )

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    wrapped = _wrapped_tool(tmp_path / "receipts.db", client, private_key, FunctionTool(purchase, "Purchase an item"))
    assert isinstance(wrapped, Tool)
    result = await wrapped.run_json({"item": "book"}, CancellationToken(), call_id="call-1")

    assert result == "purchased book"
    assert tool_runs == 1
    assert seen_body == {
        "protocol_version": 1,
        "caller_id": "agent-1",
        "operation_id": "call-1",
        "tool_name": "purchase",
        "arguments": {"item": "book"},
    }
    assert verify_receipt_chain(tmp_path / "receipts.db", {"test-key": _public_key_bytes(private_key)}) == 2
    await client.aclose()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("response_factory", "message"),
    [
        (lambda key: httpx.Response(403), "non-2xx"),
        (lambda key: httpx.Response(302, headers={"location": "https://other.example/"}), "non-2xx"),
        (lambda key: httpx.Response(200, content=b"not json"), "malformed JSON"),
        (
            lambda key: httpx.Response(
                200,
                json=_signed_verdict(key, operation_id="call-1", request_hash="0" * 64),
            ),
            "invalid or did not match",
        ),
        (
            lambda key: httpx.Response(200, json=_signed_verdict(key, operation_id="call-1", decision="deny")),
            "denied",
        ),
        (lambda key: httpx.Response(200, json={"decision": "allow"}), "malformed verdict"),
    ],
)
async def test_authorization_failures_never_run_tool(
    tmp_path: Path, response_factory: Callable[[Ed25519PrivateKey], httpx.Response], message: str
) -> None:
    private_key = Ed25519PrivateKey.generate()
    tool_runs = 0

    async def purchase(item: str) -> str:
        nonlocal tool_runs
        tool_runs += 1
        return item

    async def handler(request: httpx.Request) -> httpx.Response:
        return response_factory(private_key)

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    wrapped = _wrapped_tool(tmp_path / "receipts.db", client, private_key, FunctionTool(purchase, "Purchase"))
    with pytest.raises(SpendAuthorizationError, match=message):
        await wrapped.run_json({"item": "book"}, CancellationToken(), call_id="call-1")

    assert tool_runs == 0
    assert verify_receipt_chain(tmp_path / "receipts.db", {"test-key": _public_key_bytes(private_key)}) == 2
    await client.aclose()


@pytest.mark.asyncio
async def test_timeout_is_fail_closed(tmp_path: Path) -> None:
    private_key = Ed25519PrivateKey.generate()
    tool_runs = 0

    async def purchase(item: str) -> str:
        nonlocal tool_runs
        tool_runs += 1
        return item

    async def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("authority timed out")

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    wrapped = SpendAuthorityTool(
        FunctionTool(purchase, "Purchase"),
        "https://authority.example/authorize",
        "agent-1",
        {"test-key": _public_key_bytes(private_key)},
        tmp_path / "receipts.db",
        client=client,
    )
    with pytest.raises(SpendAuthorizationError, match="request failed"):
        await wrapped.run_json({"item": "book"}, CancellationToken(), call_id="call-1")

    assert tool_runs == 0
    assert verify_receipt_chain(tmp_path / "receipts.db", {"test-key": _public_key_bytes(private_key)}) == 2
    await client.aclose()


@pytest.mark.asyncio
async def test_invalid_signature_never_runs_tool(tmp_path: Path) -> None:
    signing_key = Ed25519PrivateKey.generate()
    wrong_key = Ed25519PrivateKey.generate()
    tool_runs = 0

    async def purchase(item: str) -> str:
        nonlocal tool_runs
        tool_runs += 1
        return item

    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=_signed_verdict(wrong_key, operation_id="call-1"))

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    wrapped = _wrapped_tool(tmp_path / "receipts.db", client, signing_key, FunctionTool(purchase, "Purchase"))
    with pytest.raises(SpendAuthorizationError, match="verdict was invalid"):
        await wrapped.run_json({"item": "book"}, CancellationToken(), call_id="call-1")

    assert tool_runs == 0
    assert verify_receipt_chain(tmp_path / "receipts.db") == 2
    await client.aclose()


@pytest.mark.asyncio
async def test_duplicate_operations_are_blocked_after_restart(tmp_path: Path) -> None:
    private_key = Ed25519PrivateKey.generate()
    authority_calls = 0
    tool_runs = 0
    ledger_path = tmp_path / "receipts.db"

    async def purchase(item: str) -> str:
        nonlocal tool_runs
        tool_runs += 1
        return item

    async def handler(request: httpx.Request) -> httpx.Response:
        nonlocal authority_calls
        authority_calls += 1
        return httpx.Response(200, json=_signed_verdict(private_key, operation_id="call-1"))

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    original = _wrapped_tool(ledger_path, client, private_key, FunctionTool(purchase, "Purchase"))
    await original.run_json({"item": "book"}, CancellationToken(), call_id="call-1")

    restarted = _wrapped_tool(ledger_path, client, private_key, FunctionTool(purchase, "Purchase"))
    with pytest.raises(SpendAuthorizationError, match="Duplicate"):
        await restarted.run_json({"item": "book"}, CancellationToken(), call_id="call-1")

    assert authority_calls == 1
    assert tool_runs == 1
    assert verify_receipt_chain(ledger_path, {"test-key": _public_key_bytes(private_key)}) == 3
    await client.aclose()


@pytest.mark.asyncio
async def test_concurrent_duplicate_calls_only_reach_authority_once(tmp_path: Path) -> None:
    private_key = Ed25519PrivateKey.generate()
    authority_calls = 0
    tool_runs = 0

    async def purchase(item: str) -> str:
        nonlocal tool_runs
        tool_runs += 1
        return item

    async def handler(request: httpx.Request) -> httpx.Response:
        nonlocal authority_calls
        authority_calls += 1
        await asyncio.sleep(0.05)
        return httpx.Response(200, json=_signed_verdict(private_key, operation_id="same-call"))

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    wrapped = _wrapped_tool(tmp_path / "receipts.db", client, private_key, FunctionTool(purchase, "Purchase"))
    outcomes = await asyncio.gather(
        wrapped.run_json({"item": "book"}, CancellationToken(), call_id="same-call"),
        wrapped.run_json({"item": "book"}, CancellationToken(), call_id="same-call"),
        return_exceptions=True,
    )

    assert sum(outcome == "book" for outcome in outcomes) == 1
    assert sum(isinstance(outcome, SpendAuthorizationError) for outcome in outcomes) == 1
    assert authority_calls == 1
    assert tool_runs == 1
    assert verify_receipt_chain(tmp_path / "receipts.db", {"test-key": _public_key_bytes(private_key)}) == 3
    await client.aclose()


def test_receipt_chain_detects_tampering(tmp_path: Path) -> None:
    private_key = Ed25519PrivateKey.generate()
    ledger_path = tmp_path / "receipts.db"

    async def purchase(item: str) -> str:
        return item

    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=_signed_verdict(private_key, operation_id="call-1"))

    async def create_receipt() -> None:
        client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        wrapped = _wrapped_tool(ledger_path, client, private_key, FunctionTool(purchase, "Purchase"))
        await wrapped.run_json({"item": "book"}, CancellationToken(), call_id="call-1")
        await client.aclose()

    asyncio.run(create_receipt())
    with sqlite3.connect(ledger_path) as connection:
        connection.execute(
            "UPDATE receipts SET receipt_json = replace(receipt_json, 'authorization_started', 'authorization_starteX') "
            "WHERE sequence = 1"
        )

    with pytest.raises(ReceiptChainError, match="hash is invalid"):
        verify_receipt_chain(ledger_path)
