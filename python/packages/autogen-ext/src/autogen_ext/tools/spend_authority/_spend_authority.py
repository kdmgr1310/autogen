import asyncio
import base64
import hashlib
import json
import sqlite3
from collections.abc import Mapping
from pathlib import Path
from typing import Any, Type

import httpx
from autogen_core import CancellationToken
from autogen_core.tools import Tool, ToolSchema
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from pydantic import BaseModel

_GENESIS_HASH = "0" * 64
_PROTOCOL_VERSION = 1
_VERDICT_FIELDS = {"protocol_version", "caller_id", "operation_id", "request_hash", "decision", "key_id", "signature"}


class SpendAuthorizationError(RuntimeError):
    """Raised when spend authorization is denied or cannot be verified."""


class ReceiptChainError(RuntimeError):
    """Raised when a persisted receipt chain fails verification."""


def _canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"Duplicate JSON key: {key}")
        value[key] = item
    return value


def _connect(database_path: str) -> sqlite3.Connection:
    connection = sqlite3.connect(database_path, timeout=30)
    connection.execute("PRAGMA busy_timeout = 30000")
    return connection


def _append_receipt(
    connection: sqlite3.Connection,
    event: str,
    caller_id: str,
    operation_id: str,
    details: Mapping[str, Any],
) -> None:
    row = connection.execute("SELECT sequence, receipt_hash FROM receipts ORDER BY sequence DESC LIMIT 1").fetchone()
    sequence = 1 if row is None else row[0] + 1
    previous_hash = _GENESIS_HASH if row is None else row[1]
    receipt = {
        "sequence": sequence,
        "previous_hash": previous_hash,
        "event": event,
        "caller_id": caller_id,
        "operation_id": operation_id,
        "details": dict(details),
    }
    receipt_json = _canonical_json(receipt).decode("utf-8")
    receipt_hash = hashlib.sha256(receipt_json.encode("utf-8")).hexdigest()
    connection.execute(
        "INSERT INTO receipts (sequence, previous_hash, receipt_json, receipt_hash) VALUES (?, ?, ?, ?)",
        (sequence, previous_hash, receipt_json, receipt_hash),
    )


def _verify_verdict_signature(
    verdict: Mapping[str, Any],
    public_keys: Mapping[str, Ed25519PublicKey],
    caller_id: str,
    operation_id: str,
    request_hash: str,
) -> None:
    if set(verdict) != _VERDICT_FIELDS:
        raise ValueError("Verdict fields are invalid")
    if (
        isinstance(verdict["protocol_version"], bool)
        or not isinstance(verdict["protocol_version"], int)
        or verdict["protocol_version"] != _PROTOCOL_VERSION
        or verdict["caller_id"] != caller_id
        or verdict["operation_id"] != operation_id
        or verdict["request_hash"] != request_hash
        or verdict["decision"] not in ("allow", "deny")
        or not isinstance(verdict["key_id"], str)
        or not isinstance(verdict["signature"], str)
    ):
        raise ValueError("Verdict does not match the signed request")
    key = public_keys.get(verdict["key_id"])
    if key is None:
        raise ValueError("Verdict uses an unknown signing key")
    signature = base64.b64decode(verdict["signature"], validate=True)
    unsigned_verdict = {key: value for key, value in verdict.items() if key != "signature"}
    key.verify(signature, _canonical_json(unsigned_verdict))


class SpendAuthorityTool:
    """Fail-closed signed authorization wrapper for an AutoGen tool.

    The authority accepts POST requests with a version-1 JSON body containing
    ``caller_id``, ``operation_id``, ``tool_name`` and the tool ``arguments``.
    It must return a 2xx response with a verdict containing
    ``protocol_version``, ``caller_id``, ``operation_id``, ``decision``
    (``allow`` or ``deny``), ``request_hash``, ``key_id`` and a base64
    Ed25519 ``signature``. ``request_hash`` is the lowercase SHA-256 hex digest
    of the canonical JSON request body and binds the verdict to the exact
    intent. The signature covers the canonical JSON encoding of every verdict
    field except ``signature``.
    Public keys are raw 32-byte Ed25519 keys indexed by key ID.

    Each operation is claimed in SQLite before the authority is contacted.
    Consequently, timeouts, denials, and process restarts cannot make the same
    ``(caller_id, operation_id)`` executable a second time. The SQLite file
    stores the request arguments in its hash-chained receipts; protect it as
    sensitive application data.
    """

    def __init__(
        self,
        tool: Tool,
        authority_url: str,
        caller_id: str,
        public_keys: Mapping[str, bytes],
        ledger_path: str | Path,
        timeout: float = 5.0,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        if not caller_id:
            raise ValueError("caller_id must not be empty")
        if not authority_url:
            raise ValueError("authority_url must not be empty")
        if timeout <= 0:
            raise ValueError("timeout must be greater than zero")
        if not public_keys:
            raise ValueError("At least one Ed25519 public key is required")
        self._public_keys = {key_id: Ed25519PublicKey.from_public_bytes(key) for key_id, key in public_keys.items()}
        self._tool = tool
        self._authority_url = authority_url
        self._caller_id = caller_id
        self._ledger_path = str(ledger_path)
        if self._ledger_path == ":memory:":
            raise ValueError("ledger_path must refer to a persistent SQLite database")
        self._timeout = timeout
        self._client = client or httpx.AsyncClient(follow_redirects=False)
        self._owns_client = client is None

        with _connect(self._ledger_path) as connection:
            connection.execute(
                "CREATE TABLE IF NOT EXISTS operations ("
                "caller_id TEXT NOT NULL, operation_id TEXT NOT NULL, status TEXT NOT NULL, "
                "PRIMARY KEY (caller_id, operation_id))"
            )
            connection.execute(
                "CREATE TABLE IF NOT EXISTS receipts ("
                "sequence INTEGER PRIMARY KEY, previous_hash TEXT NOT NULL, "
                "receipt_json TEXT NOT NULL, receipt_hash TEXT NOT NULL UNIQUE)"
            )

    @property
    def name(self) -> str:
        return self._tool.name

    @property
    def description(self) -> str:
        return self._tool.description

    @property
    def schema(self) -> ToolSchema:
        return self._tool.schema

    def args_type(self) -> Type[BaseModel]:
        return self._tool.args_type()

    def return_type(self) -> Type[Any]:
        return self._tool.return_type()

    def state_type(self) -> Type[BaseModel] | None:
        return self._tool.state_type()

    def return_value_as_string(self, value: Any) -> str:
        return self._tool.return_value_as_string(value)

    async def save_state_json(self) -> Mapping[str, Any]:
        return await self._tool.save_state_json()

    async def load_state_json(self, state: Mapping[str, Any]) -> None:
        await self._tool.load_state_json(state)

    async def aclose(self) -> None:
        if self._owns_client:
            await self._client.aclose()

    async def run_json(
        self, args: Mapping[str, Any], cancellation_token: CancellationToken, call_id: str | None = None
    ) -> Any:
        if not isinstance(call_id, str) or not call_id:
            raise SpendAuthorizationError("A non-empty AutoGen call_id is required for spend authorization")

        request_value = {
            "protocol_version": _PROTOCOL_VERSION,
            "caller_id": self._caller_id,
            "operation_id": call_id,
            "tool_name": self._tool.name,
            "arguments": dict(args),
        }
        try:
            request_bytes = _canonical_json(request_value)
        except (TypeError, ValueError) as exc:
            raise SpendAuthorizationError("Tool arguments are not valid JSON for spend authorization") from exc
        request: dict[str, Any] = json.loads(request_bytes)
        request_hash = hashlib.sha256(request_bytes).hexdigest()

        await asyncio.to_thread(self._claim_operation, call_id, request)
        verdict: dict[str, Any] | None = None
        try:
            verdict = await self._request_verdict(request_bytes, call_id, request_hash)
            decision = verdict["decision"]
            await asyncio.to_thread(
                self._finish_operation,
                call_id,
                "allowed" if decision == "allow" else "denied",
                {"request": request, "verdict": verdict},
            )
            if decision != "allow":
                raise SpendAuthorizationError("Spend authority denied this tool operation")
        except SpendAuthorizationError as exc:
            if verdict is None:
                await self._deny_operation(call_id, request, str(exc))
            raise
        except Exception as exc:
            await self._deny_operation(call_id, request, "Authority request failed")
            raise SpendAuthorizationError("Spend authorization failed; tool execution was denied") from exc

        return await self._tool.run_json(args, cancellation_token, call_id=call_id)

    def _claim_operation(self, operation_id: str, request: Mapping[str, Any]) -> None:
        with _connect(self._ledger_path) as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                connection.execute(
                    "INSERT INTO operations (caller_id, operation_id, status) VALUES (?, ?, 'pending')",
                    (self._caller_id, operation_id),
                )
            except sqlite3.IntegrityError as exc:
                _append_receipt(
                    connection,
                    "replay_denied",
                    self._caller_id,
                    operation_id,
                    {"tool_name": self._tool.name},
                )
                connection.commit()
                raise SpendAuthorizationError("Duplicate spend operation was denied") from exc
            _append_receipt(
                connection,
                "authorization_started",
                self._caller_id,
                operation_id,
                {"request": dict(request)},
            )
            connection.commit()

    def _finish_operation(self, operation_id: str, status: str, details: Mapping[str, Any]) -> None:
        with _connect(self._ledger_path) as connection:
            connection.execute("BEGIN IMMEDIATE")
            updated = connection.execute(
                "UPDATE operations SET status = ? WHERE caller_id = ? AND operation_id = ? AND status = 'pending'",
                (status, self._caller_id, operation_id),
            ).rowcount
            if updated != 1:
                raise SpendAuthorizationError("Could not persist spend authorization; tool execution was denied")
            _append_receipt(
                connection,
                f"authorization_{status}",
                self._caller_id,
                operation_id,
                details,
            )
            connection.commit()

    async def _deny_operation(self, operation_id: str, request: Mapping[str, Any], reason: str) -> None:
        try:
            await asyncio.to_thread(
                self._finish_operation,
                operation_id,
                "denied",
                {"request": dict(request), "reason": reason},
            )
        except Exception as exc:
            raise SpendAuthorizationError("Could not persist spend denial; tool execution was denied") from exc

    async def _request_verdict(self, request_bytes: bytes, operation_id: str, request_hash: str) -> dict[str, Any]:
        try:
            response = await self._client.post(
                self._authority_url,
                content=request_bytes,
                headers={"content-type": "application/json"},
                timeout=self._timeout,
                follow_redirects=False,
            )
        except httpx.HTTPError as exc:
            raise SpendAuthorizationError("Spend authority request failed; tool execution was denied") from exc

        if not 200 <= response.status_code < 300:
            raise SpendAuthorizationError("Spend authority returned a non-2xx status; tool execution was denied")
        try:
            verdict = json.loads(response.content, object_pairs_hook=_reject_duplicate_keys)
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
            raise SpendAuthorizationError("Spend authority returned malformed JSON; tool execution was denied") from exc

        if not isinstance(verdict, dict) or set(verdict) != _VERDICT_FIELDS:
            raise SpendAuthorizationError("Spend authority returned a malformed verdict; tool execution was denied")
        try:
            _verify_verdict_signature(verdict, self._public_keys, self._caller_id, operation_id, request_hash)
        except (ValueError, InvalidSignature) as exc:
            raise SpendAuthorizationError(
                "Spend authority verdict was invalid or did not match this request; tool execution was denied"
            ) from exc
        return verdict


def verify_receipt_chain(ledger_path: str | Path, public_keys: Mapping[str, bytes] | None = None) -> int:
    """Verify receipts offline, optionally checking verdict signatures using raw public keys."""
    verification_keys = (
        {key_id: Ed25519PublicKey.from_public_bytes(key) for key_id, key in public_keys.items()}
        if public_keys is not None
        else None
    )
    with _connect(str(ledger_path)) as connection:
        try:
            rows = connection.execute(
                "SELECT sequence, previous_hash, receipt_json, receipt_hash FROM receipts ORDER BY sequence"
            ).fetchall()
        except sqlite3.OperationalError as exc:
            raise ReceiptChainError("Receipt database is missing the receipts table") from exc

    previous_hash = _GENESIS_HASH
    for expected_sequence, row in enumerate(rows, start=1):
        sequence, stored_previous_hash, receipt_json, stored_hash = row
        if sequence != expected_sequence or stored_previous_hash != previous_hash:
            raise ReceiptChainError(f"Receipt chain link is invalid at sequence {expected_sequence}")
        try:
            receipt = json.loads(receipt_json, object_pairs_hook=_reject_duplicate_keys)
            canonical_receipt = _canonical_json(receipt).decode("utf-8")
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            raise ReceiptChainError(f"Receipt is malformed at sequence {expected_sequence}") from exc
        if not isinstance(receipt, dict) or set(receipt) != {
            "sequence",
            "previous_hash",
            "event",
            "caller_id",
            "operation_id",
            "details",
        }:
            raise ReceiptChainError(f"Receipt is malformed at sequence {expected_sequence}")
        if (
            receipt["sequence"] != sequence
            or receipt["previous_hash"] != stored_previous_hash
            or not isinstance(receipt["details"], dict)
        ):
            raise ReceiptChainError(f"Receipt is malformed at sequence {expected_sequence}")
        calculated_hash = hashlib.sha256(canonical_receipt.encode("utf-8")).hexdigest()
        if canonical_receipt != receipt_json or calculated_hash != stored_hash:
            raise ReceiptChainError(f"Receipt hash is invalid at sequence {expected_sequence}")
        if verification_keys is not None and receipt["event"] in ("authorization_allowed", "authorization_denied"):
            details = receipt.get("details", {})
            verdict = details.get("verdict")
            request = details.get("request")
            if verdict is not None:
                try:
                    request_hash = hashlib.sha256(_canonical_json(request)).hexdigest()
                    _verify_verdict_signature(
                        verdict,
                        verification_keys,
                        receipt["caller_id"],
                        receipt["operation_id"],
                        request_hash,
                    )
                    expected_decision = "allow" if receipt["event"] == "authorization_allowed" else "deny"
                    if verdict["decision"] != expected_decision:
                        raise ValueError("Verdict decision does not match receipt event")
                except (KeyError, TypeError, ValueError, InvalidSignature) as exc:
                    raise ReceiptChainError(f"Verdict signature is invalid at sequence {expected_sequence}") from exc
            elif receipt["event"] == "authorization_allowed":
                raise ReceiptChainError(f"Allow receipt has no signed verdict at sequence {expected_sequence}")
        previous_hash = stored_hash
    return len(rows)
