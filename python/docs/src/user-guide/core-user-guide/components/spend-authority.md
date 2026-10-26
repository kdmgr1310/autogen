# Spend authority tool wrapper

`SpendAuthorityTool` wraps an AutoGen `Tool` and consults an external policy service before allowing the wrapped tool to execute. Use it for tools that initiate metered HTTP calls, x402 payments, or other operations that should require a remote spending decision.

Install the optional dependencies:

```bash
pip install "autogen-ext[spend-authority]"
```

Wrap only the tool that should be gated and provide the authority's trusted Ed25519 public key and a persistent SQLite ledger:

```python
from autogen_ext.tools.spend_authority import SpendAuthorityTool

guarded_payment_tool = SpendAuthorityTool(
    tool=payment_tool,
    authority_url="https://authority.example/v1/authorize",
    caller_id="billing-agent",
    public_keys={"authority-key-2026": authority_public_key_bytes},
    ledger_path="./spend-ledger.sqlite3",
)
```

Pass `guarded_payment_tool` to the agent in place of `payment_tool`. AutoGen must provide a non-empty `call_id`; it becomes the operation ID. The authority request contains `protocol_version`, `caller_id`, `operation_id`, `tool_name`, and the original tool `arguments`.

## Authority response contract

The authority must return a 2xx response with this JSON shape:

```json
{
  "protocol_version": 1,
  "caller_id": "billing-agent",
  "operation_id": "the-autogen-call-id",
  "request_hash": "lowercase SHA-256 hex digest of the canonical request JSON",
  "decision": "allow",
  "key_id": "authority-key-2026",
  "signature": "base64 Ed25519 signature"
}
```

The signature covers the canonical JSON representation of every field except `signature`: UTF-8 JSON with keys sorted, compact separators, and non-ASCII characters preserved. `request_hash` is the SHA-256 digest of the same canonical JSON encoding of the full request body, binding the signed decision to the exact tool arguments. Public keys are raw 32-byte Ed25519 public keys indexed by `key_id`.

Only a matching, validly signed `allow` proceeds. Explicit denial, timeout, transport errors, non-2xx status, malformed response, unknown key, mismatched request, or invalid signature raises `SpendAuthorizationError`; the wrapped tool is not called. Redirects are not followed.

## Replay protection and receipts

The SQLite ledger atomically claims `(caller_id, operation_id)` before contacting the authority. Duplicate calls are rejected, including after process restarts. A timeout also consumes the operation ID because the authority may have processed the request; use a new ID for a new intent rather than retrying an uncertain operation under the same ID.

Authorization requests and verdicts are recorded as hash-chained receipts in the SQLite file. The ledger includes tool arguments, so protect it as sensitive application data. Verify the receipt chain offline and, optionally, verify signed verdicts with the trusted public keys:

```python
from autogen_ext.tools.spend_authority import verify_receipt_chain

receipt_count = verify_receipt_chain(
    "./spend-ledger.sqlite3",
    {"authority-key-2026": authority_public_key_bytes},
)
```

The hash chain detects edits, removals, or reordering relative to a trusted chain head. Since a local operator able to rewrite the entire database can recompute the chain, retain or externally anchor a trusted receipt hash when tamper evidence against that operator is required.
