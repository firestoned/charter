<!-- Copyright (c) 2026 Erick Bourgeois, charter -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Audit records

Every policy decision, approval decision and change Charter makes is written
as one JSON line on the `audit` log target, and mirrored as a Kubernetes Event
on the `IAMClient`. Ship the log to your SIEM with immutable retention; the
Events are a convenience for operators and expire.

## Shape

The log line wraps the record as a string in `fields.audit`:

```json
{"timestamp":"2026-11-14T15:30:33.1Z","level":"INFO","fields":{"audit":"{...record...}"},"target":"audit"}
```

The record:

```json
{
  "schema": "charter.audit/v1",
  "seq": 64,
  "prev_hash": "03b2758e96ea...",
  "time": "2026-11-14T15:30:33.186+00:00",
  "actor": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
  "action": "add_password",
  "outcome": "succeeded",
  "subject": {
    "namespace": "team-payments",
    "name": "payments-portal",
    "uid": "0f6c1a52-4c1e-4b0e-9d6e-3a9f1d2b7c44",
    "generation": 3,
    "spec_hash": "2145c2d8...",
    "admin_hash": "652146da...",
    "last_modified_by": "system:serviceaccount:charter-system:charter-provisioner",
    "unique_name": "charter-team-payments-payments-portal",
    "requested_by": "alice@example.com",
    "approved_by": "bob@example.com",
    "change_ref": "CHG0012345",
    "correlation_id": "b1f8..."
  },
  "details": { "lifetime": "90d", "reason": "rotation" }
}
```

| Field | Meaning |
|---|---|
| `schema` | `charter.audit/v1` |
| `seq` | Sequence number, per controller process |
| `prev_hash` | SHA-256 of the previous record's JSON (64 zeros for the first record of a process) |
| `time` | RFC 3339 |
| `actor` | The controller's Entra client ID |
| `action` | See below |
| `outcome` | `attempted`, `succeeded`, `failed`, `denied` or `info` |
| `subject` | The `IAMClient` and its approval evidence at the time |
| `subject.correlation_id` | Same for every record of one reconcile pass |
| `details` | Non-secret parameters: key IDs, fields, owner IDs, reasons |
| `error` | Present on `failed`: the error text |

Secret values never appear in records or logs: secrets and tokens are held
in a type that redacts itself when printed and zeroes its memory when dropped.

## Bracketed mutations

Every change to Entra or to delivered credentials is recorded twice: once as
`attempted` **before** the call, then as `succeeded` or `failed` after it. A
crash mid-call still leaves evidence of intent.

## Actions

| Action | Outcomes | `details` |
|---|---|---|
| `policy_check` | `denied` | `violations` |
| `approval_check` | `denied`, `info` | `change` (`Create`, `AdminChange`, `OwnerChange`), `authority` (`admin_approval`, `owner`) or `reason` |
| `create_application` | bracketed | `displayName`, `redirectUris` |
| `drift_detected` | `info` | `fields`, or `unexpectedOwner` |
| `update_application` | bracketed | `fields` |
| `create_service_principal` | bracketed | `appId` |
| `add_owner` | bracketed | `ownerId` |
| `remove_owner` | bracketed | `ownerId` |
| `add_password` | bracketed | `lifetime`, `reason` (`initial_or_missing`, `rotation`, `lifetime_shortened`) |
| `deliver_secret` | bracketed | `secret`, `keyId` |
| `apply_push_secret` | bracketed | `pushSecret`, `store`, `remoteKey`, `keys` |
| `delete_push_secret` | bracketed | `pushSecret`, `reason` (`push_secret_removed_from_spec`, `iamclient_deleted`) |
| `remove_password` | bracketed | `keyId`, `reason` (`rotated_out`, `unknown_credential`, `deletion_policy_retain`) |
| `delete_application` | bracketed | `appId`, `softDeleteDays` |
| `retain_application` | `info` | `appId` |
| `cleanup` | `info` | `reason` ("application already absent") |

## Kubernetes Events

Each record is also published as an Event on the `IAMClient`, with reason
`<action>:<Outcome>` (for example `add_password:Succeeded`), type `Warning`
for `failed` and `denied` and `Normal` otherwise, and the details or error as
the note (truncated to 900 characters). Publishing is best effort: the log is
the record.

## Querying

Find everything that happened to one client, or under one change:

```text
subject.uid = "<uid>"
subject.change_ref = "CHG0012345"
```

Alert on `outcome` in (`failed`, `denied`) and on any `drift_detected`.

## Integrity

`seq` and `prev_hash` make gaps and edits detectable within one process run.
The SIEM's immutable storage is the system of record; the chain is a
tamper-evidence aid, not a replacement for it.
