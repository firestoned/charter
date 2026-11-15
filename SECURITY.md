<!--
Copyright (c) 2026 Erick Bourgeois, charter
SPDX-License-Identifier: Apache-2.0
-->
# Security Policy

## Supported Versions

Charter is pre-1.0 and under active development. Only the latest commit on
`main` and the most recent release receive security fixes.

| Version | Supported |
| ------- | --------- |
| latest release / `main` | ✅ |
| anything older | ❌ |

## Reporting a Vulnerability

Use GitHub [private vulnerability reporting](https://github.com/firestoned/charter/security/advisories/new).
Do not open a public issue for a security finding, and do not record specific
unremediated findings in the public
[threat model](docs/src/security/threat-model.md).

You can expect an acknowledgement within a week. Please include the commit or
release you tested, the component (controller, admission policy, Flux
template, docs hook) and a reproduction.

## What is in scope

- Anything that changes an Entra app registration without a passing policy
  check and approval gate, or without an audit record.
- Anything that lets an owning team change an admin-only field, forge the
  approval annotations or `last-modified-by`, or set a redirect URI outside the
  allowed domains.
- Anything that delivers a client secret anywhere other than the client's own
  namespace or its controller-derived OpenBao path, or that leaks a secret into
  logs, events, status or audit records.
- Anything that leaves a revoked or superseded secret usable longer than the
  configured grace window, or revokes the secret consumers currently hold.
- Weaknesses in the controller's own authentication (workload identity,
  token handling) or in the supply chain (image, signatures, SBOMs).

## Out of scope

- Compromise of the Kubernetes control plane, cluster admins, or Entra itself.
- How consuming applications store a secret after reading it.
- Findings that require `ALLOW_CLIENT_SECRET_AUTH=true` or
  `REQUIRE_APPROVAL=false`, which are development-only settings.
