# Developer guide

- [Code layout](code-layout.md): the modules and how a reconcile flows through them.
- [Building and testing](building.md): build, lint, unit tests, CRD generation, CI.
- [End-to-end testing](e2e.md): running against a real dev tenant, with
  External Secrets and OpenBao.
- [Writing these docs](docs.md): building and previewing this site.

## Ground rules

- **Nothing reaches Entra before policy and approval pass.** New mutations go
  after step 2 of [the reconcile loop](../concepts/reconcile-loop.md).
- **Every mutation is audited.** Wrap it in `Auditor::audited` so it gets an
  `attempted` record before and a result record after. Add the action to
  [audit records](../reference/audit.md).
- **Secrets stay in `SecretString`.** Never format one into a log, an error or
  an audit record.
- **New spec fields are admin-only by default.** Make them `Option` with
  `skip_serializing_if = "Option::is_none"` so existing clients' admin hash
  does not change, and add them to the admission policy's compared fields.
- **The CRD is generated.** Change `src/crd.rs`, then regenerate
  `deploy/crd.yaml`; CI fails if they differ.
