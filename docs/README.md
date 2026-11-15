<!-- Copyright (c) 2026 Erick Bourgeois, charter -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Charter documentation

Source of the Charter documentation site (MkDocs Material).

- `mkdocs.yml`: site configuration and navigation
- `src/`: pages
- `hooks/crd_reference.py`: renders the IAMClient field tables from `../deploy/crd.yaml`

Build with `make docs` from the repository root, or preview with
`make docs-serve`. See `src/developer/docs.md` for details.
