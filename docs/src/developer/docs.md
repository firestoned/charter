# Writing these docs

The site is MkDocs with the Material theme. Sources are in `docs/src`, the
configuration is `docs/mkdocs.yml`, and dependencies are managed by Poetry in
`docs/pyproject.toml`.

## Build and preview

```sh
make docs          # build into docs/site (strict: warnings fail the build)
make docs-serve    # live preview on http://127.0.0.1:8000
make docs-clean    # remove docs/site and docs/.venv
```

Without Poetry on the host, build in a container:

```sh
docker run --rm -v "$PWD":/src -w /src/docs python:3.13 sh -c \
  'pip install -q poetry && poetry install -q --no-root && poetry run mkdocs build'
```

## Generated content

- **IAMClient field tables.** `docs/hooks/crd_reference.py` replaces
  `<!-- crd-fields: spec -->` and `<!-- crd-fields: status -->` with tables
  built from `deploy/crd.yaml`. Field descriptions come from the doc comments
  in `src/crd.rs`, so fix wording there and regenerate the CRD.
- **Manifests.** Pages include files from the repository with the snippets
  syntax, for example `--8<-- "deploy/rbac.yaml"`, so examples cannot drift
  from what is deployed.

## Conventions

- Diagrams in Mermaid fences.
- No real infrastructure: no real tenant IDs, client IDs, hostnames or IP
  addresses; use `example.com` and obviously fake GUIDs.
- No em-dashes; use a colon, comma, parentheses or a new sentence.
- New pages go in `nav` in `mkdocs.yml` (MkDocs only logs pages left out of
  it). The strict build fails on broken links and missing snippet files.
