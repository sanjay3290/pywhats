# Releasing pywhats

This document describes how to cut a release of `pywhats` to TestPyPI and
PyPI. Releases are driven entirely by pushing a git tag; publication runs
in GitHub Actions via PyPI trusted publishing (OIDC). No long-lived API
tokens are stored in repository secrets.

## One-time setup: trusted publishing

Trusted publishing has to be configured manually on both TestPyPI and
PyPI before the workflow can publish anything. Do this once, per project.

### TestPyPI

1. Sign in at <https://test.pypi.org/> and create the `pywhats` project
   if it does not already exist. (Easiest way: do a one-off manual upload
   with `twine` so the project namespace is registered, then delete the
   file. Alternatively, use the "pending publisher" flow below which does
   not require the project to exist yet.)
2. Go to *Your projects → pywhats → Publishing* (or, for a first-time
   project, *Account settings → Publishing → Add a pending publisher*).
3. Add a new trusted publisher with these exact values:
   - **Owner**: `sanjay3290`
   - **Repository name**: `pywhats`
   - **Workflow name**: `release.yml`
   - **Environment name**: `testpypi`
4. Save.

### PyPI

Repeat the same steps on <https://pypi.org/>:

1. *Your projects → pywhats → Publishing* (or *Account settings →
   Publishing → Add a pending publisher*).
2. Add a trusted publisher with:
   - **Owner**: `sanjay3290`
   - **Repository name**: `pywhats`
   - **Workflow name**: `release.yml`
   - **Environment name**: `pypi`
3. Save.

### GitHub environments

The workflow references two GitHub Actions *environments* called
`testpypi` and `pypi`. They do not need any secrets (OIDC handles auth),
but creating them in *Settings → Environments* lets you add required
reviewers for production releases if you want a human gate.

## Release checklist

1. Make sure `main` is green in CI.
2. Update the version in two places:
   - `pyproject.toml` → `project.version`
   - `src/pywhats/__init__.py` → `__version__`
3. Update `CHANGELOG.md`: rename the unreleased section to the new
   version with today's date, and add a fresh empty unreleased section if
   you keep one.
4. Commit the bump: `git commit -am "Release 0.1.0"`.
5. Tag a release candidate first:
   ```bash
   git tag v0.1.0rc1
   git push origin main v0.1.0rc1
   ```
   This triggers the `release.yml` workflow, which publishes **only** to
   TestPyPI.
6. Smoke-test the pre-release in a clean virtualenv:
   ```bash
   python -m venv /tmp/pywhats-smoke
   source /tmp/pywhats-smoke/bin/activate
   pip install -i https://test.pypi.org/simple/ \
       --extra-index-url https://pypi.org/simple/ \
       pywhats==0.1.0rc1
   python -c "import pywhats; print(pywhats.__version__)"
   ```
   Optionally run `examples/pair_and_echo.py` against a real phone for a
   manual end-to-end verification.
7. If everything looks good, tag the final release:
   ```bash
   git tag v0.1.0
   git push origin v0.1.0
   ```
   This runs the workflow again. The `publish-testpypi` job always runs;
   the `publish-pypi` job only runs for tags matching
   `v<MAJOR>.<MINOR>.<PATCH>` with no suffix.
8. Verify on PyPI:
   ```bash
   pip install pywhats==0.1.0
   ```
9. Cut a GitHub release from the tag and paste in the changelog section.

## Tag conventions

- `v0.1.0` — final release, goes to TestPyPI and PyPI.
- `v0.1.0rc1`, `v0.1.0rc2`, ... — release candidates, TestPyPI only.
- `v0.1.0a1`, `v0.1.0b1`, `v0.2.0.dev1` — pre-releases, TestPyPI only.

The workflow decides which pipeline to run by regex-matching the tag
against `^v[0-9]+\.[0-9]+\.[0-9]+$`. Anything that does not match stays
on TestPyPI.

## If a release goes wrong

- You cannot overwrite or re-upload a file on PyPI. If a broken artifact
  has been published, yank it from the web UI and cut a new patch
  version.
- For a silent rollback of a bad release candidate, just delete the git
  tag and cut a new one. TestPyPI lets you delete files from the UI if
  you need to reclaim a filename.
