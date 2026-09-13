# CI and releases

How this package is tested and published. What each consuming app replaced when it adopted
the package is in [migration-notes.md](migration-notes.md). Back to the [README](../README.md).

## CI and releases

`.github/workflows/ci.yml` calls `WebbPulse/.github/.github/workflows/python-ci.yml@v1` on
every push and pull request, overriding the inputs that assume a backend service: this
package sits at the repository root and installs from `pyproject.toml`. A second job in the
same file runs mypy, because the reusable workflow has no type checking step and this
package ships `py.typed`, so its annotations are part of its contract.

`.github/workflows/publish.yml` calls
`WebbPulse/.github/.github/workflows/codeartifact-publish-python.yml@v1` on `v*` tags,
publishing to CodeArtifact domain `webbpulse`, repository `python`, in `us-west-2`. That
workflow is idempotent: it looks the version up first and skips with a notice rather than
failing, so re-running an already released tag stays green.

## Contract tests against a deployed issuer

`tests/test_identity_contract.py` checks that a real deployment's discovery document and
JWKS have the shape API Gateway's JWT authorizer requires, which is the one thing a unit
test cannot tell you: the gateway fetches both documents itself, holding no credentials,
and caches what it gets. It is **skipped unless `WEBBPULSE_IDENTITY_CONTRACT_BASE_URL` is
set**, so the ordinary test run and CI make no network request at all.

```bash
WEBBPULSE_IDENTITY_CONTRACT_BASE_URL=https://api.staging.webbpulse.com/api/auth \
  .venv/bin/pytest tests/test_identity_contract.py -v
```

The base URL is the issuer, path included, with no trailing slash. The suite fetches
`<issuer>/.well-known/openid-configuration`, then the `jwks_uri` that document advertises
rather than a URL it guessed, and asserts that both answer anonymously, that `issuer` comes
back byte identical to what was asked for, that `jwks_uri` sits under the issuer on the
issuer's own scheme, that `RS256` is advertised with no HS algorithm alongside it, that
every key carries `kty`, `use`, `alg`, `kid`, `n` and `e` with an unpadded base64url
modulus of at least 256 bytes, that the `kid` values are distinct, and that neither
document is served with a longer cache lifetime than the other can support.

It uses `urllib.request` rather than `httpx` or `requests`, neither of which is a
dependency here: a contract suite that skipped itself with "could not import httpx" would
be indistinguishable from the intended skip. It follows no redirects, since a redirect on
either document is itself a finding, and it mints no token, so it needs no credential and
can be run by anybody against any environment.

## Required repository configuration

| Secret | Used by | Value |
| --- | --- | --- |
| `CODEARTIFACT_PUBLISH_ROLE_ARN` | `publish.yml` | ARN of the OIDC role in the artifacts account allowed to publish to CodeArtifact |
| `CODEARTIFACT_DOMAIN_OWNER` | `publish.yml` | `432410731887`, the account that owns the `webbpulse` domain |

Both are passed straight through to the reusable workflow, which needs
`codeartifact:GetAuthorizationToken` and `sts:GetServiceBearerToken` on the assumed role.
The `publish` GitHub Environment named in `publish.yml` is where the release approval and
the environment-scoped secrets live; create it in repository settings. `ci.yml` needs no
secrets, because this package's own dependencies all come from PyPI.

## Cutting a release

The tag decides only *when* the workflow runs. The version that is published comes from
`src/webbpulse/_version.py` through hatchling, so set `__version__` and tag the same commit:

```bash
# edit src/webbpulse/_version.py to 0.2.0, commit it, then
git tag v0.2.0 && git push origin v0.2.0
```

Deriving the version from the tag instead would leave an sdist built outside a checkout
unversioned, and CodeArtifact rejects that.
