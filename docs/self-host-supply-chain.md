# Verifying the images before you install them

Every image the charts install is signed when it is built, and carries two signed
attestations: what is inside it (an SBOM) and how it was built (SLSA provenance).
The eight images are `edge-control-plane`, `edge-issuer`, `edge-ratelimit`,
`edge-secrets`, `edge-migrate`, `edge-attest`, `edge-osb` and `auth-service`, all
under `ghcr.io/gaboracnicolai`.

| | What it is | Check it with |
|---|---|---|
| Signature | a keyless cosign signature on the image digest | `cosign verify` |
| SBOM | an SPDX JSON list of every package in the image, made by syft 1.54.0 | `cosign verify-attestation --type spdxjson` |
| Provenance | SLSA v1 in GitHub's [workflow build type](https://actions.github.io/buildtypes/workflow/v1): the repository, ref, commit, trigger and run that built the image | `cosign verify-attestation --type slsaprovenance1` |

All three are made by the `sign` job in
[`.github/workflows/images.yaml`](../.github/workflows/images.yaml) and signed as
that workflow. No key is involved. cosign trades the job's GitHub OIDC token for a
short-lived Fulcio certificate that names the workflow, signs with it, and
records the signature in the public Rekor log. When you verify, you check that
name:

```
issuer    https://token.actions.githubusercontent.com
identity  https://github.com/gaboracnicolai/edge-infra/.github/workflows/images.yaml@<ref>
```

`<ref>` is `refs/heads/main` for a build from main, or `refs/tags/v1.2.3` for the
release `v1.2.3`. A signature made by another repository, another workflow, or a
pull-request build (`refs/pull/<n>/merge`) does not pass.

## One command

From a checkout of this repository, with `cosign` and `jq` on your PATH:

```sh
make verify-images TAG=1.2.3       # a release
make verify-images TAG=<sha>       # a build from main, at its commit sha
```

This verifies every first-party image named in `deploy/helm/*/values.yaml`, at
that tag. It exits 1 if any image is missing its signature, its SBOM or its
provenance:

```
ok    ghcr.io/gaboracnicolai/edge-osb@sha256:…
      signed by   https://github.com/gaboracnicolai/edge-infra/.github/workflows/images.yaml@refs/tags/v1.2.3
      sbom        <n> packages (SPDX, syft)
      provenance  built from git+https://github.com/gaboracnicolai/edge-infra@refs/tags/v1.2.3 at <sha> by https://github.com/gaboracnicolai/edge-infra/actions/runs/…
…
all 8 image(s) signed, with an SBOM and SLSA provenance, by https://github.com/gaboracnicolai/edge-infra/.github/workflows/images.yaml@refs/{heads/main,tags/v<SemVer>}
```

You can pin it tighter. `SIGNER_REF=refs/tags/v1.2.3` accepts only that
release's signer. `SIGNER_SHA=<sha>` also requires the commit, both in the
certificate and in the provenance. You can name images directly:
`bash deploy/hack/supply-chain.sh verify ghcr.io/gaboracnicolai/edge-osb@sha256:…`.
If you have no cosign, `bash deploy/hack/supply-chain.sh install <dir>` fetches
the pinned one and checks its sha256.

## By hand, with cosign alone

You do not need this repository:

```sh
IMG=ghcr.io/gaboracnicolai/edge-control-plane:1.2.3
WHO=(--certificate-oidc-issuer https://token.actions.githubusercontent.com
     --certificate-identity https://github.com/gaboracnicolai/edge-infra/.github/workflows/images.yaml@refs/tags/v1.2.3)

cosign verify "${WHO[@]}" "$IMG"

cosign verify-attestation "${WHO[@]}" --type spdxjson "$IMG" \
  | jq -r .payload | base64 -d | jq '.predicate.packages[] | {name, versionInfo}'

cosign verify-attestation "${WHO[@]}" --type slsaprovenance1 "$IMG" \
  | jq -r .payload | base64 -d | jq '.predicate.buildDefinition'
```

To accept any build from main or any release instead of one tag, swap
`--certificate-identity` for
`--certificate-identity-regexp '^https://github\.com/gaboracnicolai/edge-infra/\.github/workflows/images\.yaml@refs/(heads/main|tags/v.*)$'`.

## How CI proves it

The `verify` job in `images.yaml` runs on every image build: on every pull
request and push that changes an image, on every release, and nightly. It runs
`supply-chain.sh verify` on the eight digests that run pushed. It pins the
run's own ref and commit, so each image has to carry a signature, an SBOM and
provenance from that run. It has no write access and no OIDC token. It then
verifies the per-arch `auth-service:<sha>-amd64` image, which is an intermediate
that nothing signs, and requires the check to fail.

## What this does not cover yet

- **Nothing in the cluster refuses an unsigned image.** The charts do not yet
  include an admission policy that runs this check on every pod. Verify before
  you install.
- **The provenance is SLSA Build Level 2, not 3.** GitHub's hosted runner
  generates and signs it, as the build's own workflow. Build L3 needs the
  provenance to come from a generator the build steps cannot touch, and here it
  is a script in the same workflow, so an edit to that workflow could change
  what it says. The Fulcio certificate records the ref, commit and trigger on
  its own, apart from the predicate. `SIGNER_SHA` (or cosign's
  `--certificate-github-workflow-sha`) checks the commit there.
- **The SBOM is the `linux/amd64` variant's.** The `arm64` variant is built
  from the same sources and lockfiles.
- **Two packages are private** (`edge-issuer`, `edge-ratelimit`). To verify
  them, `docker login ghcr.io` with read access first. Their digests and
  signer identity still go to the public Rekor log, like every other image's.
