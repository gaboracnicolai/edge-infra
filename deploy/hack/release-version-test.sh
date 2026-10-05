#!/usr/bin/env bash
# release-version-test.sh — a v<SemVer> tag packages every chart at that version.
#
# Packages deploy/helm/* the way release.yaml does for the tag v9.8.7-rc.1 and
# checks the result, then shows the check refusing charts packaged without the
# tag's version and the version script refusing a tag that is not SemVer.
#
# Run: make release-version-test   (needs helm)
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
RV="$REPO/deploy/hack/release-version.sh"
SHA=0123456789abcdef0123456789abcdef01234567
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

fail() { echo "release-version-test: FAIL $*" >&2; exit 1; }

version="" release="" image_tag=""

# 1. A tag: the packaged chart version equals the tag.
out="$(bash "$RV" refs/tags/v9.8.7-rc.1 "$SHA")"
eval "$out" # version= release= image_tag=
[ "$version" = 9.8.7-rc.1 ] && [ "$release" = 9.8.7-rc.1 ] && [ "$image_tag" = 9.8.7-rc.1 ] ||
	fail "tag v9.8.7-rc.1 gave: $out"
for c in "$REPO"/deploy/helm/*/; do
	helm package "$c" -d "$tmp/tag" --version "$version" --app-version "$image_tag" >/dev/null
done
bash "$RV" --check "$version" "$image_tag" "$tmp/tag" || fail "charts packaged for v9.8.7-rc.1 did not pass --check"

# 2. The check can go red: charts packaged at their Chart.yaml version.
for c in "$REPO"/deploy/helm/*/; do helm package "$c" -d "$tmp/plain" >/dev/null; done
if bash "$RV" --check "$version" "$image_tag" "$tmp/plain" 2>/dev/null; then
	fail "--check passed charts packaged without the tag's version"
fi

# 3. A branch build is a dev version pinned to its sha; a non-SemVer tag is refused.
eval "$(bash "$RV" refs/heads/main "$SHA")"
[ "$version" = 0.0.0-g0123456789ab ] && [ -z "$release" ] && [ "$image_tag" = "$SHA" ] ||
	fail "refs/heads/main gave version=$version release=$release image_tag=$image_tag"
if bash "$RV" refs/tags/v1.2 "$SHA" 2>/dev/null; then fail "tag v1.2 was accepted"; fi

echo "release-version-test: ok — v9.8.7-rc.1 packages every chart as 9.8.7-rc.1"
