#!/usr/bin/env bash
# release-version.sh — the SemVer a release is stamped with, from its git tag.
#
#   bash deploy/hack/release-version.sh <git-ref> <sha>
#       prints three key=value lines (for $GITHUB_OUTPUT):
#         version=    the chart version: X.Y.Z[-pre] on a vX.Y.Z[-pre] tag, else 0.0.0-g<sha12>
#         release=    X.Y.Z[-pre] on a release tag, empty otherwise
#         image_tag=  the tag the charts pin: the release on a tag, else <sha>
#       A ref under refs/tags/ that is not v<SemVer> fails, so a typo in a tag
#       cannot ship as a dev build.
#   bash deploy/hack/release-version.sh --check <version> <image-tag> <dir>
#       exit 1 unless <dir> holds one <name>-<version>.tgz per deploy/helm chart,
#       each with version: <version> and appVersion: <image-tag> inside.
#   bash deploy/hack/release-version.sh --stamps <version> <sha>
#       exit 1 unless every image `release-pin.sh --list` prints carries the
#       labels org.opencontainers.image.version=<version> and .revision=<sha>.
#
# A release is `git tag v1.2.3 && git push origin v1.2.3`: release.yaml builds
# and pushes every image at :<sha> and :1.2.3, pins the charts to :1.2.3,
# packages them as 1.2.3 and attaches them to the GitHub release v1.2.3.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

die() { echo "release-version: $*" >&2; exit 1; }

# SemVer 2.0.0 without build metadata (an image tag cannot hold '+').
NUM='(0|[1-9][0-9]*)'
PRE_ID='(0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)'
SEMVER_RE="^${NUM}\.${NUM}\.${NUM}(-${PRE_ID}(\.${PRE_ID})*)?$"

version() { # ref sha
	local ref="$1" sha="$2" v
	[[ "$sha" =~ ^[0-9a-f]{40}$ ]] || die "'$sha' is not a full commit sha"
	case "$ref" in
	refs/tags/*)
		v="${ref#refs/tags/}"
		[[ "$v" == v* && "${v#v}" =~ $SEMVER_RE ]] || die "tag '$v' is not v<SemVer> (e.g. v1.2.3 or v1.2.3-rc.1)"
		v="${v#v}"
		printf 'version=%s\nrelease=%s\nimage_tag=%s\n' "$v" "$v" "$v"
		;;
	*) printf 'version=0.0.0-g%s\nrelease=\nimage_tag=%s\n' "${sha:0:12}" "$sha" ;;
	esac
}

# field <Chart.yaml text> <key> — a top-level scalar, unquoted.
field() { sed -n "s/^$2:[[:space:]]*//p" <<<"$1" | sed 's/[[:space:]]*#.*$//; s/^"//; s/"$//; s/^'\''//; s/'\''$//' | head -1; }

check() { # version image-tag dir
	local want="$1" app="$2" dir="$3" c name chart got gotapp fail=0 n=0
	[ -d "$dir" ] || die "no directory $dir"
	for c in "$REPO"/deploy/helm/*/Chart.yaml; do
		name="$(field "$(cat "$c")" name)"
		n=$((n + 1))
		if [ ! -f "$dir/$name-$want.tgz" ]; then
			echo "FAIL  $name: no $dir/$name-$want.tgz" >&2
			fail=1
			continue
		fi
		chart="$(helm show chart "$dir/$name-$want.tgz")"
		got="$(field "$chart" version)"
		gotapp="$(field "$chart" appVersion)"
		if [ "$got" != "$want" ] || [ "$gotapp" != "$app" ]; then
			echo "FAIL  $name: packaged version $got appVersion $gotapp, want $want / $app" >&2
			fail=1
			continue
		fi
		echo "ok    $name-$want.tgz  version $got  appVersion $gotapp"
	done
	[ "$n" -gt 0 ] || die "found no chart under deploy/helm"
	[ "$fail" = 0 ] || die "the packaged charts do not carry version $want"
}

stamps() { # version sha
	local want="$1" sha="$2" ref got fail=0
	while IFS= read -r ref; do
		docker pull -q "$ref" >/dev/null
		got="$(docker image inspect "$ref" --format '{{index .Config.Labels "org.opencontainers.image.version"}} {{index .Config.Labels "org.opencontainers.image.revision"}}')"
		if [ "$got" != "$want $sha" ]; then
			echo "FAIL  $ref is stamped '$got', want '$want $sha'" >&2
			fail=1
		else
			echo "ok    $ref  $got"
		fi
	done < <(bash "$REPO/deploy/hack/release-pin.sh" --list)
	[ "$fail" = 0 ] || die "an image does not carry this release's stamp"
}

case "${1:-}" in
--check) [ $# = 4 ] || die "usage: --check <version> <image-tag> <dir>"; check "$2" "$3" "$4" ;;
--stamps) [ $# = 3 ] || die "usage: --stamps <version> <sha>"; stamps "$2" "$3" ;;
"" | -*) die "usage: release-version.sh <git-ref> <sha> | --check <version> <image-tag> <dir> | --stamps <version> <sha>" ;;
*) [ $# = 2 ] || die "usage: release-version.sh <git-ref> <sha>"; version "$1" "$2" ;;
esac
