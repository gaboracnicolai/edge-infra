#!/usr/bin/env bash
# verify-image-pins.sh — no chart runs an image on the floating "latest" tag.
#
# Renders every chart in deploy/helm for base defaults and every env overlay
# that exists for it, and fails (exit 1) if any rendered image is :latest,
# untagged (which pulls latest) or has an empty tag. A digest (@sha256:) or a
# fixed tag passes. Images behind a switch are switched on for the render (the
# auth-service attest init container, the issuer's required activeKid), so an
# optional image is checked too, not only the default set.
#
# Extra args are passed to every `helm template` — `--set image.tag=latest`
# must make this fail, which is how CI proves the check can go red.
#
# Run: make verify-image-pins    (or: bash deploy/hack/verify-image-pins.sh)
set -uo pipefail

REPO="$(git rev-parse --show-toplevel)"
EXTRA=("$@")

# Values that make a chart render every image it can run.
switches() { # chart
	case "$1" in
	auth-service)
		echo --set confidential.enabled=true \
			--set 'confidential.attestation.measurements[0]=00' \
			--set confidential.attestation.trustedKey=verify-image-pins
		;;
	edge-issuer) echo --set config.activeKid=verify-image-pins ;;
	esac
}

fail=0
checked=0
check() { # chart label overlay-relpath(optional)
	local chart="$1" label="$2" overlay="${3:-}"
	local args=("$chart" "$REPO/deploy/helm/$chart")
	[ -n "$overlay" ] && args+=(--values "$REPO/$overlay")
	# shellcheck disable=SC2207
	args+=($(switches "$chart"))
	local out
	if ! out="$(helm template "${args[@]}" ${EXTRA[@]+"${EXTRA[@]}"} 2>&1)"; then
		echo "FAIL  $chart $label  (helm render error)"
		echo "$out" | tail -3
		fail=1
		return
	fi
	local images bad=()
	images="$(sed -n 's/^[[:space:]-]*image:[[:space:]]*//p' <<<"$out" | sed 's/[[:space:]]*#.*$//; s/^"//; s/"$//' | sort -u)"
	if [ -z "$images" ]; then
		echo "FAIL  $chart $label  (rendered no image)"
		fail=1
		return
	fi
	while IFS= read -r img; do
		checked=$((checked + 1))
		case "$img" in *@sha256:*) continue ;; esac
		local name="${img##*/}"
		case "$name" in
		*:latest | *:) bad+=("$img") ;;
		*:*) ;;
		*) bad+=("$img (untagged)") ;;
		esac
	done <<<"$images"
	if [ ${#bad[@]} -eq 0 ]; then
		echo "PASS  $chart $label  ($(wc -l <<<"$images" | tr -d ' ') image(s))"
	else
		echo "FAIL  $chart $label  floating: ${bad[*]}"
		fail=1
	fi
}

for dir in "$REPO"/deploy/helm/*/; do
	chart="$(basename "$dir")"
	check "$chart" "base"
	for overlay in "$REPO"/deploy/envs/*/values-"${chart#edge-}".yaml "$REPO"/deploy/envs/*/*/values-"${chart#edge-}".yaml; do
		[ -f "$overlay" ] || continue
		rel="${overlay#"$REPO"/}"
		env="${rel#deploy/envs/}"
		check "$chart" "${env%/*}" "$rel"
	done
done

echo
if [ "$fail" -eq 0 ]; then
	echo "OK: $checked rendered image reference(s), none on a floating tag."
else
	echo "FLOATING IMAGE: pin the image(s) above to a SHA tag or digest."
	exit 1
fi
