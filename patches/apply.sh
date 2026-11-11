#!/bin/sh
# Applies the user-agent patch (useragent.patch, with @CHROME_MAJOR@ filled
# in) to a writable copy of the pinned mautrix-meta tree. The image build
# runs this with the Chrome major version of the browser the owner signs in
# with, so the bridge does not present a stale browser fingerprint. Usage:
#   patches/apply.sh <mautrix-meta dir> <chrome major>
set -eu
dir=${1:-}
major=${2:-}
here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
[ -n "$dir" ] && [ -n "$major" ] || { echo "usage: $0 <mautrix-meta dir> <chrome major>" >&2; exit 2; }
case $major in
  *[!0-9]* | "") echo "chrome major must be digits, got: $major" >&2; exit 2 ;;
esac
target=$dir/pkg/messagix/useragent/useragent.go
[ -f "$target" ] || { echo "no useragent.go under $dir" >&2; exit 1; }
# A copy of the module cache is read-only.
chmod u+w "$target"
work=$(mktemp)
trap 'rm -f "$work"' EXIT
sed "s/@CHROME_MAJOR@/$major/g" "$here/useragent.patch" >"$work"
# --batch --forward: never prompt, and refuse (rather than reverse) a tree
# the patch was already applied to. The context lines pin the upstream
# spelling, so a pin that changes them fails here, loudly.
if command -v patch >/dev/null 2>&1; then
  patch -p1 --batch --forward -d "$dir" -i "$work" >&2
else
  # The golang build image ships git but not patch; git apply enforces the
  # same context and likewise refuses a second application.
  (cd "$dir" && git apply -p1 --whitespace=nowarn "$work") >&2
fi
grep -q "^const ChromeVersion = \"$major\"\$" "$target" || {
  echo "patched $target does not claim Chrome $major" >&2
  exit 1
}
grep -q '^const ChromeVersionFull = ChromeVersion + ".0.0.0"$' "$target" || {
  echo "patched $target has no zeroed ChromeVersionFull" >&2
  exit 1
}
echo "user agent patched to Chrome $major"
