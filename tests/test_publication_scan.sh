#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
SCANNER="$ROOT/tests/publication_scan.sh"
TMP_ROOT=$(mktemp -d "${TMPDIR:-/tmp}/beam-publication-scan-test.XXXXXX")
trap 'rm -rf -- "$TMP_ROOT"' EXIT
failures=0

pass() { printf 'ok - publication scan %s\n' "$1"; }
fail() { printf 'not ok - publication scan %s\n' "$1" >&2; failures=$((failures + 1)); }

new_stage() {
  local stage
  stage=$(mktemp -d "$TMP_ROOT/stage.XXXXXX")
  mkdir -p "$stage/tests"
  cp -- "$SCANNER" "$stage/tests/publication_scan.sh"
  printf '%s\n' '#!/usr/bin/env bash' >"$stage/beam_patch_toolkit.sh"
  printf '%s\n' '# Test public tree' >"$stage/README.md"
  printf '%s\n' 'MIT' >"$stage/LICENSE"
  printf '%s\n' "$stage"
}

expect_clean() {
  local stage=$1 description=$2
  if (cd "$stage" && bash tests/publication_scan.sh >/dev/null 2>&1); then
    pass "$description"
  else
    fail "$description"
  fi
}

expect_reject() {
  local stage=$1 description=$2
  if (cd "$stage" && bash tests/publication_scan.sh >/dev/null 2>&1); then
    fail "$description"
  else
    pass "$description"
  fi
}

stage=$(new_stage)
expect_clean "$stage" 'accepts an allowlisted text-only stage'

stage=$(new_stage); : >"$stage/tests/leaked.beam"
expect_reject "$stage" 'rejects BEAM artifacts'

stage=$(new_stage); : >"$stage/tests/secret.key"
expect_reject "$stage" 'rejects key artifacts'

stage=$(new_stage); : >"$stage/tests/node.cookie"
expect_reject "$stage" 'rejects cookie artifacts'

stage=$(new_stage); : >"$stage/tests/events.etf"
expect_reject "$stage" 'rejects ETF trace artifacts'

stage=$(new_stage); : >"$stage/tests/erl_crash.dump"
expect_reject "$stage" 'rejects crash dumps'

stage=$(new_stage); : >"$stage/tests/module.candidate"
expect_reject "$stage" 'rejects candidate artifacts'

stage=$(new_stage); : >"$stage/tests/module.decrypted"
expect_reject "$stage" 'rejects decrypted artifacts'

stage=$(new_stage); handoff_name="AI_""HANDOFF.md"; : >"$stage/tests/$handoff_name"
expect_reject "$stage" 'rejects private handoff filenames'

stage=$(new_stage); ln -s README.md "$stage/tests/public-link"
expect_reject "$stage" 'rejects symlinks'

stage=$(new_stage); target_ip=$(printf '%s.%s.%s.%s' 203 0 113 42); printf '%s\n' "$target_ip" >>"$stage/README.md"
expect_reject "$stage" 'rejects target IP addresses'

stage=$(new_stage); local_path=$(printf '/%s/%s/private' Users example); printf '%s\n' "$local_path" >>"$stage/README.md"
expect_reject "$stage" 'rejects local user paths'

stage=$(new_stage); product_name=$(printf '%s%s' Flus sonic); printf '%s\n' "$product_name" >>"$stage/README.md"
expect_reject "$stage" 'rejects product-specific association'

stage=$(new_stage); pem_marker=$(printf '%s %s %s' BEGIN OPENSSH 'PRIVATE KEY'); printf '%s\n' "$pem_marker" >>"$stage/README.md"
expect_reject "$stage" 'rejects private-key markers'

stage=$(new_stage)
key_half_a=0123456789abcdef0123456789abcdef
key_half_b=fedcba9876543210fedcba9876543210
printf 'KEY%s = "%s%s"\n' 1 "$key_half_a" "$key_half_b" >>"$stage/README.md"
expect_reject "$stage" 'rejects embedded named AES keys'

if (( failures > 0 )); then
  printf '%d publication scan test(s) failed\n' "$failures" >&2
  exit 1
fi
printf 'all publication scan tests passed\n'
