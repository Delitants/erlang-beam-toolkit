#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)

special=$(find "$ROOT" -path "$ROOT/.git" -prune -o \
  ! -type d ! -type f -print -quit)
if [[ -n $special ]]; then
  printf 'symlink or special public artifact: %s\n' "${special#"$ROOT/"}" >&2
  exit 1
fi

while IFS= read -r path; do
  rel=${path#"$ROOT/"}
  lower=$(printf '%s' "$rel" | tr '[:upper:]' '[:lower:]')
  case $lower in
    *ai_handoff*|*.beam|*.beam.*|*.beam_*|*.key|*.keys|*aes-key*|*key1|*key2|*.cookie|*cookie*|*.etf|*.etf.*|*erl_crash.dump*|*.dump|*candidate*|*decrypted*|*packed*)
      printf 'forbidden public artifact: %s\n' "$rel" >&2
      exit 1
      ;;
  esac
  case $rel in
    beam_patch_toolkit.sh|README.md|LICENSE|docs/flow-analysis.md|docs/runtime-tracing.md|docs/patching.md|docs/output-formats.md|examples/flow_scenario.term|tests/*.sh|tests/*.escript|tests/fixtures/*.erl|.github/workflows/test.yml) ;;
    *)
      printf 'non-public path: %s\n' "$rel" >&2
      exit 1
      ;;
  esac
done < <(find "$ROOT" -path "$ROOT/.git" -prune -o -type f -print)

deny='(AI_HANDOFF|([0-9]{1,3}\.){3}[0-9]{1,3}|/Users/[^/]+/|/root/|/home/[^/]+/|/opt/[^ ]+/ebin|flussonic|BEGIN[[:space:]]+[^[:space:]]*[[:space:]]*PRIVATE[[:space:]]+KEY|KEY[12][[:space:]]*=.*[[:xdigit:]]{64})'
if LC_ALL=C grep -RIEiln --exclude-dir=.git --exclude=publication_scan.sh -- "$deny" "$ROOT"; then
  printf 'private, secret, or target-specific content found\n' >&2
  exit 1
fi

if [[ -n ${1-} ]]; then
  [[ -f $1 && ! -L $1 ]] || {
    printf 'invalid private deny file\n' >&2
    exit 1
  }
  if LC_ALL=C grep -RIFln --exclude-dir=.git --exclude=publication_scan.sh -f "$1" "$ROOT"; then
    printf 'private deny-file content found\n' >&2
    exit 1
  fi
fi

printf 'public tree clean\n'
