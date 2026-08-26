# Structural BEAM patching

The toolkit patches symbolic BEAM assembly as parsed Erlang terms. It never
balances braces, searches for a textual suffix, splices by pretty-printer line
number, or edits raw BEAM chunk offsets. Those text-oriented techniques can
produce a file that looks plausible while changing the enclosing term or label
ownership.

Use the same OTP major that produced or successfully disassembles the module.
Pass its `bin` directory with `--runtime-bin` when it is not first on `PATH`.
All commands refuse symlink inputs and existing outputs.

## Establish an unchanged baseline

```bash
TOOL=/path/to/beam_patch_toolkit.sh
RUNTIME=/path/to/otp/bin
INPUT=/path/to/module.beam
WORK=/safe/new/module-workspace

"$TOOL" doctor --input "$INPUT" --runtime-bin "$RUNTIME"
"$TOOL" extract --input "$INPUT" --workspace "$WORK" \
  --runtime-bin "$RUNTIME"
"$TOOL" roundtrip --input "$INPUT" --workspace "$WORK" \
  --runtime-bin "$RUNTIME"
"$TOOL" verify --original "$INPUT" \
  --candidate "$WORK/roundtrip.beam" --runtime-bin "$RUNTIME"
```

Do not edit until `roundtrip` has created `.roundtrip-verified.term`. Every
later patch command rechecks that proof against the immutable workspace input,
editable assembly, extra chunks, rebuilt round trip, runtime identity, and
module identity.

## Export and replace one complete function

Find the required entry label in `functions.term`, then export exactly that
function:

```bash
"$TOOL" export-function --workspace "$WORK" \
  --assembly "$WORK/editable.S" --entry-label 42 \
  --output /safe/new/function.term --runtime-bin "$RUNTIME"
```

The exported file is one `beam_patch_function` wrapper. Its metadata binds the
function to:

- module, name, arity, and entry label;
- the SHA-256 of the exact source assembly;
- every label owned by the function; and
- one complete parsed `{function,...}` term.

Retain the wrapper and change only the intended values inside its `function`
field. The file must remain exactly one consultable Erlang term ending in a
period. Then replace it:

```bash
"$TOOL" replace-function --workspace "$WORK" \
  --assembly "$WORK/editable.S" --function /safe/new/function.edited.term \
  --output /safe/new/edited.S --runtime-bin "$RUNTIME"
```

Replacement fails before writing if the wrapper is truncated, has more than
one top-level term, belongs to another module or assembly revision, changes
MFA/entry identity, adds or removes a label, does not select exactly one
function, or cannot be assembled with the preserved chunks.

## Rewrite one exact parsed subterm

For a small literal or instruction operand, put the old and new values in two
separate one-term files. This avoids manually rewriting the function wrapper:

```bash
printf '%s\n' 'old_value.' > /safe/new/from.term
printf '%s\n' 'new_value.' > /safe/new/to.term

"$TOOL" rewrite-function-term --workspace "$WORK" \
  --assembly "$WORK/editable.S" --entry-label 42 \
  --from-term /safe/new/from.term --to-term /safe/new/to.term \
  --expected-count 1 --output /safe/new/edited.S \
  --runtime-bin "$RUNTIME"
```

The command walks the selected parsed function recursively and requires the
exact match count. It rejects map-key collisions and validates the complete
assembly before committing the output.

## Rebuild and verify

```bash
"$TOOL" validate-assembly --workspace "$WORK" \
  --assembly /safe/new/edited.S --runtime-bin "$RUNTIME"
"$TOOL" rebuild --workspace "$WORK" --assembly /safe/new/edited.S \
  --output /safe/new/module.candidate.beam --runtime-bin "$RUNTIME"
"$TOOL" verify --original "$INPUT" \
  --candidate /safe/new/module.candidate.beam --runtime-bin "$RUNTIME"
```

An occupied output returns exit 73 and is never overwritten. Add
`--auto-version-output` to select the first free `.vN` path, or choose a new
path explicitly. Never delete an old output merely to make a command succeed;
retain it as provenance or choose a new name.

`validate-assembly` proves parse and assembly structure. `rebuild` proves a
BEAM can be emitted and disassembled. `verify` checks module, function count,
exports, and imports. A successful load in a disposable matching runtime adds
loader evidence. Only an application-level test proves the intended behavior.
These are separate gates; none should be reported as stronger evidence than it
is.

Loading may execute a module's `on_load` callback. Static extraction,
round-trip construction, and structural verification do not load the module.
Use only a disposable runtime for candidate load or behavior tests unless the
deployment itself is explicitly authorized. Before any real installation,
make a byte-exact backup, use an atomic replacement appropriate to that host,
and retain a tested rollback path.
