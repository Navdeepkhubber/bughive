#!/usr/bin/env bash
# Install bughive's DSH plugins into a profile.
#
# Two failure modes this script now handles, both of which previously aborted the
# install after the FIRST plugin:
#
#  1. pnpm refuses to run ANY install while the profile's pnpm-workspace.yaml still
#     contains the placeholder values its interactive prompt writes
#     ("set this to true or false"), failing with ERR_PNPM_IGNORED_BUILDS.
#     We repair those in place and preserve any other customisation.
#
#  2. A single bad plugin (a git dependency needing a prepare script pnpm blocks)
#     killed the loop because of `set -e`. Now each plugin is attempted
#     independently, failures are collected, and the run continues so every
#     bughive plugin still lands.
set -uo pipefail

PROFILE="${DSH_PROFILE:-web}"
PROFILE_DIR="${DSH_PROFILE_DIR:-$HOME/.dsh/profiles/$PROFILE}"

echo "→ Installing into DSH profile: $PROFILE"

# ---------------------------------------------------------------- 1. pnpm policy
# pnpm blocks lifecycle scripts by default. DSH's own dependencies need a few of
# them, and its prompt writes string placeholders that pnpm then rejects.
ensure_allow_builds() {
  local ws="$PROFILE_DIR/pnpm-workspace.yaml"
  [ -d "$PROFILE_DIR" ] || return 0

  if [ ! -f "$ws" ]; then
    echo "  · creating $ws with allowBuilds defaults"
    cat > "$ws" <<'YAML'
packages:
  - .

nodeLinker: hoisted
autoInstallPeers: false

# Native/runtime build scripts required by DSH's own dependencies.
allowBuilds:
  '@deepseek-ai/dsh-subprocess-local': true
  '@google/genai': true
  koffi: true
  node-pty: true
  protobufjs: true
YAML
    return 0
  fi

  if grep -q 'set this to true or false' "$ws"; then
    echo "  · repairing placeholder allowBuilds values in $ws"
    # Only touch the placeholder lines; leave the rest of the file alone.
    sed -i.bak 's/: set this to true or false$/: true/' "$ws"
  fi
}

ensure_allow_builds

# --------------------------------------------------- 2. optional external plugins
# These are third-party conveniences, not required for bughive. A git-hosted plugin
# whose prepare script pnpm blocks will fail with ERR_PNPM_GIT_DEP_PREPARE_NOT_ALLOWED;
# that is a supply-chain decision for the operator, so we warn instead of aborting.
add_optional() {
  local spec="$1"
  if dsh plugin --profile "$PROFILE" add "$spec" >/dev/null 2>&1; then
    echo "  ✓ optional: $spec"
  else
    echo "  · skipped optional: $spec"
    echo "      (pnpm blocked its build script; to allow it, add the exact key pnpm"
    echo "       printed to allowBuilds in $PROFILE_DIR/pnpm-workspace.yaml)"
  fi
}
add_optional "github:PerryLink/dsh-budget#main"
add_optional "github:dmsobtl/dsh-skill-evolve#main"

# ------------------------------------------------------------- 3. bughive plugins
failed=()
installed=0
for p in plugins/*/; do
  [ -f "$p/package.json" ] || continue
  name="$(basename "$p")"
  if ( cd "$p" && dsh plugin --profile "$PROFILE" add . >/dev/null 2>&1 ); then
    echo "  + $name"
    installed=$((installed + 1))
  else
    echo "  ✗ $name"
    failed+=("$name")
  fi
done

echo "→ Installed $installed plugin(s)"

# ------------------------------------------------------------------ 4. verify
# Expected ids are read from each plugin's own cordis.patch.yml, so this list never
# goes stale when a plugin is added or renamed.
echo "→ Verifying config"
config="$(dsh --profile "$PROFILE" --dump-config 2>/dev/null || true)"
missing=()
expected=0
for p in plugins/*/; do
  patch="$p/cordis.patch.yml"
  [ -f "$patch" ] || continue
  id="$(sed -n 's/^[[:space:]]*-[[:space:]]*id:[[:space:]]*\([A-Za-z0-9._-]*\).*/\1/p' "$patch" | head -1)"
  [ -n "$id" ] || continue
  expected=$((expected + 1))
  case "$config" in
    *"id: $id"*) ;;
    *) missing+=("$id ($(basename "$p"))") ;;
  esac
done

if [ ${#failed[@]} -gt 0 ]; then
  echo "!! plugin install failed: ${failed[*]}"
fi
if [ ${#missing[@]} -gt 0 ]; then
  echo "!! $expected expected, ${#missing[@]} not present in --dump-config:"
  printf '     - %s\n' "${missing[@]}"
  echo "   Fix pnpm first, then re-run. Inspect with: dsh plugin --profile $PROFILE list"
  exit 1
fi

echo "✓ All $expected plugins registered. Restart DSH: dsh --profile $PROFILE"
