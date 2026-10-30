#!/bin/bash
# Offline developer checks. Dependencies must already be cached; nothing is downloaded.
# Usage: OUT=target/local-check scripts/local-check.sh [--only name1,name2] [--skip name]
# Names are printed by --help. Each row has its own log and temporary HOME.
set -uo pipefail
cd "$(dirname "$0")/.."
ROOT=$PWD
names=(cargo-test clippy swift-build swift-test configs convert imports routes ca diag app dmg smoke)
only=,; skip=,
usage() {
    echo "Usage: $0 [--only name1,name2] [--skip name[,name...]]"
    echo "Checks: ${names[*]}"
    echo 'OUT defaults to target/local-check. Requires cached Cargo and Swift dependencies.'
}
validate_names() {
    local item
    local -a requested
    IFS=, read -r -a requested <<< "$1"
    for item in "${requested[@]}"; do
        case " ${names[*]} " in *" $item "*) ;; *) echo "Unknown check: $item" >&2; exit 2 ;; esac
    done
}
while (($#)); do
    case "$1" in
        --only|--skip)
            (($# >= 2)) && [[ -n $2 ]] || { usage >&2; exit 2; }
            validate_names "$2"
            if [[ $1 == --only ]]; then only="$only$2,"; else skip="$skip$2,"; fi
            shift 2 ;;
        -h|--help) usage; exit 0 ;;
        *) usage >&2; exit 2 ;;
    esac
done
mkdir -p "${OUT:-target/local-check}"
OUT=$(cd "${OUT:-target/local-check}" && pwd)
export OUT
work=$(mktemp -d "${TMPDIR:-/tmp}/sluice-local-check.XXXXXX")
trap 'rm -rf "$work"' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
original_cargo_home=${CARGO_HOME:-$HOME/.cargo}
export RUSTUP_HOME=${RUSTUP_HOME:-$HOME/.rustup}
# Use an installed toolchain, never rustup's network-backed toolchain selection.
rust_bin=$(rustup which cargo 2>/dev/null || command -v cargo || true)
[[ -z $rust_bin ]] || rust_bin=$(dirname "$rust_bin")
swift_bin=$(command -v swift || true)
export LOCAL_CHECK_SWIFT=$swift_bin
export CARGO_HOME="$work/cargo"
export CARGO_NET_OFFLINE=true CARGO_TERM_COLOR=never
export CARGO_TARGET_DIR="$ROOT/target"
mkdir -p "$work/bin" "$CARGO_HOME"
# Private copies let Cargo write its locks/cache metadata without touching ~/.cargo.
prepare_cargo() {
    [[ -f $CARGO_HOME/.ready ]] && return
    local dir
    for dir in registry git; do
        if [[ -d $original_cargo_home/$dir ]]; then
            cp -cR "$original_cargo_home/$dir" "$CARGO_HOME/" 2>/dev/null || {
                rm -rf "$CARGO_HOME/$dir"
                cp -R "$original_cargo_home/$dir" "$CARGO_HOME/"
            }
        fi
    done
    touch "$CARGO_HOME/.ready"
}
cat > "$work/bin/swift" <<'SH'
#!/bin/bash
set -euo pipefail
# Resolution is locked; cached checkout and binary artifact are required below.
exec "$LOCAL_CHECK_SWIFT" "$@" --disable-automatic-resolution --skip-update \
    --disable-sandbox --cache-path "$HOME/swift-cache" \
    --config-path "$HOME/swift-config" --security-path "$HOME/swift-security" \
    -Xcc "-fmodules-cache-path=$HOME/clang-cache"
SH
chmod +x "$work/bin/swift"
export PATH="$work/bin${rust_bin:+:$rust_bin}:$PATH"
unset http_proxy https_proxy all_proxy HTTP_PROXY HTTPS_PROXY ALL_PROXY no_proxy NO_PROXY
unset SLUICE_LOG_DIR SUDO_USER SIGN_IDENTITY UNIVERSAL SKIP_APP_BUILD
unset SLUICE_E2E_CONFIG SLUICE_GENERATED_CONFIG_DIR
export SIGN_IDENTITY=- UNIVERSAL=0
export SLUICE_LOCAL_CHECK_ROOT=$ROOT
export SLUICE_LOCAL_CHECK_FIXTURES="$ROOT/tests/fixtures/local-check"
export SLUICE_LOCAL_CHECK_BINARY="$ROOT/target/release/sluice"
need() { command -v "$1" >/dev/null || { echo "SKIP: missing tool $1"; exit 77; }; }
core() { need cargo; prepare_cargo; cargo build --release --offline --locked; }
swift_ready() {
    [[ $(uname -s) == Darwin && -n $swift_bin ]] || { echo 'SKIP: macOS Swift required'; exit 77; }
    # SwiftPM can otherwise try to fetch missing checkouts or binary artifacts.
    [[ -f apps/macos/.build/checkouts/Sparkle/Package.swift &&
       -d apps/macos/.build/artifacts/sparkle/Sparkle/Sparkle.xcframework ]] || {
        echo 'SKIP: Sparkle checkout/artifact not cached in apps/macos/.build (offline)'; exit 77;
    }
}
helper() { need python3; python3 -I scripts/local-check/check.py "$1"; }
check_cargo_test() { need cargo; prepare_cargo; cargo test --release --offline --locked; }
check_clippy() { need cargo; prepare_cargo; cargo clippy --offline --locked --all-targets -- -D warnings; }
check_swift_build() { swift_ready; (cd apps/macos && swift build); }
check_swift_test() { swift_ready; (cd apps/macos && swift test); }
check_configs() {
    core
    # Check each example before trying Swift, so a blocked Swift build doesn't hide it.
    helper examples
    swift_ready
    export SLUICE_GENERATED_CONFIG_DIR="$CHECK_WORK/generated"
    (cd apps/macos && swift test --filter GeneratedConfigTests)
    helper generated
}
check_convert() { core; helper convert; }
check_imports() { core; helper imports; }
check_routes() { core; helper routes; }
check_ca() { core; need openssl; helper ca; }
check_diag() { core; helper diag; }
verify_app() {
    local app=dist/Sluice.app/Contents
    for f in MacOS/Sluice MacOS/SluiceHelper Resources/sluice Resources/Sluice.icns \
        Library/LaunchDaemons/dev.sluice.Sluice.helper.plist; do
        [[ -s $app/$f ]] || { echo "Missing bundle file: $f"; return 1; }
    done
    [[ -d $app/Frameworks/Sparkle.framework ]] || { echo 'Missing Sparkle.framework'; return 1; }
    [[ -x $app/MacOS/Sluice && -x $app/MacOS/SluiceHelper && -x $app/Resources/sluice ]]
    codesign --verify --deep --strict dist/Sluice.app
}
check_app() {
    swift_ready; need codesign; prepare_cargo
    scripts/build-app.sh
    verify_app
}
check_dmg() {
    swift_ready; need codesign; need hdiutil; prepare_cargo
    # Independently build; --only dmg never trusts an old bundle or image.
    scripts/build-dmg.sh
    verify_app
    local version
    version=$(/usr/libexec/PlistBuddy -c 'Print :CFBundleShortVersionString' dist/Sluice.app/Contents/Info.plist)
    [[ -s dist/Sluice-$version.dmg ]]
    hdiutil verify "dist/Sluice-$version.dmg"
}
check_smoke() { core; helper smoke; }
: > "$OUT/summary.tsv"
failed=0
for name in "${names[@]}"; do
    status=SKIP; detail='filtered out'
    if [[ ( $only == , || $only == *,$name,* ) && $skip != *,$name,* ]]; then
        echo "Running $name (log: $OUT/$name.log)"
        (
            set -e
            export CHECK_WORK="$work/$name"
            mkdir -p "$CHECK_WORK/home" "$CHECK_WORK/tmp"
            export HOME="$CHECK_WORK/home" CFFIXED_USER_HOME="$CHECK_WORK/home" TMPDIR="$CHECK_WORK/tmp/"
            export XDG_CACHE_HOME="$HOME/.cache" CLANG_MODULE_CACHE_PATH="$HOME/clang-cache"
            "check_${name//-/_}"
        ) > "$OUT/$name.log" 2>&1
        rc=$?
        case $rc in
            0) status=PASS; detail=ok ;;
            77) status=SKIP; detail=$(tail -1 "$OUT/$name.log") ;;
            *) status=FAIL; detail="exit $rc; see $name.log"; failed=1
               if LC_ALL=C grep -Eq 'Operation not permitted|PermissionDenied|sandbox.*denied|sandbox_apply' "$OUT/$name.log"; then
                   detail="exit $rc (permission/sandbox error); see $name.log"
               fi ;;
        esac
    else
        echo 'SKIP: filtered out by --only/--skip' > "$OUT/$name.log"
    fi
    printf '%s\t%s\t%s\n' "$name" "$status" "$detail" >> "$OUT/summary.tsv"
done
printf '\n%-14s %-6s %s\n' CHECK RESULT DETAIL
while IFS=$'\t' read -r name status detail; do
    printf '%-14s %-6s %s\n' "$name" "$status" "$detail"
done < "$OUT/summary.tsv"
exit "$failed"
