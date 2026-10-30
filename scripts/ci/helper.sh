#!/bin/bash
# The privileged helper (docs/helper.md) on a proxy-free runner with passwordless sudo:
# loads it as a system launchd daemon (what SMAppService does after approval, which CI can't
# click), then drives it over XPC with `SluiceHelper client`:
#   1. handshake runs as root; a different executable is rejected
#   2. start/stop the core without TUN
#      and reject a substituted core
#   3. enhanced mode through the helper, then "crash" the app: the helper must stop the core
#      and routes/DNS must be restored
# Needs: ./target/release/sluice and apps/macos/.build/release/SluiceHelper.
set -u
cd "$(dirname "$0")/../.."
work=$(mktemp -d)
mkdir -p ci-logs
fails=0
out=ci-logs/helper-output.txt
exec 3>&1 > "$out" 2>&1
helper=$PWD/apps/macos/.build/release/SluiceHelper
core=$PWD/target/release/sluice
label=dev.sluice.Sluice.helper
plist=/Library/LaunchDaemons/$label.plist
pass() { echo "PASS  $1"; }
fail() { echo "FAIL  $1"; fails=$((fails + 1)); }
# NTP reachability varies between runners; the tun job covers it.
export SLUICE_CHECK_NTP=0
check() { if eval "$2"; then pass "$1"; else fail "$1"; fi; }

# Patching the helper invalidates its signature; sign it again before launchd loads it.
if ! scripts/record-core-cdhash.sh "$helper" "$core" || ! codesign -f -s - "$helper"; then
  echo "failed to embed core cdhashes and sign helper"
  exec 1>&3 2>&1
  cat "$out"
  exit 1
fi

sudo tee "$plist" > /dev/null <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>$label</string>
  <key>Program</key><string>$helper</string>
  <key>MachServices</key><dict><key>$label</key><true/></dict>
  <key>EnvironmentVariables</key><dict>
    <key>SLUICE_HELPER_CORE</key><string>$core</string>
    <key>SLUICE_HELPER_CLIENT</key><string>$helper</string>
  </dict>
  <key>StandardErrorPath</key><string>$PWD/ci-logs/helper-daemon.log</string>
</dict></plist>
PLIST
sudo launchctl bootstrap system "$plist" || fail "launchctl bootstrap"

echo "=================== handshake"
hello=$("$helper" client hello); echo "$hello"
check "helper answers over XPC as root" "[[ '$hello' == *'uid 0'* ]]"
cp "$helper" "$work/impostor"
check "other executables are rejected" "! '$work/impostor' client hello"

echo "=================== core without TUN"
printf '[General]\napi-listen = 127.0.0.1:6170\n[Rule]\nFINAL,DIRECT\n' > "$work/plain.conf"
"$helper" client start "$work/plain.conf"
for _ in $(seq 30); do curl -s -m 2 -o /dev/null http://127.0.0.1:6170/v1/policies && break; sleep 0.5; done
check "core API up" "curl -s -m 2 -o /dev/null http://127.0.0.1:6170/v1/policies"
check "core runs as root" "[ \"\$(ps -o user= -p \$(pgrep -x sluice))\" = root ]"
"$helper" client stop
check "core stopped" "! pgrep -x sluice > /dev/null"

echo "=================== substituted core"
# Keep the original signed bytes and restore them even if the script is interrupted.
cp -p "$core" "$work/core-original"
restore_core() { cp -p "$work/core-original" "$core"; }
trap restore_core EXIT
if cp /usr/bin/true "$core"; then
  rejected=$("$helper" client start "$work/plain.conf" 2>&1)
  result=$?
  echo "$rejected"
  if [[ $result != 0 && $rejected == *"refused core:"* ]]; then
    pass "substituted core is refused"
  else
    fail "substituted core is refused"
    "$helper" client stop
  fi
else
  fail "substitute core for rejection check"
fi
restore_core
trap - EXIT

echo "=================== enhanced mode, app crash"
# The output can't reach the job log while the TUN is up; a watchdog guarantees it comes down.
sleep 300 & app=$!
(sleep 120; sudo pkill -INT -x sluice && echo "!! watchdog stopped Sluice") & watchdog=$!
"$helper" client start "$PWD/examples/tun-test.conf" "$app"
for _ in $(seq 30); do curl -s -m 2 -o /dev/null http://127.0.0.1:6170/v1/policies && break; sleep 0.5; done
sleep 1
scripts/tun-check.sh || fails=$((fails + 1))
kill "$app"
for _ in $(seq 30); do pgrep -x sluice > /dev/null || break; sleep 0.5; done
kill "$watchdog" 2>/dev/null
check "helper stopped the core when the app died" "! grep -q 'watchdog' '$out'"
scripts/tun-check.sh after || fails=$((fails + 1))
echo "-- core log"; tail -15 /Library/Logs/Sluice/core.log

sudo launchctl bootout "system/$label"
sudo rm -f "$plist"
echo "-- daemon log"; cat ci-logs/helper-daemon.log
echo; [ $fails = 0 ] && echo "All helper checks passed." || echo "$fails helper check(s) failed."
exec 1>&3 2>&1
cat "$out"
exit $fails
