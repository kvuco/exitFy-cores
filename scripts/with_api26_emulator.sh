#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 1 ]]; then
  echo "usage: $0 COMMAND [ARG ...]" >&2
  exit 2
fi

if [[ -z "${ANDROID_HOME:-}" ]]; then
  echo "ANDROID_HOME is required" >&2
  exit 2
fi

sdkmanager_bin="${ANDROID_HOME}/cmdline-tools/latest/bin/sdkmanager"
avdmanager_bin="${ANDROID_HOME}/cmdline-tools/latest/bin/avdmanager"
emulator_bin="${ANDROID_HOME}/emulator/emulator"
adb_bin="${ANDROID_HOME}/platform-tools/adb"
for required in "$sdkmanager_bin" "$avdmanager_bin" "$emulator_bin" "$adb_bin"; do
  if [[ ! -x "$required" ]]; then
    echo "Android SDK tool is missing: $required" >&2
    exit 2
  fi
done

avd_name="exitfy-api26-${GITHUB_RUN_ID:-local}-${GITHUB_RUN_ATTEMPT:-0}"
serial="emulator-5554"
temporary="${RUNNER_TEMP:-${TMPDIR:-/tmp}}/$avd_name"
mkdir -p "$temporary"
export ANDROID_AVD_HOME="$temporary/avd"
mkdir -p "$ANDROID_AVD_HOME"

cleanup() {
  "$adb_bin" -s "$serial" emu kill >/dev/null 2>&1 || true
  if [[ -n "${emulator_pid:-}" ]]; then
    kill "$emulator_pid" >/dev/null 2>&1 || true
    wait "$emulator_pid" >/dev/null 2>&1 || true
  fi
  rm -rf "$ANDROID_AVD_HOME"
}
trap cleanup EXIT

yes | "$sdkmanager_bin" --licenses >/dev/null || true
"$sdkmanager_bin" "platform-tools" "emulator" \
  "system-images;android-26;default;x86_64"
echo no | "$avdmanager_bin" create avd --force --name "$avd_name" \
  --package "system-images;android-26;default;x86_64" --device pixel

"$emulator_bin" -avd "$avd_name" -port 5554 -no-window -no-audio \
  -no-boot-anim -no-snapshot -gpu swiftshader_indirect -camera-back none \
  >"$temporary/emulator.log" 2>&1 &
emulator_pid=$!

booted=false
for _ in $(seq 1 240); do
  if ! kill -0 "$emulator_pid" >/dev/null 2>&1; then
    break
  fi
  if [[ "$("$adb_bin" -s "$serial" shell getprop sys.boot_completed \
      2>/dev/null | tr -d '\r')" == "1" ]]; then
    booted=true
    break
  fi
  sleep 2
done
if [[ "$booted" != true ]]; then
  cat "$temporary/emulator.log" >&2
  echo "Android API 26 emulator did not boot" >&2
  exit 1
fi

"$adb_bin" -s "$serial" shell settings put global window_animation_scale 0
"$adb_bin" -s "$serial" shell settings put global transition_animation_scale 0
"$adb_bin" -s "$serial" shell settings put global animator_duration_scale 0
ANDROID_SERIAL="$serial" "$@"
