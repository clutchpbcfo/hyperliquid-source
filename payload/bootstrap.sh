#!/usr/bin/env bash
set -euo pipefail
probe_root=$(mktemp -d /tmp/hyper-git-diagnostic-XXXXXXXX)
chmod 755 "$probe_root"
mkdir -p "$GITHUB_WORKSPACE/diagnostic-receipts"
cp -R payload "$probe_root/frozen"
mkdir "$probe_root/output"
set +e
timeout --signal=TERM --kill-after=5s 180s python3 -I -B "$probe_root/frozen/control.py" prepare "$probe_root" "$GITHUB_WORKSPACE/source" > "$probe_root/output/acquisition.stdout" 2> "$probe_root/output/acquisition.stderr"
prepare_status=$?
set -e
if [ "$prepare_status" -ne 0 ]; then
  find "$probe_root/output" -maxdepth 1 -type f -exec cp '{}' "$GITHUB_WORKSPACE/diagnostic-receipts/" \;
  exit "$prepare_status"
fi
parent_network_namespace=$(readlink /proc/self/ns/net)
set +e
sudo unshare --mount --net --pid --fork --mount-proc --propagation private \
  /bin/bash "$probe_root/frozen/isolate.sh" "$probe_root" "$parent_network_namespace" > "$probe_root/output/namespace.stdout" 2> "$probe_root/output/namespace.stderr"
probe_status=$?
set -e
find "$probe_root/output" -maxdepth 1 -type f -exec cp '{}' "$GITHUB_WORKSPACE/diagnostic-receipts/" \;
exit "$probe_status"
