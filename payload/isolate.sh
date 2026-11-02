#!/usr/bin/env bash
set -euo pipefail
probe_root=$1
parent_network_namespace=$2
for input in frozen source venv bin; do
  mount --bind "$probe_root/$input" "$probe_root/$input"
  mount -o remount,bind,ro,nosuid,nodev "$probe_root/$input"
done
mount -o remount,bind,ro,nosuid,nodev,noexec "$probe_root/frozen"
mount -o remount,bind,ro,nosuid,nodev,noexec "$probe_root/source"
mount --bind "$probe_root/work" "$probe_root/source/work"
mount -o remount,bind,rw,nosuid,nodev,noexec "$probe_root/source/work"
cd "$probe_root/output"
exec setpriv --reuid=65534 --regid=65534 --clear-groups \
  --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
  env -i PATH="$probe_root/bin" LANG=C.UTF-8 LC_ALL=C.UTF-8 \
    HOME="$probe_root/home" TMPDIR="$probe_root/tmp" \
    PYTHONNOUSERSITE=1 PYTHONDONTWRITEBYTECODE=1 \
    GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL="$probe_root/safe-git-config" GIT_OPTIONAL_LOCKS=0 \
    "$probe_root/venv/bin/python" -I -B "$probe_root/frozen/control.py" analyze "$probe_root" "$parent_network_namespace"
