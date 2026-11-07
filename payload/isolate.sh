#!/usr/bin/env bash
set -euo pipefail
probe_root=$1
parent_namespace=$2
shard_id=$3
for input in frozen source venv bin tools; do
  mount --bind "$probe_root/$input" "$probe_root/$input"
  mount -o remount,bind,ro,nosuid,nodev "$probe_root/$input"
done
mount -o remount,bind,ro,nosuid,nodev,noexec "$probe_root/frozen"
mount -o remount,bind,ro,nosuid,nodev,noexec "$probe_root/source"
for area in artifacts upstream; do
  copy="$probe_root/work/tree/$area"
  mount --bind "$copy" "$copy"
  mount -o remount,bind,ro,nosuid,nodev,noexec "$copy"
done
exec setpriv --reuid=65534 --regid=65534 --clear-groups \
  --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
  env -i PATH="$probe_root/bin" LANG=C.UTF-8 LC_ALL=C.UTF-8 HOME="$probe_root/work/home" \
    TMPDIR="$probe_root/work/tmp" PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 PYTHONNOUSERSITE=1 PYTHONDONTWRITEBYTECODE=1 \
    GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null GIT_OPTIONAL_LOCKS=0 \
    "$probe_root/venv/bin/python" -I -B "$probe_root/frozen/validate.py" analyze "$probe_root" "$parent_namespace" "$shard_id"
