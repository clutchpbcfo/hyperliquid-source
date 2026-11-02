#!/usr/bin/env bash
set -euo pipefail
probe_root=$(mktemp -d /tmp/hyper-jsonrpc-validation-XXXXXXXX)
chmod 755 "$probe_root"
mkdir -p "$GITHUB_WORKSPACE/probe-receipts"
cp -R payload "$probe_root/frozen"
mkdir "$probe_root/output"
python3 -m venv "$probe_root/venv"
curl --fail --location --max-time 90 --silent --show-error \
  'https://files.pythonhosted.org/packages/15/3e/3a4f45dd4eda6fc8051f76bf3ed50ead6040d827000371211fbaaf057625/capstone-5.0.7-py3-none-manylinux_2_17_x86_64.manylinux2014_x86_64.whl' \
  --output "$probe_root/capstone-5.0.7-py3-none-manylinux_2_17_x86_64.manylinux2014_x86_64.whl"
printf '%s  %s\n' 'b809a9654844ce0d35099121a851ddd2ab2689df1ff6687037babcedcaae6391' \
  "$probe_root/capstone-5.0.7-py3-none-manylinux_2_17_x86_64.manylinux2014_x86_64.whl" | sha256sum --check
"$probe_root/venv/bin/python" -m pip install --no-index --no-deps --disable-pip-version-check \
  "$probe_root/capstone-5.0.7-py3-none-manylinux_2_17_x86_64.manylinux2014_x86_64.whl"
set +e
"$probe_root/venv/bin/python" -I -B "$probe_root/frozen/control.py" prepare "$probe_root" "$GITHUB_WORKSPACE/source" > "$probe_root/output/acquisition.stdout" 2> "$probe_root/output/acquisition.stderr"
prepare_status=$?
set -e
if [ "$prepare_status" -ne 0 ]; then
  find "$probe_root/output" -maxdepth 1 -type f -exec cp '{}' "$GITHUB_WORKSPACE/probe-receipts/" \;
  exit "$prepare_status"
fi
parent_network_namespace=$(readlink /proc/self/ns/net)
set +e
sudo unshare --mount --net --pid --fork --mount-proc --propagation private \
  /bin/bash "$probe_root/frozen/isolate.sh" "$probe_root" "$parent_network_namespace" > "$probe_root/output/namespace.stdout" 2> "$probe_root/output/namespace.stderr"
probe_status=$?
set -e
find "$probe_root/output" -maxdepth 1 -type f -exec cp '{}' "$GITHUB_WORKSPACE/probe-receipts/" \;
cp "$probe_root/preparation.json" "$GITHUB_WORKSPACE/probe-receipts/"
exit "$probe_status"
