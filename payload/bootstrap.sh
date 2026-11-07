#!/usr/bin/env bash
set -euo pipefail
probe_root=$(mktemp -d /tmp/node115-full-XXXXXXXX)
chmod 755 "$probe_root"
mkdir "$probe_root/output"
mkdir -p "$GITHUB_WORKSPACE/probe-receipts"
cp -R payload "$probe_root/frozen"
collect() {
  find "$probe_root/output" -maxdepth 1 -type f -exec cp '{}' "$GITHUB_WORKSPACE/probe-receipts/" \;
}
trap collect EXIT
python3 -m venv "$probe_root/venv"
"$probe_root/venv/bin/python" -m pip install --require-hashes --only-binary=:all: --no-deps \
  --disable-pip-version-check --timeout 20 --retries 0 -r "$probe_root/frozen/requirements.txt"
curl --fail --location --max-time 50 --silent --show-error \
  'https://github.com/BurntSushi/ripgrep/releases/download/14.1.1/ripgrep-14.1.1-x86_64-unknown-linux-musl.tar.gz' \
  --output "$probe_root/ripgrep.tar.gz"
printf '%s  %s\n' '4cf9f2741e6c465ffdb7c26f38056a59e2a2544b51f7cc128ef28337eeae4d8e' \
  "$probe_root/ripgrep.tar.gz" | sha256sum --check
timeout --kill-after=5s 110s "$probe_root/venv/bin/python" -I -B "$probe_root/frozen/validate.py" \
  prepare "$probe_root" "$GITHUB_WORKSPACE/acquired"
parent_namespace=$(readlink /proc/self/ns/net)
sudo unshare --mount --net --pid --fork --mount-proc --propagation private \
  /bin/bash "$probe_root/frozen/isolate.sh" "$probe_root" "$parent_namespace"
