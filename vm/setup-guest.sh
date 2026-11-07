#!/usr/bin/env bash
# Runs INSIDE the Ubuntu VM as the VM user. Idempotent.
set -euo pipefail
sudo apt-get update -qq
sudo apt-get install -y -qq curl rsync python3 python3-venv ca-certificates fonts-liberation fonts-noto-color-emoji >/dev/null
# uv + a venv with playwright
if ! command -v uv >/dev/null; then curl -LsSf https://astral.sh/uv/install.sh | sh >/dev/null; fi
export PATH="$HOME/.local/bin:$PATH"
mkdir -p ~/render/in ~/render/out
cd ~/render
[ -d .venv ] && rm -rf .venv; uv venv -q --python 3.12 .venv
uv pip install -q --python .venv/bin/python "playwright>=1.49"
# Playwright's bundled Chromium segfaults on Ubuntu 26.10's 7.3 kernel (arm64); use the distro snap.
sudo snap install chromium >/dev/null 2>&1 || true
# unattended security updates, firewall: ssh only
sudo apt-get install -y -qq unattended-upgrades ufw >/dev/null
sudo ufw --force enable >/dev/null; sudo ufw allow 22/tcp >/dev/null
echo "guest ready: $(.venv/bin/pip show playwright 2>/dev/null | grep -i ^version || .venv/bin/python -c "import playwright, importlib.metadata as m; print(m.version(\"playwright\"))")"
