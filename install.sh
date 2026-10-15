#!/usr/bin/env bash
set -e

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
chmod +x "$REPO_DIR/bin/secdict"
chmod +x "$REPO_DIR/scripts/build_dataset.py"

python3 "$REPO_DIR/scripts/build_dataset.py" --from-shards

if [ -n "$PREFIX" ] && [ -d "$PREFIX/bin" ]; then
  ln -sf "$REPO_DIR/bin/secdict" "$PREFIX/bin/secdict"
  echo "[+] Installed secdict to $PREFIX/bin/secdict"
elif [ -w "/usr/local/bin" ]; then
  ln -sf "$REPO_DIR/bin/secdict" "/usr/local/bin/secdict"
  echo "[+] Installed secdict to /usr/local/bin/secdict"
else
  sudo ln -sf "$REPO_DIR/bin/secdict" "/usr/local/bin/secdict"
  echo "[+] Installed secdict to /usr/local/bin/secdict"
fi

echo "[+] Run 'secdict --stats' or 'secdict nmap' from anywhere."
