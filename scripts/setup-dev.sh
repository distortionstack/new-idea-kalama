#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
venv_path="${repo_root}/.venv"

if [[ ! -d "${venv_path}" ]]; then
  python3 -m venv "${venv_path}"
fi

"${venv_path}/bin/python" -m pip install --upgrade pip
"${venv_path}/bin/python" -m pip install -e "${repo_root}"

echo "Development environment installed."
echo "Activate it with: source ${venv_path}/bin/activate"
