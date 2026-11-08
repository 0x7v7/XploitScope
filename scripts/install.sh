#!/usr/bin/env sh
set -eu

project_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
command -v go >/dev/null 2>&1 || {
    echo "Go is required. Install Go 1.22 or newer and retry." >&2
    exit 1
}

python_cmd=
if command -v python3 >/dev/null 2>&1; then
    python_cmd=python3
elif command -v python >/dev/null 2>&1; then
    python_cmd=python
else
    echo "Python 3 is required. Install Python 3 and retry." >&2
    exit 1
fi

"$python_cmd" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)' || {
    echo "Python 3.10 or newer is required." >&2
    exit 1
}

go_version=$(go env GOVERSION)
"$python_cmd" -c 'import re, sys; match = re.match(r"go(\d+)\.(\d+)", sys.argv[1]); sys.exit(0 if match and tuple(map(int, match.groups())) >= (1, 22) else 1)' "$go_version" || {
    echo "Go 1.22 or newer is required; found $go_version." >&2
    exit 1
}

echo "Using $go_version"
echo "Using $("$python_cmd" --version 2>&1)"

user_bin=${XPLOITSCOPE_BIN_DIR:-"$HOME/.local/bin"}
data_dir=${XDG_DATA_HOME:-"$HOME/.local/share"}/xploitscope
mkdir -p "$user_bin" "$data_dir"

build_dir=$(mktemp -d)
trap 'rm -rf "$build_dir"' EXIT HUP INT TERM
(
    cd "$project_root"
    go build -o "$build_dir/xploitscope" ./cmd/xploitscope
)
install -m 755 "$build_dir/xploitscope" "$user_bin/xploitscope"
mkdir -p "$data_dir/xploitscope_detector"
install -m 644 "$project_root/python/xploitscope_detector/"*.py "$data_dir/xploitscope_detector/"

echo "Installed XploitScope to $user_bin/xploitscope"
case ":$PATH:" in
    *":$user_bin:"*) ;;
    *) echo "Add $user_bin to PATH to run xploitscope from any directory." ;;
esac
echo "Run 'xploitscope doctor' to verify the installation."
