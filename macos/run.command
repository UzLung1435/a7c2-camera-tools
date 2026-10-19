#!/bin/sh
set -eu
base=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$base"

python3 -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 10) else 1)' || {
    echo 'Python 3.10 or newer is required / 需要 Python 3.10 或更新版本。' >&2
    exit 1
}

camera_python="$base/a7c2-200-venv/bin/python"
if [ ! -x "$camera_python" ]; then
    python3 -m venv "$base/a7c2-200-venv"
fi

if ! "$camera_python" -c 'import numpy, Crypto, Cryptodome, usb, libusb_package, imageio_ffmpeg' >/dev/null 2>&1; then
    echo 'Installing Python packages / 正在安装 Python 依赖...'
    "$camera_python" -m pip install --disable-pip-version-check --only-binary=:all: \
        'numpy>=1.26,<3' 'pycryptodome>=3.20,<4' \
        'pycryptodomex>=3.20,<4' 'pyusb==1.3.1' \
        'libusb-package==1.0.30.0' 'imageio-ffmpeg==0.6.0'
fi

"$camera_python" -c 'from pathlib import Path; import libusb_package, usb.backend.libusb1; p=libusb_package.get_library_path(); assert p is not None and Path(p).is_file(); assert usb.backend.libusb1.get_backend(find_library=lambda _: str(p)) is not None'

exec "$camera_python" "$base/mac_service_readonly/ui.py" "$@"
