"""Resolve libusb from the Python environment on Windows."""

from pathlib import Path


def get_backend():
    import usb.backend.libusb1

    backend = usb.backend.libusb1.get_backend()
    if backend is not None:
        return backend
    try:
        import libusb_package
    except ImportError as exc:
        raise RuntimeError("libusb-package is required on this Windows Python") from exc
    library = libusb_package.get_library_path()
    if library is None or not Path(library).is_file():
        raise RuntimeError("libusb-package did not provide a library file")
    backend = usb.backend.libusb1.get_backend(find_library=lambda _: str(library))
    if backend is None:
        raise RuntimeError("bundled libusb library could not be loaded")
    return backend
