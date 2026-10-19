# Native worker sources

The editable C sources for the AArch64 workers are under `source/`. The fixed
p1 window reader source remains beside its worker in each platform directory.
The distributed color and p1 worker templates contain empty data slots.

`generate_private_headers.py --p1 <saved-p1.img> --bk4 <saved-Backup.bin>`
creates ignored, local headers from a read-only camera capture. It does not
connect to the camera. The installer itself reconstructs each checked worker
from these camera-owned data before use.

With Zig 0.14.1, `compile_p1_templates.sh <zig> native/generated <output-dir>`
compiles the eight p1 variants. Run `verify_p1_templates.py --compiled-dir
<output-dir>` to check the empty templates against the shipped binaries.
`compile_misc_workers.sh` and `verify_misc_workers.py` cover the update,
BK4, and CP workers. The CP workers' runtime load segments are compared after
ignoring the ELF section-table pointer, which is not loaded by the camera.
`compile_window.py` covers the fixed p1 window reader.

The pinned worker binaries remain the installation artifacts. Recompiling a
worker requires an AArch64 Linux toolchain and a byte-level comparison against
the pinned binary before it can replace an artifact.
