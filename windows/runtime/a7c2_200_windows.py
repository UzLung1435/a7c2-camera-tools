#!/usr/bin/env python3
"""Interactive Windows A7C II 2.01 to persistent FL2/FL3 2.00 workflow."""

import argparse
import ctypes
from datetime import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time
import winreg

import ui

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "release"))
import feature_package_200 as feature_package
RUNS = ROOT / "runs"
OFFICIAL_SHA = "eb4943e6099754d64deaef5047942e9bfe258f232d0b7bc39fa23b3cd10e1e31"
BK4_SOURCE_SHA = "f6897866e2014a972d17383ea2c6fef4096fc5a3166f348eaff3c60f67a23ba1"
BK4_TARGET_SHA = "1035933d52e7198f9656181dc2e8242fa90fc95018eba3823a102c669e02f6f2"
OFFICIAL = ROOT.parent / "ILCE-7CM2-v2.01-BODYDATA.DAT"
TARGET = ROOT.parent / "BODYDATA_FL23_200.DAT"
SCREEN = ui.Console("zh")
LOG_DIR = None
RUN_COUNT = 0


class Stopped(Exception):
    pass


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(path):
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(8 << 20), b""):
            h.update(block)
    return h.hexdigest()


def official_source():
    if OFFICIAL.is_file():
        require(digest(OFFICIAL) == OFFICIAL_SHA,
                "同名官方 2.01 DAT 的 SHA-256 不匹配")
        return OFFICIAL
    candidates = [path for path in ROOT.parent.glob("*.DAT")
                  if path.name != TARGET.name and path.is_file() and
                  digest(path) == OFFICIAL_SHA]
    require(len(candidates) == 1,
            "请在 BAT 同目录放入恰好一份未修改的官方 A7C II 2.01 DAT")
    return candidates[0]


def confirm(word, message):
    if not SCREEN.manual(word, message):
        raise Stopped("stopped by user; progress was saved")


def run(script, *args):
    global RUN_COUNT
    RUN_COUNT += 1
    SCREEN.child_start(script)
    stamp = datetime.now().strftime("%Y%m%dT%H%M%S%f")
    log_path = LOG_DIR / f"{stamp}-{RUN_COUNT:02d}-{Path(script).stem}.log"
    try:
        with log_path.open("w", encoding="utf-8") as log:
            child = subprocess.Popen([sys.executable, str(ROOT / script),
                                      *map(str, args)], stdout=subprocess.PIPE,
                                     stderr=subprocess.STDOUT, text=True,
                                     encoding="utf-8", errors="replace", bufsize=1)
            tail = []
            for line in child.stdout:
                log.write(line)
                tail = (tail + [line.rstrip()])[-8:]
                SCREEN.child_line(line)
            code = child.wait()
    finally:
        SCREEN.child_done()
    if code:
        SCREEN.failure(script, log_path, tail)
    require(code == 0, f"{script} failed; log: {log_path}")


def pnp(timeout=25):
    from windows_service_probe import windows_devices
    deadline = time.monotonic() + timeout
    waiting = False
    while True:
        inventory = windows_devices()["devices"]
        candidates = [x for x in inventory
                      if x["id"].upper().startswith("USB\\VID_054C&PID_0E8A\\")]
        entries = [x for x in candidates if x["status"] == "OK"]
        if len(entries) == 1:
            break
        require(len(entries) < 2, "检测到多台状态正常的 A7C II；停止自动选择")
        if time.monotonic() >= deadline:
            observed = [(x["id"], x["status"], x.get("service"))
                        for x in inventory]
            raise ValueError(f"{timeout} 秒内未见状态为 OK 的 A7C II (054C:0E8A)；"
                             "Sony USB 设备：" + repr(observed))
        if not waiting:
            SCREEN.note_pair(("等待相机从服务模式返回普通 USB…",
                              "Waiting for the camera to return to normal USB…"))
            waiting = True
        time.sleep(1)
    item = entries[0]
    serial = item["id"].rsplit("\\", 1)[-1].upper()
    require(re.fullmatch(r"[0-9A-F]{12}", serial), "相机 USB 序列号格式不符")
    return serial, str(item["service"]).upper(), item["id"]


def property_value(instance, key):
    script = ("$ErrorActionPreference='Stop'; "
              "$x=Get-PnpDeviceProperty -InstanceId $env:A7C2_DEVICE_ID "
              "-KeyName '" + key + "'; [Console]::Write($x.Data)")
    env = dict(os.environ, A7C2_DEVICE_ID=instance)
    result = subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive",
                             "-Command", script], env=env, capture_output=True,
                            text=True, timeout=30)
    require(result.returncode == 0, "无法读取相机驱动属性")
    return result.stdout.strip()


def pnputil(*args, timeout=90):
    try:
        result = subprocess.run(["pnputil.exe", *map(str, args)],
                                capture_output=True, text=True,
                                errors="replace", timeout=timeout)
    except subprocess.TimeoutExpired:
        return False
    return result.returncode == 0


def save_driver(run_dir, serial):
    _, service, instance = pnp()
    require(service == "WINUSB", "普通模式仍未绑定 WinUSB")
    inf = property_value(instance, "DEVPKEY_Device_DriverInfPath")
    require(re.fullmatch(r"oem[0-9]+\.inf", inf, re.I),
            "普通模式驱动 INF 身份不符合预期")
    destination = run_dir / "normal_winusb_driver"
    destination.mkdir(exist_ok=True)
    if not list(destination.glob("*.inf")):
        require(pnputil("/export-driver", inf, destination),
                "无法导出本机普通模式 WinUSB 驱动")
    require(len(list(destination.glob("*.inf"))) == 1,
            "普通模式驱动导出文件数量不符")
    return next(destination.glob("*.inf"))


def ensure_winusb(run_dir, serial):
    current, service, instance = pnp()
    require(current == serial, "连接的相机已变化")
    if service in {"LIBUSBK", "LIBUSB0"}:
        clear_driver_bindings(serial, instance)
        current, service, _ = pnp()
        require(current == serial, "连接的相机已变化")
    if service != "WINUSB":
        require(service == "USBSTOR", "相机普通模式驱动不受支持：" + str(service))
        candidate = run_dir / "normal_winusb_driver" / "ilce-7cm2.inf"
        if not candidate.is_file():
            candidate = ROOT / "tools" / "normal_winusb_export" / "ilce-7cm2.inf"
        if candidate.is_file():
            pnputil("/add-driver", candidate, "/install")
        _, service, _ = pnp()
        if service != "WINUSB":
            zadig = (ROOT.parent / "zadig.exe")
            if not zadig.is_file():
                found = shutil.which("zadig")
                zadig = Path(found) if found else None
            if zadig is not None:
                subprocess.Popen([str(zadig)])
            confirm("0E8A WINUSB", "Zadig 完成普通模式绑定后回到此窗口。")
            current, service, _ = pnp()
            require(current == serial and service == "WINUSB",
                    "054C:0E8A WinUSB 仍未生效")
    save_driver(run_dir, serial)
    SCREEN.note_pair(("普通模式 WinUSB 已验证。", "Normal-mode WinUSB verified."))


def prepare_service_driver():
    local = Path.home() / "usb_driver" / "A7C_II_service_mode.inf"
    inf = (local if local.is_file() else
           ROOT / "tools" / "service_winusb_export" /
           "a7c_ii_service_mode.inf")
    require(inf.is_file() and inf.with_suffix(".cat").is_file(),
            "缺少 054C:0336 WinUSB INF/CAT")
    result = subprocess.run(["pnputil.exe", "/add-driver", str(inf), "/install"],
                            capture_output=True, text=True, errors="replace",
                            timeout=90)
    if result.returncode:
        raise ValueError("054C:0336 驱动未放入本机驱动库；"
                         "请在 Zadig 用 Device → Load Preset Device 加载 "
                         "runtime/tools/a7c2_service_0336.cfg，选择 WinUSB 后重试。\n" +
                         (result.stdout + result.stderr)[-1000:])
    SCREEN.note_pair(("054C:0336 WinUSB 驱动已放入本机驱动库：" + str(inf),
                      "054C:0336 WinUSB driver staged: " + str(inf)))


def read_version_201(run_dir, serial, output):
    arguments = ("--serial", serial, "--out", output,
                 "--expected-dat4-hex", "0102", "--execute")
    try:
        run("windows_rollback_gate_ro.py", *arguments)
        return
    except ValueError:
        from windows_service_probe import windows_devices
        service = [x for x in windows_devices()["devices"]
                   if "PID_0336" in x["id"].upper()]
        if service and any(str(x["service"]).upper() != "WINUSB"
                           for x in service):
            raise ValueError("054C:0336 没有绑定 WinUSB；请先在本机准备服务模式驱动，"
                             "可用 runtime/tools/a7c2_service_0336.cfg 的 Zadig 预设；"
                             "恢复普通 0E8A 连接后重启 BAT")
        raise


def driver_package_field(block, *names):
    for name in names:
        match = re.search(r"^\s*" + re.escape(name) + r"\s*:\s*(.+?)\s*$",
                          block, re.M)
        if match:
            return match.group(1)
    return ""


def third_party_packages_0e8a():
    """Published names of every Zadig-style package registered for 0E8A.

    Zadig keeps one package per backend it was ever used with, so a single
    camera can carry libwdi, libusbK and libusb-win32 entries at the same
    time. Removing only the currently bound one lets the next package bind
    immediately, so the device never falls back to USBSTOR and the exporter
    never sees the card. Only libwdi-generated packages are matched, which
    leaves Sony's own drivers (Imaging Edge Webcam etc.) untouched.
    """
    result = subprocess.run(["pnputil.exe", "/enum-drivers"],
                            capture_output=True, text=True,
                            encoding="mbcs", errors="replace", timeout=60)
    require(result.returncode == 0, "无法枚举本机驱动包")
    found = []
    for block in re.split(r"\r?\n[ \t]*\r?\n", result.stdout):
        if not re.search(r"VID_054C&PID_0E8A", block, re.I):
            continue
        provider = driver_package_field(block, "提供程序名称", "Provider Name")
        published = driver_package_field(block, "发布名称", "Published Name")
        if provider.lower() not in {"libwdi", "libusbk", "libusb-win32"}:
            continue
        if re.fullmatch(r"oem[0-9]+\.inf", published, re.I):
            found.append(published)
    return found


_CFGMGR32 = None
DN_HAS_PROBLEM = 0x00000400


def cfgmgr32():
    global _CFGMGR32
    if _CFGMGR32 is None:
        from ctypes import wintypes
        lib = ctypes.WinDLL("cfgmgr32")
        lib.CM_Locate_DevNodeW.argtypes = [ctypes.POINTER(wintypes.ULONG),
                                           wintypes.LPCWSTR, wintypes.ULONG]
        lib.CM_Locate_DevNodeW.restype = wintypes.ULONG
        lib.CM_Get_DevNode_Status.argtypes = [ctypes.POINTER(wintypes.ULONG),
                                              ctypes.POINTER(wintypes.ULONG),
                                              wintypes.ULONG, wintypes.ULONG]
        lib.CM_Get_DevNode_Status.restype = wintypes.ULONG
        _CFGMGR32 = lib
    return _CFGMGR32


def device_binding(instance):
    """Status and driver service of one PnP node, without spawning a process.

    Driver-store churn (pnputil /delete-driver, rescans) makes a full WMI
    enumeration block for tens of seconds, and even a healthy PowerShell probe
    costs about ten seconds here - both are useless for watching a
    re-enumeration that lasts a few seconds. CM_Get_DevNode_Status plus the
    Enum key answer in about a millisecond, and a node that is absent, phantom
    or still failed-install reports a problem code instead of a stale service.

    Returns ("OK"|"ERROR", service) or None when the node cannot be read.
    """
    from ctypes import wintypes
    lib = cfgmgr32()
    node = wintypes.ULONG()
    if lib.CM_Locate_DevNodeW(ctypes.byref(node), instance, 0):
        return None
    status = wintypes.ULONG()
    problem = wintypes.ULONG()
    if lib.CM_Get_DevNode_Status(ctypes.byref(status), ctypes.byref(problem),
                                 node.value, 0):
        return None
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                            "SYSTEM\\CurrentControlSet\\Enum\\" + instance) as key:
            service = str(winreg.QueryValueEx(key, "Service")[0]).upper()
    except OSError:
        service = ""
    healthy = problem.value == 0 and not status.value & DN_HAS_PROBLEM
    return ("OK" if healthy else "ERROR", service or None)


def poll_service(serial, timeout=30.0):
    """Bind state of this serial's 0E8A node, polled until it settles.

    Returns the upper-cased service name, or None when the node is absent or
    not in a healthy state. Every probe failure - including a node that is
    mid-rebuild - is treated as "not settled yet" rather than as an error.
    """
    instance = "USB\\VID_054C&PID_0E8A\\" + serial.upper()
    deadline = time.monotonic() + timeout
    found = None
    while True:
        binding = device_binding(instance)
        if binding is not None and binding[0] == "OK" and binding[1]:
            found = binding[1]
            if found == "USBSTOR":
                return found
        if time.monotonic() >= deadline:
            return found
        time.sleep(0.5)


def clear_driver_bindings(serial, instance):
    """Drop every Zadig package bound to 0E8A so USBSTOR can take the node.

    Zadig leaves one package per backend it was ever used with, so deleting
    only the currently bound one just hands the node to the next package.
    The bound package is removed last, and anything still locked is retried
    with /force. When the store is finally empty Windows re-enumerates the
    camera as mass storage on its own; if the node keeps a stale binding we
    delete the device node and rescan once.
    """
    packages = third_party_packages_0e8a()
    require(packages, "未找到这台相机的第三方驱动包；"
                      "请手工把 054C:0E8A 恢复为 USBSTOR 后重试")
    try:
        bound = str(property_value(instance,
                                   "DEVPKEY_Device_DriverInfPath")).lower()
    except (subprocess.TimeoutExpired, ValueError):
        bound = ""
    SCREEN.note_pair(("正在移除这台相机的 Zadig 驱动包（当前绑定 " +
                      (bound or "未知") + "）：" + ", ".join(packages),
                      "Removing Zadig packages for this camera (bound " +
                      (bound or "unknown") + "): " + ", ".join(packages)))
    ordered = [p for p in packages if p.lower() != bound]
    ordered += [p for p in packages if p.lower() == bound]
    for inf in ordered:
        pnputil("/delete-driver", inf, "/uninstall", timeout=45)
    for inf in third_party_packages_0e8a():
        pnputil("/delete-driver", inf, "/force", timeout=45)
    remaining = third_party_packages_0e8a()
    removed = [p for p in packages if p not in remaining]
    failed = remaining
    time.sleep(1)
    pnputil("/scan-devices", timeout=60)
    service = poll_service(serial, timeout=25)
    if service is not None and service != "USBSTOR":
        pnputil("/remove-device", instance, timeout=45)
        service = poll_service(serial, timeout=25)
    if service is None:
        confirm("REPLUG", "请拔下 USB 约 10 秒再插回，等待相机进入海量存储连接。")
        service = poll_service(serial, timeout=30)
    require(service == "USBSTOR",
            "普通模式未切回 USBSTOR；当前仍为 " + str(service) +
            "；已移除 " + (", ".join(removed) or "无") +
            "；未能移除 " + (", ".join(failed) or "无") +
            "；请在设备管理器卸载 054C:0E8A 后重试")
    return service


def ensure_storage(serial):
    current, service, instance = pnp()
    require(current == serial, "连接的相机已变化")
    if service != "USBSTOR":
        require(service in {"WINUSB", "LIBUSBK", "LIBUSB0"},
                "相机普通模式驱动不受支持：" + str(service))
        clear_driver_bindings(serial, instance)
    from windows_storage import volume_identity
    try:
        card, _ = volume_identity(serial)
    except (OSError, ValueError):
        confirm("CARD", "请拔下 USB 约 10 秒再插回，等待相机显示海量存储连接和照片卡卷出现。")
        card, _ = volume_identity(serial)
    SCREEN.note_pair(("照片卡已验证：" + card["drive"] + ":",
                      "Photo card verified: " + card["drive"] + ":"))


def saved(run_dir, name):
    return run_dir / name


def bk4_properties(snapshot_dir, serial):
    snapshot = json.loads((snapshot_dir / "windows-bk4-receipt.json").read_text(
        encoding="utf-8"))
    require(snapshot.get("serial") == serial and
            snapshot.get("normal_mode_and_driver_verified_after_child_exit") is True and
            set(snapshot.get("results", {})) == {"backup_bin", "backup_bak"},
            "BK4 readback after CP write is incomplete")
    entries = list(snapshot["results"].values())
    require(all(item.get("bk4_record_checksum_verified") is True and
                item.get("property_length") == 8192 and
                item.get("property_attr") == "0x8" for item in entries),
            "BK4 readback checksum or layout differs")
    return {item.get("property_sha256") for item in entries}


def resolve_bk4_after_ram(serial, snapshot_dir, receipt_path, manifest,
                          version_200, bk4_before, ram):
    properties = bk4_properties(snapshot_dir, serial)
    if properties == {BK4_TARGET_SHA}:
        mode = "persisted_by_cp"
    else:
        require(properties == {BK4_SOURCE_SHA},
                "BK4 properties are mixed or differ from the verified source/target")
        run("windows_bk4_commit_200.py", "--serial", serial,
            "--p1-manifest", manifest, "--version-report", version_200,
            "--before-dir", bk4_before, "--after-ram-report", ram, "--execute")
        require((manifest.parent / "windows_bk4_commit_200_after_ram_receipt.json").is_file(),
                "BK4 commit receipt is absent")
        mode = "committed"
    receipt_path.write_text(json.dumps({"serial": serial, "mode": mode,
                                        "snapshot": str(snapshot_dir)}, indent=2) + "\n",
                            encoding="utf-8")
    SCREEN.note("BK4: " + mode)


def read_target_bk4(serial, output_dir):
    run("windows_bk4_snapshot.py", "--serial", serial,
        "--out-dir", output_dir, "--execute")
    require(bk4_properties(output_dir, serial) == {BK4_TARGET_SHA},
            "BK4 target property did not persist after the write")


def step(state_path, state, key, fn, proof=None):
    if state.get(key) == "done":
        require(proof is None or proof.exists(), "已记录步骤缺少结果：" + key)
        return
    bk4_safe_retry = (key == "bk4_201" and proof is not None and
                      not proof.exists() and
                      not any(proof.parent.glob("a7c2-readonly-backup_*.bin")))
    # A step marked "started" without its receipt never produced a result: the
    # run died before the side effect was recorded, so retrying the step is
    # the same operation from scratch. Staging the package to the card is in
    # that class and used to require hand-editing workflow.json.
    unfinished_retry = (key == "card" and proof is not None and
                        not proof.exists())
    require(state.get(key) is None or key in ("build", "p1_capture") or
            bk4_safe_retry or unfinished_retry or
            (key in ("version_201", "version_cold") and
             proof is not None and not proof.exists()),
            "上次中断于 " + key + "；需检查记录后继续")
    SCREEN.progress(key, state)
    state[key] = "started"
    state_path.write_text(json.dumps(state, indent=2) + "\n", encoding="utf-8")
    fn()
    require(proof is None or proof.exists(), "步骤缺少验证文件：" + key)
    state[key] = "done"
    state_path.write_text(json.dumps(state, indent=2) + "\n", encoding="utf-8")
    SCREEN.progress(key, state)


def main(action="run", language="zh", screen=None):
    global SCREEN, LOG_DIR, RUN_COUNT
    SCREEN = screen if screen is not None else ui.Console(language)
    RUN_COUNT = 0
    require(sys.platform == "win32", "仅支持 Windows")
    require(ctypes.windll.shell32.IsUserAnAdmin(), "请以管理员身份运行 BAT")
    serial, service, _ = pnp()
    run_dir = RUNS / serial
    run_dir.mkdir(parents=True, exist_ok=True)
    LOG_DIR = run_dir / "logs"
    LOG_DIR.mkdir(exist_ok=True)
    state_path = saved(run_dir, "workflow.json")
    state = (json.loads(state_path.read_text(encoding="utf-8"))
             if state_path.exists() else {"format": 1, "serial": serial})
    require(state.get("format") == 1 and state.get("serial") == serial,
            "运行记录属于另一台相机")
    version_201 = saved(run_dir, "version201.json")
    version_200 = saved(run_dir, "version200.json")
    bk4_201 = saved(run_dir, "bk4_201")
    p1_dir = saved(run_dir, "p1_capture")
    gates = saved(run_dir, "p1_gate_200")
    manifest = gates / "p1_gate_200_windows_manifest.json"
    bk4_before = saved(run_dir, "bk4_200_before")
    cp_before = saved(run_dir, "cp_before.json")
    ram = saved(run_dir, "cp_ram_apply.json")
    bk4_after_ram = saved(run_dir, "bk4_after_ram")
    bk4_resolution = saved(run_dir, "bk4_resolution.json")
    bk4_after = saved(run_dir, "bk4_200_after")
    cp_cold = saved(run_dir, "cp_cold.json")
    bk4_cold = saved(run_dir, "bk4_200_cold")
    cold_receipt = saved(run_dir, "cold_verified.json")
    SCREEN.camera(serial)
    if "feature_plan" in state:
        SCREEN.selected_features(state["feature_plan"])
    if action == "restore-only":
        require(manifest.is_file() and state.get("p1_installed") == "done",
                "未找到已验证的 p1 安装记录")
        SCREEN.progress("p1_restored", state)
        ensure_winusb(run_dir, serial)
        run("windows_p1_200.py", "--serial", serial, "--manifest", manifest,
            "--action", "restore", "--execute")
        if version_200.is_file():
            state["p1_restored"] = "done"
        else:
            state["cancelled_and_p1_restored"] = True
        state_path.write_text(json.dumps(state, indent=2) + "\n", encoding="utf-8")
        return

    source = official_source()

    if state.get("complete"):
        receipt = (cold_receipt if state["feature_plan"]["fl23"] else
                   saved(run_dir, "version_200_cold.json"))
        SCREEN.note_pair(("本机身已完成冷启动验证：" + str(receipt),
                          "Cold-boot verification already complete: " + str(receipt)))
        return
    require(not state.get("cancelled_and_p1_restored"),
            "此前已取消更新并恢复 p1；这次记录不再继续安装")
    require(service in ("USBSTOR", "WINUSB", "LIBUSBK", "LIBUSB0"),
            "相机当前驱动不受支持：" + str(service))
    if "feature_plan" not in state:
        plan = SCREEN.features()
        feature_package.features(plan["fl23"], plan["audio_mode"])
        if plan["audio_mode"] == "custom":
            selected_audio = Path(plan["audio_path"]).expanduser().resolve()
            require(selected_audio.is_file() and not selected_audio.is_symlink() and
                    selected_audio.suffix.lower() in (".mp3", ".wav") and
                    0 < selected_audio.stat().st_size <= 50_000_000,
                    "select an MP3/WAV audio file no larger than 50 MB")
            feature_package.sound.encode_audio(
                selected_audio, feature_package.sound.spec_data()["audio"],
                plan["volume_percent"])
            plan["audio_path"] = str(selected_audio)
            plan["audio_sha256"] = digest(selected_audio)
        state["feature_plan"] = plan
        state_path.write_text(json.dumps(state, indent=2) + "\n", encoding="utf-8")
    plan = state["feature_plan"]
    feature_package.features(plan["fl23"], plan["audio_mode"])
    SCREEN.selected_features(plan)
    audio = Path(plan["audio_path"]) if plan["audio_mode"] == "custom" else None
    if audio is not None:
        require(audio.is_file() and not audio.is_symlink() and
                digest(audio) == plan.get("audio_sha256"),
                "selected custom audio changed")
    package_manifest = run_dir / feature_package.MANIFEST_NAME
    package_args = ("--package-manifest", package_manifest)
    build_args = ("--official", source, "--out-dir", run_dir,
                  "--audio-mode", plan["audio_mode"], "--volume",
                  plan["volume_percent"])
    if plan["fl23"]:
        build_args += ("--fl23",)
    if audio is not None:
        build_args += ("--audio", audio)
    step(state_path, state, "build",
         lambda: run("release/feature_package_200.py", *build_args),
         package_manifest)
    if state.get("p1_build") != "done":
        if state.get("version_201") != "done":
            prepare_service_driver()
        ensure_winusb(run_dir, serial)
    step(state_path, state, "version_201",
         lambda: read_version_201(run_dir, serial, version_201),
         version_201)
    step(state_path, state, "bk4_201",
         lambda: run("windows_bk4_snapshot.py", "--serial", serial,
                     "--out-dir", bk4_201, "--execute"),
         bk4_201 / "windows-bk4-receipt.json")
    step(state_path, state, "p1_capture",
         lambda: run("windows_p1_capture.py", "--serial", serial,
                     "--out-dir", p1_dir, "--execute"),
         p1_dir / "p1-capture-state.json")
    step(state_path, state, "p1_cleanup",
         lambda: run("windows_p1_cleanup.py", "--serial", serial,
                     "--out-dir", p1_dir, "--execute"),
         p1_dir / "p1-final-tmpfs-cleanup.json")
    step(state_path, state, "p1_build",
         lambda: run("windows_build_p1_200.py", "--serial", serial,
                                 "--capture-dir", p1_dir, "--bk4-dir", bk4_201,
                                 "--version-report", version_201,
                                 "--out-dir", gates), manifest)
    if state.get("card") != "done":
        ensure_storage(serial)
    step(state_path, state, "card",
         lambda: run("windows_stage_package_200.py", "--serial", serial,
                              "--version-report", version_201,
                              "--p1-manifest", manifest, "--official", source,
                              *package_args, "--execute",
                              "--confirm", "STAGE A7C2 " + serial),
         gates / "package_200_card_stage_receipt.json")
    if state.get("p1_installed") != "done":
        ensure_winusb(run_dir, serial)
    step(state_path, state, "p1_installed",
         lambda: run("windows_p1_200.py", "--serial", serial,
                                "--manifest", manifest, "--action", "install",
                                *package_args, "--execute"),
         gates / "windows_p1_200_install_state.json")
    step(state_path, state, "hold",
         lambda: run("windows_update_hold200.py", "--serial", serial,
                               "--p1-manifest", manifest, "--version-report",
                               version_201, *package_args, "--execute"),
         gates / "update_hold200_start_receipt.json")
    if state.get("updated") != "done":
        if version_200.is_file():
            verified = json.loads(version_200.read_text(encoding="utf-8"))
            require(verified.get("serial") == serial and
                    verified.get("dat4_hex") == "0002" and
                    verified.get("normal_mode_and_driver_verified_after_child_exit") is True,
                    "已有 2.00 版本回读记录不完整")
            state["updated"] = "done"
            state_path.write_text(json.dumps(state, indent=2) + "\n", encoding="utf-8")
    if state.get("updated") != "done":
        SCREEN.progress("updated", state)
        confirm("TARGET 2.00", "断开 USB，从机身菜单打开固件更新确认页。")
        hold_receipt = json.loads((gates / "update_hold200_start_receipt.json").read_text(
            encoding="utf-8"))
        hold_time = datetime.fromisoformat(hold_receipt["host_receipt_utc"]).timestamp()
        require(0 <= time.time() - hold_time < 540,
                "菜单版本窗口可能已过期；请勿按执行，需恢复 p1 后再处理")
        confirm("UPDATED 2.00", "相机更新完毕、重新连接并确认 MENU 显示 2.00。")
        run("windows_rollback_gate_ro.py", "--serial", serial, "--out",
            version_200, "--expected-dat4-hex", "0002", "--execute")
        state["updated"] = "done"
        state_path.write_text(json.dumps(state, indent=2) + "\n", encoding="utf-8")
    step(state_path, state, "p1_restored",
         lambda: run("windows_p1_200.py", "--serial", serial,
                                "--manifest", manifest, "--action", "restore",
                                "--execute"),
         gates / "windows_p1_200_restore_state.json")
    if not plan["fl23"]:
        if state.get("cold") != "done":
            SCREEN.progress("cold", state)
            confirm("COLD", "请断开 USB，关机并取出电池约 30 秒，装回开机并连接 USB。")
            require(pnp()[0] == serial, "冷启动后相机身份变化")
            state["cold"] = "done"
            state_path.write_text(json.dumps(state, indent=2) + "\n", encoding="utf-8")
        version_cold = saved(run_dir, "version_200_cold.json")
        ensure_winusb(run_dir, serial)
        step(state_path, state, "version_cold",
             lambda: run("windows_rollback_gate_ro.py", "--serial", serial,
                         "--out", version_cold, "--expected-dat4-hex", "0002",
                         "--execute"), version_cold)
        if state.get("sound_check") != "done":
            SCREEN.progress("sound_check", state)
            confirm("SOUND OK", "确认机身原声或上传音效在电子快门拍摄时播放。")
            state["sound_check"] = "done"
            state_path.write_text(json.dumps(state, indent=2) + "\n", encoding="utf-8")
        SCREEN.progress("storage", state)
        ensure_storage(serial)
        state["complete"] = True
        state_path.write_text(json.dumps(state, indent=2) + "\n", encoding="utf-8")
        SCREEN.finished(version_cold, sound=True, fl23=False)
        return
    step(state_path, state, "bk4_before",
         lambda: run("windows_bk4_snapshot.py", "--serial", serial,
                                   "--out-dir", bk4_before, "--execute"),
         bk4_before / "windows-bk4-receipt.json")
    step(state_path, state, "cp_before",
         lambda: run("windows_cp_color_ro_200.py", "--serial", serial,
                                "--version-report", version_200, "--out",
                                cp_before, "--execute"), cp_before)
    step(state_path, state, "cp_ram",
         lambda: run("windows_cp_color_ram_apply_200.py", "--serial",
                                 serial, "--version-report", version_200,
                                 "--before-cp-report", cp_before,
                                 "--bk4-dir", bk4_before, "--out", ram,
                                 "--execute"), ram)
    step(state_path, state, "bk4_after_ram",
         lambda: run("windows_bk4_snapshot.py", "--serial", serial,
                     "--out-dir", bk4_after_ram, "--execute"),
         bk4_after_ram / "windows-bk4-receipt.json")
    step(state_path, state, "bk4_commit",
         lambda: resolve_bk4_after_ram(serial, bk4_after_ram, bk4_resolution,
                                       manifest, version_200, bk4_before, ram),
         bk4_resolution)
    step(state_path, state, "bk4_after",
         lambda: read_target_bk4(serial, bk4_after),
         bk4_after / "windows-bk4-receipt.json")
    if state.get("cold") != "done":
        SCREEN.progress("cold", state)
        confirm("COLD", "请断开 USB、关机、取出电池约 30 秒，装回开机并连接 USB。")
        require(pnp()[0] == serial, "冷启动后相机身份变化")
        state["cold"] = "done"
        state_path.write_text(json.dumps(state, indent=2) + "\n", encoding="utf-8")
    step(state_path, state, "cp_cold",
         lambda: run("windows_cp_color_ro_200.py", "--serial", serial,
                     "--version-report", version_200, "--out", cp_cold,
                     "--execute"), cp_cold)
    step(state_path, state, "bk4_cold",
         lambda: run("windows_bk4_snapshot.py", "--serial", serial,
                     "--out-dir", bk4_cold, "--execute"),
         bk4_cold / "windows-bk4-receipt.json")
    if not cold_receipt.exists():
        run("windows_verify_cold200.py", "--serial", serial,
            "--cp-report", cp_cold, "--bk4-dir", bk4_cold,
            "--out", cold_receipt)
    if plan["audio_mode"] != "none" and state.get("sound_check") != "done":
        SCREEN.progress("sound_check", state)
        confirm("SOUND OK", "Check the electronic shutter sound on the camera and reconnect USB.")
        state["sound_check"] = "done"
        state_path.write_text(json.dumps(state, indent=2) + "\n", encoding="utf-8")
    elif plan["audio_mode"] == "none" and state.get("sound_check") != "done":
        state["sound_check"] = "done"
        state_path.write_text(json.dumps(state, indent=2) + "\n", encoding="utf-8")
    SCREEN.progress("storage", state)
    ensure_storage(serial)
    state["complete"] = True
    state_path.write_text(json.dumps(state, indent=2) + "\n", encoding="utf-8")
    SCREEN.finished(cold_receipt, plan["audio_mode"] != "none", fl23=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", nargs="?", choices=("run", "restore-only"),
                        default="run")
    parser.add_argument("--lang", choices=("zh", "en"), default="zh")
    args = parser.parse_args()
    try:
        main(args.action, args.lang)
    except (Stopped, OSError, ValueError, json.JSONDecodeError,
            subprocess.SubprocessError) as exc:
        print("Error / 错误: " + str(exc), file=sys.stderr)
        raise SystemExit(2 if isinstance(exc, Stopped) else 1)
