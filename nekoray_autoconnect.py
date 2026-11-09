#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
NekoRay Auto-Connect
====================

هر بار که این اسکریپت را اجرا می‌کنید:

  1) اگر NekoRay باز باشد آن را می‌بندد (تا فایل‌های کانفیگ قابل تغییر باشند)
  2) همه‌ی پروفایل‌های ذخیره‌شده را با هسته‌ی همراه خودِ NekoRay تست می‌کند
     (بدون نیاز به اینترنت سالم برای خود اسکریپت؛ تست‌ها از داخل خود پروکسی انجام می‌شوند)
  3) اولین پروفایلی که واقعاً اینترنت می‌دهد را انتخاب می‌کند
  4) NekoRay را طوری تنظیم می‌کند که در استارت‌آپ همان پروفایل را خودکار وصل کند
  5) NekoRay را اجرا می‌کند و با تست پورت SOCKS خودِ NekoRay صحت اتصال را تأیید می‌کند

نیازمندی: فقط Python 3.8+ (هیچ پکیج اضافه‌ای لازم نیست) و نسخه‌ی Windows همین NekoRay.

نمونه اجرا:
    python nekoray_autoconnect.py
    python nekoray_autoconnect.py --mode vpn
    python nekoray_autoconnect.py --dir "D:\\path\\to\\nekoray" --workers 20

نکته: حالت پیش‌فرض system_proxy است (بدون نیاز به Administrator).
برای حالت TUN/VPN از --mode vpn استفاده کنید (NekoRay ممکن است Administrator بخواهد).
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import shutil
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import time
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from pathlib import Path
from urllib.parse import urlsplit

# ----------------------------------------------------------------------------
# تنظیمات پیش‌فرض
# ----------------------------------------------------------------------------

DEFAULT_NEKORAY_DIR = r"D:\Downloads\nekoray-3.26-2023-12-09-windows64\nekoray"
NEKO_EXE = "nekoray.exe"
CORE_EXE = "nekobox_core.exe"          # sing-box 1.6.4 همراه NekoRay؛ برای تست پروفایل‌ها
CACHE_FILE = "nekoray_autoconnect.json"
DEFAULT_TEST_URL = "https://www.gstatic.com/generate_204"

CREATE_NO_WINDOW = 0x08000000 if os.name == "nt" else 0
DEVNULL = subprocess.DEVNULL

SUPPORTED_TYPES = {"vless", "vmess", "trojan", "shadowsocks"}
UNSUPPORTED_NETS = {"xhttp", "httpupgrade", "quic", "tcp@soskeynets"}

SS_METHODS = {
    "aes-128-gcm", "aes-192-gcm", "aes-256-gcm",
    "chacha20-ietf-poly1305", "chacha20-poly1305", "xchacha20-ietf-poly1305",
    "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm",
    "2022-blake3-chacha20-poly1305",
    "aes-128-cfb", "aes-192-cfb", "aes-256-cfb",
    "aes-128-ctr", "aes-192-ctr", "aes-256-ctr",
    "rc4-md5", "chacha20-ietf", "xchacha20",
}

UTLS_FINGERPRINTS = {
    "chrome", "firefox", "edge", "safari", "360", "qq", "ios", "android",
    "random", "randomized",
}

# ----------------------------------------------------------------------------
# ابزارهای عمومی
# ----------------------------------------------------------------------------

STOP = threading.Event()
_PROCS: set[subprocess.Popen] = set()
_PROCS_LOCK = threading.Lock()
_PORT_LOCK = threading.Lock()
_USED_PORTS: set[int] = set()

_SSL_CONTEXT: ssl.SSLContext | None = None
_SSL_LOCK = threading.Lock()


def log(msg: str) -> None:
    print(msg, flush=True)


def log_err(msg: str) -> None:
    print(msg, file=sys.stderr, flush=True)


def setup_console() -> None:
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass


def load_json(path: Path, default=None):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return default


def atomic_write_json(path: Path, data) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp-autoconnect")
    with open(tmp, "w", encoding="utf-8", newline="\n") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
        f.write("\n")
    os.replace(tmp, path)


def run_hidden(args, **kwargs) -> subprocess.CompletedProcess:
    if not any(k in kwargs for k in ("stdout", "stderr", "capture_output")):
        kwargs["stdout"] = DEVNULL
        kwargs["stderr"] = DEVNULL
    kwargs.setdefault("creationflags", CREATE_NO_WINDOW)
    return subprocess.run(args, **kwargs)


def image_running(name: str) -> bool:
    try:
        out = run_hidden(
            ["tasklist", "/FI", f"IMAGENAME eq {name}", "/NH"],
            capture_output=True, text=True, errors="ignore",
        ).stdout or ""
    except Exception:
        return False
    return name.lower() in out.lower()


def kill_image(name: str) -> None:
    run_hidden(["taskkill", "/F", "/T", "/IM", name])


def kill_neko_processes() -> None:
    """NekoRay و هسته‌های احتمالی باقی‌مانده را می‌بندد."""
    if os.name != "nt":
        return
    for exe in ("nekoray.exe", "nekoray_core.exe", "nekobox_core.exe"):
        if image_running(exe):
            kill_image(exe)
    time.sleep(0.7)


def register_proc(p: subprocess.Popen) -> None:
    with _PROCS_LOCK:
        _PROCS.add(p)


def unregister_proc(p: subprocess.Popen) -> None:
    with _PROCS_LOCK:
        _PROCS.discard(p)


def kill_all_test_procs() -> None:
    with _PROCS_LOCK:
        procs = list(_PROCS)
    for p in procs:
        try:
            p.kill()
        except Exception:
            pass
    for p in procs:
        try:
            p.wait(timeout=3)
        except Exception:
            pass


def free_port() -> int:
    """یک پورت آزاد محلی پیدا می‌کند (با کمی احتیاط برای همزمانی)."""
    for _ in range(200):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.bind(("127.0.0.1", 0))
            port = s.getsockname()[1]
        finally:
            s.close()
        with _PORT_LOCK:
            if port not in _USED_PORTS:
                _USED_PORTS.add(port)
                return port
    raise RuntimeError("could not find a free port")


def release_port(port: int) -> None:
    with _PORT_LOCK:
        _USED_PORTS.discard(port)


def get_ssl_context() -> ssl.SSLContext:
    global _SSL_CONTEXT
    with _SSL_LOCK:
        if _SSL_CONTEXT is None:
            ctx = ssl.create_default_context()
            ctx.check_hostname = True
            ctx.verify_mode = ssl.CERT_REQUIRED
            _SSL_CONTEXT = ctx
        return _SSL_CONTEXT


# ----------------------------------------------------------------------------
# Windows system proxy helpers
# ----------------------------------------------------------------------------

INET_KEY = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"


def get_system_proxy():
    if os.name != "nt":
        return None
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, INET_KEY) as k:
            def val(name):
                try:
                    return winreg.QueryValueEx(k, name)[0]
                except OSError:
                    return None
            return {
                "ProxyEnable": val("ProxyEnable"),
                "ProxyServer": val("ProxyServer"),
                "ProxyOverride": val("ProxyOverride"),
            }
    except Exception:
        return None


def set_system_proxy(enabled: bool, server=None, override=None) -> None:
    if os.name != "nt":
        return
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, INET_KEY, 0, winreg.KEY_SET_VALUE) as k:
            winreg.SetValueEx(k, "ProxyEnable", 0, winreg.REG_DWORD, 1 if enabled else 0)
            if server is not None:
                winreg.SetValueEx(k, "ProxyServer", 0, winreg.REG_SZ, str(server))
            if override is not None:
                winreg.SetValueEx(k, "ProxyOverride", 0, winreg.REG_SZ, str(override))
        # اطلاع‌دادن به WinINet تا تنظیمات سریع اعمال شوند
        try:
            import ctypes
            wininet = ctypes.windll.Wininet
            wininet.InternetSetOptionW(0, 39, 0, 0)  # INTERNET_OPTION_SETTINGS_CHANGED
            wininet.InternetSetOptionW(0, 37, 0, 0)  # INTERNET_OPTION_REFRESH
        except Exception:
            pass
    except Exception:
        pass


def disable_system_proxy() -> None:
    set_system_proxy(False)


# ----------------------------------------------------------------------------
# تبدیل Bean نیکوری به outbound استاندارد sing-box
# ----------------------------------------------------------------------------

def _valid_alpn(raw) -> list[str]:
    if not raw or not isinstance(raw, str):
        return []
    result = []
    for item in raw.split(","):
        item = item.strip().lower()
        if item in ("h2", "http/1.1") and item not in result:
            result.append(item)
    return result


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def bean_to_outbound(profile: dict):
    """خروجی: (outbound یا None، دلیل رد شدن)"""
    ptype = (profile.get("type") or "").lower()
    if ptype not in SUPPORTED_TYPES:
        return None, f"type {ptype or '?'} پشتیبانی نمی‌شود"

    bean = profile.get("bean") or {}
    stream = bean.get("stream") or {}

    addr = str(bean.get("addr") or "").strip()
    try:
        port = int(bean.get("port") or 0)
    except (TypeError, ValueError):
        port = 0
    if not addr or not (0 < port < 65536):
        return None, "آدرس/پورت نامعتبر"

    net = str(stream.get("net") or "tcp").strip().lower()
    if net in UNSUPPORTED_NETS:
        return None, f"ترنسپورت {net} توسط هسته‌ی همراه پشتیبانی نمی‌شود"
    if net in ("", "raw"):
        net = "tcp"

    sec = str(stream.get("sec") or "").strip().lower()
    pbk = str(stream.get("pbk") or "").strip()
    use_reality = (sec == "reality") or bool(pbk)
    use_tls = (sec == "tls") or use_reality

    out = {"type": ptype, "tag": "proxy", "server": addr, "server_port": port}

    # ---------- TLS / Reality ----------
    if use_tls:
        tls = {"enabled": True}
        sni = str(stream.get("sni") or stream.get("host") or "").strip()
        if not sni or sni == addr:
            sni = "" if _is_ip(addr) else addr
        if sni:
            tls["server_name"] = sni

        if bool(stream.get("insecure")):
            tls["insecure"] = True

        alpn = _valid_alpn(stream.get("alpn"))
        if alpn:
            tls["alpn"] = alpn

        fp = str(stream.get("utls") or "").strip().lower()
        fp = fp if fp in UTLS_FINGERPRINTS else ""
        if use_reality:
            tls["reality"] = {
                "enabled": True,
                "public_key": pbk,
                "short_id": str(stream.get("sid") or ""),
            }
            fp = fp or "chrome"          # Reality بدون uTLS کار نمی‌کند
        if fp:
            tls["utls"] = {"enabled": True, "fingerprint": fp}

        out["tls"] = tls

    # ---------- Transport ----------
    host = str(stream.get("host") or "").strip()
    path = str(stream.get("path") or "").strip()

    if net == "ws":
        tr = {"type": "ws", "path": path or "/"}
        if host:
            tr["headers"] = {"Host": host}
        out["transport"] = tr
    elif net == "grpc":
        out["transport"] = {"type": "grpc", "service_name": path}
    elif net == "http":
        tr = {"type": "http", "path": path or "/"}
        if host:
            tr["host"] = [host]
        out["transport"] = tr
    elif net not in ("tcp",):
        return None, f"ترنسپورت {net} پشتیبانی نمی‌شود"

    # ---------- پروتکل ----------
    if ptype == "vless":
        uuid = str(bean.get("pass") or "").strip()
        if not uuid:
            return None, "UUID خالی"
        out["uuid"] = uuid
        flow = str(bean.get("flow") or "").strip()
        if flow == "xtls-rprx-vision" and net == "tcp" and use_tls:
            out["flow"] = flow

    elif ptype == "vmess":
        uuid = str(bean.get("id") or bean.get("pass") or "").strip()
        if not uuid:
            return None, "UUID خالی"
        security = str(bean.get("sec") or "auto").strip().lower()
        if security not in ("auto", "none", "zero", "aes-128-gcm", "chacha20-poly1305"):
            security = "auto"
        out["uuid"] = uuid
        out["security"] = security
        try:
            out["alter_id"] = int(bean.get("aid") or 0)
        except (TypeError, ValueError):
            out["alter_id"] = 0

    elif ptype == "trojan":
        password = str(bean.get("pass") or "")
        if not password:
            return None, "رمز خالی"
        out["password"] = password

    elif ptype == "shadowsocks":
        method = str(bean.get("method") or "").strip().lower()
        password = str(bean.get("pass") or "")
        if method not in SS_METHODS:
            return None, f"متد {method or '?'} پشتیبانی نمی‌شود"
        if not password:
            return None, "رمز خالی"
        out["method"] = method
        out["password"] = password

    return out, ""


# ----------------------------------------------------------------------------
# SOCKS5 + HTTP probe
# ----------------------------------------------------------------------------

def _recv_exact(sock: socket.socket, n: int, deadline: float) -> bytes:
    buf = b""
    while len(buf) < n:
        remaining = deadline - time.time()
        if remaining <= 0:
            raise TimeoutError("deadline")
        sock.settimeout(remaining)
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("connection closed")
        buf += chunk
    return buf


def socks5_connect(proxy_host: str, proxy_port: int, host: str, port: int, deadline: float) -> socket.socket:
    remaining = deadline - time.time()
    if remaining <= 0:
        raise TimeoutError("deadline")
    sock = socket.create_connection((proxy_host, proxy_port), timeout=remaining)
    try:
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        sock.settimeout(max(0.2, deadline - time.time()))
        sock.sendall(b"\x05\x01\x00")
        if _recv_exact(sock, 2, deadline) != b"\x05\x00":
            raise ConnectionError("socks5 auth rejected")

        host_bytes = host.encode("idna")
        sock.sendall(b"\x05\x01\x00\x03" + bytes([len(host_bytes)]) + host_bytes + struct.pack("!H", port))
        head = _recv_exact(sock, 4, deadline)
        if head[0] != 5 or head[1] != 0:
            raise ConnectionError(f"socks5 connect failed (code {head[1]})")
        atyp = head[3]
        if atyp == 1:
            _recv_exact(sock, 4, deadline)
        elif atyp == 3:
            ln = _recv_exact(sock, 1, deadline)[0]
            _recv_exact(sock, ln, deadline)
        elif atyp == 4:
            _recv_exact(sock, 16, deadline)
        else:
            raise ConnectionError(f"socks5 bad atyp {atyp}")
        _recv_exact(sock, 2, deadline)
        return sock
    except Exception:
        sock.close()
        raise


def probe_socks(socks_port: int, test_url: str, timeout: float):
    """از طریق SOCKS محلی یک درخواست HTTP(S) می‌فرستد. خروجی: (موفق؟، پیام)"""
    u = urlsplit(test_url)
    host = u.hostname
    if not host:
        return False, "test URL نامعتبر"
    port = u.port or (443 if u.scheme == "https" else 80)
    path = u.path or "/"
    if u.query:
        path += "?" + u.query

    deadline = time.time() + timeout
    sock = None
    try:
        sock = socks5_connect("127.0.0.1", socks_port, host, port, deadline)
        if u.scheme == "https":
            sock.settimeout(max(0.3, deadline - time.time()))
            sock = get_ssl_context().wrap_socket(sock, server_hostname=host)

        request = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n"
            "Accept: */*\r\n"
            "Connection: close\r\n\r\n"
        )
        sock.sendall(request.encode("ascii", "ignore"))

        data = b""
        while b"\r\n\r\n" not in data and len(data) < 16384:
            remaining = deadline - time.time()
            if remaining <= 0:
                break
            sock.settimeout(remaining)
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk

        if not data.startswith(b"HTTP/"):
            return False, "پاسخ HTTP دریافت نشد"
        first_line = data.split(b"\r\n", 1)[0].decode("latin1")
        parts = first_line.split()
        code = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0
        if 200 <= code < 400:
            return True, f"HTTP {code}"
        return False, f"HTTP {code}"
    except ssl.SSLCertVerificationError as e:
        return False, f"خطای گواهی TLS: {e.verify_message or e}"
    except Exception as e:
        return False, f"{type(e).__name__}: {e}"
    finally:
        if sock is not None:
            try:
                sock.close()
            except Exception:
                pass


# ----------------------------------------------------------------------------
# تست یک پروفایل
# ----------------------------------------------------------------------------

def wait_for_port(port: int, proc: subprocess.Popen, timeout: float) -> bool:
    end = time.time() + timeout
    while time.time() < end:
        if proc.poll() is not None:
            return False
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.settimeout(0.15)
            if s.connect_ex(("127.0.0.1", port)) == 0:
                return True
        finally:
            s.close()
        time.sleep(0.05)
    return False


def test_profile(pid: int, outbound: dict, *, core_path: Path, workdir: Path,
                 tmpdir: Path, test_url: str, timeout: float):
    """خروجی: (id, موفق؟، توضیح، تأخیر میلی‌ثانیه)"""
    if STOP.is_set():
        return pid, False, "cancelled", None

    port = free_port()
    cfg_path = tmpdir / f"p{pid}_{os.getpid()}_{threading.get_ident()}.json"
    proc = None
    started = time.time()
    try:
        config = {
            "log": {"level": "error"},
            "inbounds": [{
                "type": "socks", "tag": "socks-in",
                "listen": "127.0.0.1", "listen_port": port,
            }],
            "outbounds": [outbound],
            "route": {"final": "proxy"},
        }
        with open(cfg_path, "w", encoding="utf-8") as f:
            json.dump(config, f, ensure_ascii=False)

        proc = subprocess.Popen(
            [str(core_path), "run", "-c", str(cfg_path)],
            cwd=str(workdir), stdout=DEVNULL, stderr=DEVNULL,
            creationflags=CREATE_NO_WINDOW,
        )
        register_proc(proc)

        if not wait_for_port(port, proc, timeout=min(3.5, timeout)):
            return pid, False, "هسته بالا نیامد (کانفیگ نامعتبر؟)", None
        if STOP.is_set():
            return pid, False, "cancelled", None

        ok, message = probe_socks(port, test_url, timeout)
        latency = int((time.time() - started) * 1000)
        return pid, ok, message, (latency if ok else None)
    except Exception as e:
        return pid, False, f"{type(e).__name__}: {e}", None
    finally:
        release_port(port)
        if proc is not None:
            try:
                proc.kill()
            except Exception:
                pass
            try:
                proc.wait(timeout=3)
            except Exception:
                pass
            unregister_proc(proc)
        try:
            cfg_path.unlink()
        except Exception:
            pass


# ----------------------------------------------------------------------------
# خواندن پروفایل‌ها و ترتیب تست
# ----------------------------------------------------------------------------

def load_profiles(config_dir: Path) -> dict[int, dict]:
    profiles: dict[int, dict] = {}
    pdir = config_dir / "profiles"
    if not pdir.is_dir():
        return profiles
    for fn in pdir.glob("*.json"):
        data = load_json(fn)
        if not isinstance(data, dict):
            continue
        try:
            pid = int(data.get("id"))
        except (TypeError, ValueError):
            try:
                pid = int(fn.stem)
            except ValueError:
                continue
        profiles[pid] = data
    return profiles


def build_order(profiles: dict[int, dict], config_dir: Path, first_ids: list[int]) -> list[int]:
    order: list[int] = []
    seen: set[int] = set()

    def add(pid):
        if pid in profiles and pid not in seen:
            seen.add(pid)
            order.append(pid)

    for pid in first_ids:
        add(pid)

    pm = load_json(config_dir / "groups" / "pm.json", {}) or {}
    gids = pm.get("groups") or []

    for gid in gids:
        try:
            gid = int(gid)
        except (TypeError, ValueError):
            continue
        gdata = load_json(config_dir / "groups" / f"{gid}.json", {}) or {}
        for pid in gdata.get("order") or []:
            try:
                pid = int(pid)
            except (TypeError, ValueError):
                continue
            if profiles.get(pid, {}).get("gid") == gid:
                add(pid)
        for pid in sorted(profiles):
            if profiles[pid].get("gid") == gid:
                add(pid)

    for pid in sorted(profiles):
        add(pid)
    return order


# ----------------------------------------------------------------------------
# جستجوی پروفایل سالم
# ----------------------------------------------------------------------------

def search_working(order, outbounds, *, args, core_path, workdir, tmpdir):
    candidates = [
        pid for pid in order
        if outbounds.get(pid) and pid not in args._skip
    ]
    if args.max and args.max > 0:
        candidates = candidates[:args.max]

    total = len(candidates)
    if not total:
        return None

    log(f"[*] شروع تست {total} پروفایل با {args.workers} هسته‌ی موازی ...")

    futures = {}
    tested = 0
    failed = 0
    best = None
    ex = ThreadPoolExecutor(max_workers=args.workers)
    it = iter(candidates)

    def submit_next():
        while len(futures) < args.workers:
            try:
                pid = next(it)
            except StopIteration:
                return
            fut = ex.submit(
                test_profile, pid, outbounds[pid],
                core_path=core_path, workdir=workdir, tmpdir=tmpdir,
                test_url=args.test_url, timeout=args.timeout,
            )
            futures[fut] = pid

    try:
        submit_next()
        while futures:
            done, _ = wait(list(futures.keys()), return_when=FIRST_COMPLETED)
            for fut in done:
                pid = futures.pop(fut)
                tested += 1
                try:
                    rpid, ok, message, latency = fut.result()
                except Exception as e:
                    rpid, ok, message, latency = pid, False, repr(e), None

                if ok:
                    name = ((outbounds[pid] or {}).get("server") or "")
                    if args.verbose:
                        log(f"[+] OK  #{pid} {name}  {latency}ms")
                    if best is None or (latency is not None and best[3] is not None and latency < best[3]):
                        best = (pid, True, message, latency)
                else:
                    failed += 1
                    args._skip.add(pid)
                    if args.verbose:
                        log(f"[-] #{pid}: {message}")

                if tested % 25 == 0 or tested == total:
                    log(f"    ... {tested}/{total} تست شد | {failed} ناموفق")

            if best is not None:
                STOP.set()
                kill_all_test_procs()
                for fut in futures:
                    fut.cancel()
                break
            submit_next()
    finally:
        STOP.set()
        kill_all_test_procs()
        ex.shutdown(wait=True, cancel_futures=True)
        STOP.clear()

    return best


# ----------------------------------------------------------------------------
# تنظیم NekoRay
# ----------------------------------------------------------------------------

def nekoray_datastore_path(config_dir: Path) -> Path:
    return config_dir / "groups" / "nekoray.json"


def update_neko_datastore(config_dir: Path, profile: dict, profile_id: int, mode: str) -> None:
    fn = nekoray_datastore_path(config_dir)
    data = load_json(fn, {}) or {}

    if fn.exists():
        backup = fn.with_name(fn.name + ".bak-autoconnect")
        if not backup.exists():
            try:
                shutil.copy2(fn, backup)
            except Exception:
                pass

    gid = profile.get("gid")
    try:
        gid = int(gid)
    except (TypeError, ValueError):
        gid = data.get("current_group", 0)

    data["current_group"] = gid
    data["remember_enable"] = True
    data["remember_id"] = int(profile_id)
    # کلید واقعیِ ذخیره‌سازیِ «حالت اتصال» در NekoRay 3.26 نامش spmode2 است
    if mode == "vpn":
        data["spmode2"] = ["vpn"]
    elif mode == "none":
        data["spmode2"] = []
    else:
        data["spmode2"] = ["system_proxy"]
    # سازگاری با نسخه‌های دیگر
    data.pop("remember_spmode", None)

    atomic_write_json(fn, data)


def launch_neko(neko_dir: Path) -> subprocess.Popen:
    return subprocess.Popen(
        [str(neko_dir / NEKO_EXE)],
        cwd=str(neko_dir),
        close_fds=True,
    )


def verify_neko_connection(config_dir: Path, test_url: str, timeout: float = 35.0) -> tuple[bool, str]:
    data = load_json(nekoray_datastore_path(config_dir), {}) or {}
    try:
        port = int(data.get("inbound_socks_port", 2080))
    except (TypeError, ValueError):
        port = 2080

    deadline = time.time() + timeout
    last = "هنوز آماده نشده"
    while time.time() < deadline:
        if not image_running("nekoray.exe"):
            return False, "پروسه‌ی NekoRay بسته شد"
        ok, message = probe_socks(port, test_url, timeout=min(6.0, max(2.0, deadline - time.time())))
        if ok:
            return True, message
        last = message
        time.sleep(0.8)
    return False, last


# ----------------------------------------------------------------------------
# main
# ----------------------------------------------------------------------------

def main() -> int:
    setup_console()

    parser = argparse.ArgumentParser(
        description="اتصال خودکار NekoRay به یک کانفیگ سالم",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "مثال‌ها:\n"
            "  python nekoray_autoconnect.py\n"
            "  python nekoray_autoconnect.py --mode vpn\n"
            "  python nekoray_autoconnect.py --workers 20 --timeout 6\n"
        ),
    )
    parser.add_argument("--dir", default=os.environ.get("NEKORAY_DIR", DEFAULT_NEKORAY_DIR),
                        help="پوشه‌ی نصب NekoRay")
    parser.add_argument("--mode", choices=("system_proxy", "vpn", "none"), default="system_proxy",
                        help="حالت اتصال NekoRay (پیش‌فرض: system_proxy)")
    parser.add_argument("--workers", type=int, default=16,
                        help="تعداد تست همزمان (پیش‌فرض: 16)")
    parser.add_argument("--timeout", type=float, default=7.0,
                        help="مهلت هر تست به ثانیه (پیش‌فرض: 7)")
    parser.add_argument("--test-url", default=DEFAULT_TEST_URL,
                        help="آدرس تست اینترنت (پیش‌فرض: gstatic generate_204)")
    parser.add_argument("--max", type=int, default=0,
                        help="حداکثر تعداد پروفایل برای تست در هر دور (0 = همه)")
    parser.add_argument("--no-launch", action="store_true",
                        help="فقط پروفایل سالم را پیدا و ذخیره کن، NekoRay را اجرا نکن")
    parser.add_argument("--retest", action="store_true",
                        help="کش آخرین پروفایل سالم را نادیده بگیر")
    parser.add_argument("--verbose", action="store_true", help="نمایش جزئیات هر تست")
    args = parser.parse_args()

    args.workers = max(1, args.workers)
    args.timeout = max(2.0, args.timeout)
    args._skip: set[int] = set()

    if os.name != "nt":
        log_err("[!] این اسکریپت برای Windows نوشته شده است.")
        return 2

    neko_dir = Path(args.dir).expanduser().resolve()
    config_dir = neko_dir / "config"
    neko_exe = neko_dir / NEKO_EXE
    core_exe = neko_dir / CORE_EXE

    if not neko_exe.exists():
        log_err(f"[!] NekoRay پیدا نشد: {neko_exe}")
        log_err("    مسیر را با --dir مشخص کنید.")
        return 2
    if not core_exe.exists():
        log_err(f"[!] هسته‌ی همراه NekoRay پیدا نشد: {core_exe}")
        return 2
    if not (config_dir / "profiles").is_dir():
        log_err(f"[!] پوشه‌ی پروفایل‌ها پیدا نشد: {config_dir / 'profiles'}")
        log_err("    یک بار NekoRay را باز کنید تا فایل‌هایش ساخته شوند.")
        return 2

    log(f"[*] NekoRay: {neko_dir}")

    # ---- بستن NekoRay در حال اجرا ----
    was_running = image_running("nekoray.exe")
    if was_running:
        log("[*] بستن نسخه‌ی در حال اجرای NekoRay ...")
    kill_neko_processes()

    previous_proxy = get_system_proxy()
    proxy_disabled = False
    launched = False
    exit_code = 0
    launch_proc = None

    try:
        if previous_proxy and previous_proxy.get("ProxyEnable") == 1:
            log("[*] غیرفعال‌کردن موقت پروکسی سیستم تا تست‌ها تمیز انجام شوند ...")
            disable_system_proxy()
            proxy_disabled = True

        # ---- پروفایل‌ها ----
        profiles = load_profiles(config_dir)
        if not profiles:
            log_err("[!] هیچ پروفایلی پیدا نشد.")
            return 3

        cache = load_json(config_dir / CACHE_FILE, {}) or {}
        datastore = load_json(nekoray_datastore_path(config_dir), {}) or {}
        first_ids: list[int] = []
        if not args.retest:
            for candidate in (cache.get("last_working_id"), datastore.get("remember_id")):
                try:
                    candidate = int(candidate)
                except (TypeError, ValueError):
                    continue
                if candidate >= 0:
                    first_ids.append(candidate)

        order = build_order(profiles, config_dir, first_ids)

        outbounds: dict[int, dict] = {}
        skipped = 0
        for pid in order:
            out, _reason = bean_to_outbound(profiles[pid])
            if out is None:
                skipped += 1
                continue
            outbounds[pid] = out

        # حذف تکراری‌ها (نکته‌ی مهم برای سرعت)
        seen_keys: set[str] = set()
        deduped_order = []
        for pid in order:
            out = outbounds.get(pid)
            if out is None:
                continue
            key = json.dumps(out, sort_keys=True, ensure_ascii=False)
            if key in seen_keys:
                continue
            seen_keys.add(key)
            deduped_order.append(pid)
        order = deduped_order
        outbounds = {pid: outbounds[pid] for pid in order}

        log(f"[*] {len(profiles)} پروفایل پیدا شد | {len(order)} قابل تست | {skipped} رد شد (نوع/ترنسپورت)")

        tmpdir = Path(tempfile.mkdtemp(prefix="neko_autoconnect_"))
        try:
            working = None
            pending = []

            # 1) بررسی سریع آخرین کانفیگ سالم تا اجراهای بعدی چندثانیه‌ای باشند
            if not args.retest and first_ids:
                quick_candidates = [pid for pid in dict.fromkeys(first_ids) if pid in outbounds]
                if quick_candidates:
                    log("")
                    log(f"[*] بررسی سریع آخرین پروفایل سالم (#{quick_candidates[0]}) ...")
                    for pid in quick_candidates[:2]:
                        r = test_profile(
                            pid, outbounds[pid],
                            core_path=core_exe, workdir=neko_dir, tmpdir=tmpdir,
                            test_url=args.test_url, timeout=args.timeout,
                        )
                        if r[1]:
                            pending.append(r)
                            break
                        args._skip.add(pid)

            # 2) در صورت نیاز، جستجوی کامل
            attempt = 0
            while working is None:
                if pending:
                    result = pending.pop(0)
                else:
                    attempt += 1
                    if attempt > 3:
                        break
                    log("")
                    if attempt > 1:
                        log(f"[*] تلاش {attempt}: گزینه‌ی سالم بعدی ...")
                    result = search_working(
                        order, outbounds,
                        args=args, core_path=core_exe, workdir=neko_dir, tmpdir=tmpdir,
                    )
                    if not result:
                        break

                pid, _ok, message, latency = result
                profile = profiles[pid]
                out = outbounds[pid]
                name = str((profile.get("bean") or {}).get("name") or "")
                log("")
                log(f"[+] پروفایل سالم: #{pid}  {name}")
                log(f"    {out['type']}  {out['server']}:{out['server_port']}  ({message}، {latency}ms)")

                update_neko_datastore(config_dir, profile, pid, args.mode)
                atomic_write_json(config_dir / CACHE_FILE, {
                    "last_working_id": pid,
                    "last_working_name": name,
                    "last_checked": int(time.time()),
                })

                if args.no_launch:
                    working = (pid, profile)
                    break

                log("[*] اجرای NekoRay ...")
                launch_proc = launch_neko(neko_dir)
                launched = True
                time.sleep(2.5)
                if launch_proc.poll() is not None:
                    log_err("[!] NekoRay بلافاصله بسته شد (شاید نسخه‌ی دیگری در حال اجراست).")
                    launched = False
                    args._skip.add(pid)
                else:
                    log("[*] منتظر برقراری اتصال در NekoRay ...")
                    ok, detail = verify_neko_connection(config_dir, args.test_url)
                    if ok:
                        working = (pid, profile)
                        log(f"[+] NekoRay متصل شد ({detail}).")
                        break
                    log_err(f"[!] NekoRay وصل نشد ({detail}).")
                    kill_neko_processes()
                    launched = False
                    args._skip.add(pid)

            if working is None:
                log_err("")
                log_err("[!] هیچ کانفیگ سالمی پیدا نشد.")
                log_err("    (اینترنت/فیلترینگ یا سابسکریپشن‌ها به‌روز نیستند؛ با --retest دوباره امتحان کنید)")
                exit_code = 4
            elif args.no_launch:
                log("")
                log(f"[*] پروفایل #{working[0]} در NekoRay ذخیره شد؛ اجرای NekoRay با --no-launch انجام نشد.")
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

    except KeyboardInterrupt:
        log_err("\n[!] لغو شد.")
        exit_code = 130
    finally:
        STOP.set()
        kill_all_test_procs()
        if not launched and proxy_disabled and previous_proxy:
            set_system_proxy(
                bool(previous_proxy.get("ProxyEnable")),
                previous_proxy.get("ProxyServer"),
                previous_proxy.get("ProxyOverride"),
            )

    if exit_code == 0 and launched:
        log("")
        log("[+] تمام شد. NekoRay باز است و به کانفیگ سالم وصل شده.")
        log("    (دفعه‌ی بعد هم خود NekoRay به همین کانفیگ وصل می‌شود)")
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
