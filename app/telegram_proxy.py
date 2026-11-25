"""Telegram Proxy Engine (MTProto Fake-TLS via mtg + built-in async SOCKS5) & bore.pub TCP Tunnel Manager."""
from __future__ import annotations

import asyncio
from datetime import datetime
import ipaddress
import logging
import os
import re
import secrets
import shutil
import socket
import struct
from typing import Any, Optional
from urllib.parse import quote

from app.state import CONFIG, TELEGRAM_CONFIG, TELEGRAM_LOCK, TELEGRAM_USERS, log_activity, save_state

logger = logging.getLogger("MX-UI.Telegram")

_BORE_LISTEN_RE = re.compile(r"listening at\s+([A-Za-z0-9.\-]+):(\d+)", re.IGNORECASE)

# Live runtime state per user ID (not persisted to JSON)
_RUNTIME: dict[str, dict[str, Any]] = {}


def _find_bin(name: str) -> Optional[str]:
    found = shutil.which(name)
    if found:
        return found
    for candidate in (f"/usr/local/bin/{name}", f"/usr/bin/{name}", f"./bin/{name}"):
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    return None


def generate_mtproto_secret(fake_tls_domain: str = "www.cloudflare.com") -> str:
    """Generate a valid Telegram MTProto v2 Fake-TLS (ee) secret."""
    domain = (fake_tls_domain or "www.cloudflare.com").strip().lower()
    domain = re.sub(r"^https?://", "", domain).split("/")[0].strip() or "www.cloudflare.com"
    key_hex = secrets.token_hex(16)
    dom_hex = domain.encode("utf-8").hex()
    return f"ee{key_hex}{dom_hex}"


def next_available_port(start: int = 32100) -> int:
    used = {int(u.get("local_port", 0)) for u in TELEGRAM_USERS.values()}
    port = start
    while port in used and port < 65000:
        port += 1
    return port


# ---------------------------------------------------------------------------
# Lightweight Pure-Python Async SOCKS5 Server (RFC 1928 + RFC 1929 User/Pass)
# ---------------------------------------------------------------------------
async def _pipe_streams(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    try:
        while True:
            data = await reader.read(16384)
            if not data:
                break
            writer.write(data)
            await writer.drain()
    except Exception:
        pass
    finally:
        try:
            writer.close()
        except Exception:
            pass


async def _handle_socks5_client(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    username: str,
    password: str,
) -> None:
    remote_writer: Optional[asyncio.StreamWriter] = None
    try:
        header = await asyncio.wait_for(reader.readexactly(2), timeout=15)
        ver, nmethods = header[0], header[1]
        if ver != 5:
            return
        methods = await asyncio.wait_for(reader.readexactly(nmethods), timeout=15)

        require_auth = bool(username or password)
        if require_auth:
            if 2 not in methods:
                writer.write(b"\x05\xff")
                await writer.drain()
                return
            writer.write(b"\x05\x02")
            await writer.drain()

            auth_ver = (await asyncio.wait_for(reader.readexactly(1), timeout=15))[0]
            if auth_ver != 1:
                return
            ulen = (await asyncio.wait_for(reader.readexactly(1), timeout=15))[0]
            u_in = (await asyncio.wait_for(reader.readexactly(ulen), timeout=15)).decode("utf-8", errors="replace")
            plen = (await asyncio.wait_for(reader.readexactly(1), timeout=15))[0]
            p_in = (await asyncio.wait_for(reader.readexactly(plen), timeout=15)).decode("utf-8", errors="replace")

            if not (secrets.compare_digest(u_in, username) and secrets.compare_digest(p_in, password)):
                writer.write(b"\x01\x01")
                await writer.drain()
                return
            writer.write(b"\x01\x00")
            await writer.drain()
        else:
            if 0 not in methods:
                writer.write(b"\x05\xff")
                await writer.drain()
                return
            writer.write(b"\x05\x00")
            await writer.drain()

        req = await asyncio.wait_for(reader.readexactly(4), timeout=15)
        ver, cmd, _, atyp = req[0], req[1], req[2], req[3]
        if ver != 5 or cmd != 1:  # Only CONNECT supported
            writer.write(b"\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00")
            await writer.drain()
            return

        if atyp == 1:  # IPv4
            raw_addr = await asyncio.wait_for(reader.readexactly(4), timeout=15)
            dst_host = socket.inet_ntoa(raw_addr)
        elif atyp == 3:  # Domain
            dlen = (await asyncio.wait_for(reader.readexactly(1), timeout=15))[0]
            dst_host = (await asyncio.wait_for(reader.readexactly(dlen), timeout=15)).decode("utf-8", errors="replace")
        elif atyp == 4:  # IPv6
            raw_addr = await asyncio.wait_for(reader.readexactly(16), timeout=15)
            dst_host = str(ipaddress.IPv6Address(raw_addr))
        else:
            writer.write(b"\x05\x08\x00\x01\x00\x00\x00\x00\x00\x00")
            await writer.drain()
            return

        dst_port = struct.unpack("!H", await asyncio.wait_for(reader.readexactly(2), timeout=15))[0]

        try:
            remote_reader, remote_writer = await asyncio.wait_for(
                asyncio.open_connection(dst_host, dst_port), timeout=15
            )
        except Exception:
            writer.write(b"\x05\x05\x00\x01\x00\x00\x00\x00\x00\x00")
            await writer.drain()
            return

        writer.write(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
        await writer.drain()

        t1 = asyncio.create_task(_pipe_streams(reader, remote_writer))
        t2 = asyncio.create_task(_pipe_streams(remote_reader, writer))
        await asyncio.wait([t1, t2], return_when=asyncio.FIRST_COMPLETED)
        t1.cancel()
        t2.cancel()
    except Exception:
        pass
    finally:
        for w in (writer, remote_writer):
            if w is not None:
                try:
                    w.close()
                except Exception:
                    pass


# ---------------------------------------------------------------------------
# Subprocess & Bore Tunnel Lifecycle
# ---------------------------------------------------------------------------
async def _watch_bore_output(uid: str, proc: asyncio.subprocess.Process) -> None:
    """Read bore stdout/stderr continuously and capture the assigned public host:port."""
    try:
        assert proc.stdout is not None
        while True:
            line = await proc.stdout.readline()
            if not line:
                break
            text = line.decode("utf-8", errors="replace").strip()
            if not text:
                continue
            rt = _RUNTIME.get(uid)
            if rt is not None:
                rt["bore_last_line"] = text
                m = _BORE_LISTEN_RE.search(text)
                if m:
                    rt["public_host"] = m.group(1)
                    rt["public_port"] = int(m.group(2))
                    rt["tunnel_running"] = True
                    logger.info("[bore] User %s exposed at %s:%s", uid, m.group(1), m.group(2))
    except asyncio.CancelledError:
        pass
    except Exception as exc:
        logger.debug("[bore] reader ended for %s: %s", uid, exc)
    finally:
        rt = _RUNTIME.get(uid)
        if rt is not None and rt.get("bore_proc") is proc:
            rt["tunnel_running"] = False


async def start_user_proxy(uid: str) -> dict[str, Any]:
    """Start proxy engine (mtg or SOCKS5) and bore.pub tunnel for a Telegram user."""
    await stop_user_proxy(uid)

    async with TELEGRAM_LOCK:
        user = TELEGRAM_USERS.get(uid)
        if not user or not user.get("active", True):
            return {"running": False, "tunnel_running": False}
        mode = user.get("mode", "mtproto")
        local_port = int(user.get("local_port", 32100))
        secret = str(user.get("secret", ""))
        username = str(user.get("username", ""))
        password = str(user.get("password", ""))
        tunnel_mode = TELEGRAM_CONFIG.get("tunnel_mode", "bore")
        bore_server = TELEGRAM_CONFIG.get("bore_server", "bore.pub").strip() or "bore.pub"
        bore_secret = TELEGRAM_CONFIG.get("bore_secret", "").strip()
        direct_host = TELEGRAM_CONFIG.get("direct_host", "").strip() or CONFIG.get("host", "localhost")

    rt: dict[str, Any] = {
        "running": False,
        "tunnel_running": False,
        "engine": mode,
        "local_port": local_port,
        "public_host": direct_host if tunnel_mode == "direct" else bore_server,
        "public_port": local_port if tunnel_mode == "direct" else 0,
        "error": "",
        "bore_last_line": "",
        "started_at": datetime.now().isoformat(),
    }
    _RUNTIME[uid] = rt

    # 1. Start local proxy listener
    bind_host = "127.0.0.1" if tunnel_mode == "bore" else "0.0.0.0"
    if mode == "mtproto":
        mtg_bin = _find_bin("mtg")
        if mtg_bin:
            try:
                proc = await asyncio.create_subprocess_exec(
                    mtg_bin,
                    "simple-run",
                    f"{bind_host}:{local_port}",
                    secret,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.STDOUT,
                )
                rt["proxy_proc"] = proc
                rt["running"] = True
                rt["engine"] = "mtg-v2"
            except Exception as exc:
                rt["error"] = f"mtg start failed: {exc}"
                logger.warning("[telegram] mtg failed for %s: %s", uid, exc)
        else:
            rt["error"] = "mtg binary not installed (run inside Docker or install mtg v2)"
    else:
        try:
            server = await asyncio.start_server(
                lambda r, w: _handle_socks5_client(r, w, username, password),
                bind_host,
                local_port,
            )
            rt["socks_server"] = server
            rt["running"] = True
            rt["engine"] = "socks5-async"
        except Exception as exc:
            rt["error"] = f"SOCKS5 bind failed on port {local_port}: {exc}"
            logger.warning("[telegram] SOCKS5 failed for %s: %s", uid, exc)

    # 2. Start bore.pub TCP tunnel when tunnel_mode == "bore" and proxy is running
    if rt["running"] and tunnel_mode == "bore":
        bore_bin = _find_bin("bore")
        if bore_bin:
            try:
                cmd = [bore_bin, "local", str(local_port), "--to", bore_server]
                if bore_secret:
                    cmd.extend(["--secret", bore_secret])
                bproc = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.STDOUT,
                )
                rt["bore_proc"] = bproc
                rt["bore_task"] = asyncio.create_task(_watch_bore_output(uid, bproc))
                # Wait briefly (up to 2.5s) for bore to print its assigned port
                for _ in range(25):
                    if rt.get("public_port"):
                        break
                    await asyncio.sleep(0.1)
            except Exception as exc:
                rt["error"] = f"bore tunnel failed: {exc}"
                logger.warning("[bore] failed for %s: %s", uid, exc)
        else:
            rt["error"] = "bore binary not installed (build via Dockerfile or install bore)"
    elif rt["running"] and tunnel_mode == "direct":
        rt["tunnel_running"] = True
        rt["public_host"] = direct_host
        rt["public_port"] = local_port

    return rt


async def stop_user_proxy(uid: str) -> None:
    rt = _RUNTIME.pop(uid, None)
    if not rt:
        return

    task = rt.get("bore_task")
    if task:
        task.cancel()

    for key in ("bore_proc", "proxy_proc"):
        proc = rt.get(key)
        if proc is not None:
            try:
                proc.terminate()
                await asyncio.wait_for(proc.wait(), timeout=2.0)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass

    srv = rt.get("socks_server")
    if srv is not None:
        try:
            srv.close()
            await srv.wait_closed()
        except Exception:
            pass


async def start_all_telegram_proxies() -> None:
    async with TELEGRAM_LOCK:
        active_ids = [uid for uid, u in TELEGRAM_USERS.items() if u.get("active", True)]
    for uid in active_ids:
        await start_user_proxy(uid)
    if active_ids:
        log_activity("telegram", f"Started {len(active_ids)} Telegram proxy user(s)", "ok")


async def stop_all_telegram_proxies() -> None:
    for uid in list(_RUNTIME.keys()):
        await stop_user_proxy(uid)


def build_telegram_links(user: dict[str, Any], rt: Optional[dict[str, Any]] = None) -> dict[str, str]:
    rt = rt or _RUNTIME.get(user["id"], {})
    tunnel_mode = TELEGRAM_CONFIG.get("tunnel_mode", "bore")
    host = rt.get("public_host") or (
        TELEGRAM_CONFIG.get("direct_host") or CONFIG.get("host", "localhost")
        if tunnel_mode == "direct"
        else TELEGRAM_CONFIG.get("bore_server", "bore.pub")
    )
    port = int(rt.get("public_port") or (user.get("local_port", 32100) if tunnel_mode == "direct" else 0))

    mode = user.get("mode", "mtproto")
    if mode == "mtproto":
        sec = quote(str(user.get("secret", "")), safe="")
        qs = f"server={quote(str(host), safe='')}&port={port}&secret={sec}"
        return {
            "tg_link": f"tg://proxy?{qs}",
            "tme_link": f"https://t.me/proxy?{qs}",
            "endpoint": f"{host}:{port}" if port else f"{host} (connecting...)",
        }

    u_q = quote(str(user.get("username", "")), safe="")
    p_q = quote(str(user.get("password", "")), safe="")
    qs = f"server={quote(str(host), safe='')}&port={port}&user={u_q}&pass={p_q}"
    return {
        "tg_link": f"tg://socks?{qs}",
        "tme_link": f"https://t.me/socks?{qs}",
        "endpoint": f"{host}:{port}" if port else f"{host} (connecting...)",
    }


def serialize_telegram_user(user: dict[str, Any]) -> dict[str, Any]:
    uid = user["id"]
    rt = _RUNTIME.get(uid, {})
    links = build_telegram_links(user, rt)
    return {
        **user,
        "running": bool(rt.get("running", False)),
        "tunnel_running": bool(rt.get("tunnel_running", False)),
        "public_host": rt.get("public_host", ""),
        "public_port": int(rt.get("public_port", 0)),
        "engine": rt.get("engine", user.get("mode", "mtproto")),
        "error": rt.get("error", ""),
        "bore_last_line": rt.get("bore_last_line", ""),
        **links,
    }


def get_telegram_system_status() -> dict[str, Any]:
    return {
        "mtg_available": _find_bin("mtg") is not None,
        "bore_available": _find_bin("bore") is not None,
        "tunnel_mode": TELEGRAM_CONFIG.get("tunnel_mode", "bore"),
        "bore_server": TELEGRAM_CONFIG.get("bore_server", "bore.pub"),
        "has_bore_secret": bool(TELEGRAM_CONFIG.get("bore_secret", "").strip()),
        "direct_host": TELEGRAM_CONFIG.get("direct_host", ""),
        "total_users": len(TELEGRAM_USERS),
        "active_users": sum(1 for u in TELEGRAM_USERS.values() if u.get("active", True)),
        "running_users": sum(1 for rt in _RUNTIME.values() if rt.get("running")),
        "tunnels_online": sum(1 for rt in _RUNTIME.values() if rt.get("tunnel_running")),
    }
