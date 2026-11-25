"""Telegram Proxy user management & bore.pub tunnel API routes."""
from __future__ import annotations

from datetime import datetime
import secrets
import uuid

from fastapi import APIRouter, Depends, HTTPException, Request

from app.auth import require_auth
from app.qr_generator import generate_qr_base64
from app.state import TELEGRAM_CONFIG, TELEGRAM_LOCK, TELEGRAM_USERS, log_activity, save_state
from app.telegram_proxy import (
    generate_mtproto_secret,
    get_telegram_system_status,
    next_available_port,
    serialize_telegram_user,
    start_all_telegram_proxies,
    start_user_proxy,
    stop_all_telegram_proxies,
    stop_user_proxy,
)

router = APIRouter(prefix="/api/telegram", tags=["telegram"])


@router.get("/status")
async def telegram_status(_=Depends(require_auth)):
    return get_telegram_system_status()


@router.get("/users")
async def list_telegram_users(_=Depends(require_auth)):
    async with TELEGRAM_LOCK:
        items = [serialize_telegram_user(u) for u in TELEGRAM_USERS.values()]
    return {"users": items, "status": get_telegram_system_status()}


@router.post("/users")
async def create_telegram_user(request: Request, _=Depends(require_auth)):
    body = await request.json()
    label = str(body.get("label") or "").strip()[:60] or f"TG-User-{len(TELEGRAM_USERS) + 1}"
    mode = str(body.get("mode") or "mtproto").strip().lower()
    if mode not in ("mtproto", "socks5"):
        raise HTTPException(status_code=400, detail="Mode must be 'mtproto' or 'socks5'")

    fake_tls_domain = str(body.get("fake_tls_domain") or "www.cloudflare.com").strip()[:100]
    note = str(body.get("note") or "").strip()[:200]
    active = bool(body.get("active", True))

    uid = str(uuid.uuid4())
    async with TELEGRAM_LOCK:
        local_port = next_available_port()
        if mode == "mtproto":
            secret = str(body.get("secret") or "").strip() or generate_mtproto_secret(fake_tls_domain)
            username = ""
            password = ""
        else:
            secret = ""
            username = str(body.get("username") or "").strip()[:40] or f"tg_{secrets.token_hex(3)}"
            password = str(body.get("password") or "").strip()[:64] or secrets.token_urlsafe(10)

        user = {
            "id": uid,
            "label": label,
            "mode": mode,
            "fake_tls_domain": fake_tls_domain if mode == "mtproto" else "",
            "secret": secret,
            "username": username,
            "password": password,
            "local_port": local_port,
            "active": active,
            "note": note,
            "created_at": datetime.now().isoformat(),
        }
        TELEGRAM_USERS[uid] = user

    await save_state()
    if active:
        await start_user_proxy(uid)

    log_activity("telegram", f"Created Telegram {mode.upper()} user '{label}'", "ok")
    return {"ok": True, "user": serialize_telegram_user(user)}


@router.put("/users/{uid}")
async def update_telegram_user(uid: str, request: Request, _=Depends(require_auth)):
    body = await request.json()
    async with TELEGRAM_LOCK:
        user = TELEGRAM_USERS.get(uid)
        if not user:
            raise HTTPException(status_code=404, detail="Telegram user not found")

        if "label" in body:
            user["label"] = str(body["label"] or "").strip()[:60] or user["label"]
        if "note" in body:
            user["note"] = str(body["note"] or "").strip()[:200]
        if "active" in body:
            user["active"] = bool(body["active"])
        if "fake_tls_domain" in body and user.get("mode") == "mtproto":
            dom = str(body["fake_tls_domain"] or "www.cloudflare.com").strip()[:100]
            if dom != user.get("fake_tls_domain"):
                user["fake_tls_domain"] = dom
                user["secret"] = generate_mtproto_secret(dom)

        is_active = bool(user.get("active", True))

    await save_state()
    if is_active:
        await start_user_proxy(uid)
    else:
        await stop_user_proxy(uid)

    log_activity("telegram", f"Updated Telegram user '{user['label']}' (active={is_active})", "info")
    return {"ok": True, "user": serialize_telegram_user(user)}


@router.post("/users/{uid}/restart")
async def restart_telegram_user(uid: str, _=Depends(require_auth)):
    async with TELEGRAM_LOCK:
        user = TELEGRAM_USERS.get(uid)
        if not user:
            raise HTTPException(status_code=404, detail="Telegram user not found")
        user["active"] = True

    await save_state()
    await start_user_proxy(uid)
    log_activity("telegram", f"Restarted Telegram proxy & tunnel for '{user['label']}'", "ok")
    return {"ok": True, "user": serialize_telegram_user(user)}


@router.delete("/users/{uid}")
async def delete_telegram_user(uid: str, _=Depends(require_auth)):
    await stop_user_proxy(uid)
    async with TELEGRAM_LOCK:
        removed = TELEGRAM_USERS.pop(uid, None)
        if not removed:
            raise HTTPException(status_code=404, detail="Telegram user not found")

    await save_state()
    log_activity("telegram", f"Deleted Telegram user '{removed.get('label', uid)}'", "info")
    return {"ok": True}


@router.get("/users/{uid}/qr")
async def telegram_user_qr(uid: str, _=Depends(require_auth)):
    async with TELEGRAM_LOCK:
        user = TELEGRAM_USERS.get(uid)
        if not user:
            raise HTTPException(status_code=404, detail="Telegram user not found")
        data = serialize_telegram_user(user)
    return {
        "label": data["label"],
        "tg_link": data["tg_link"],
        "tme_link": data["tme_link"],
        "tg_qr": generate_qr_base64(data["tg_link"]),
        "tme_qr": generate_qr_base64(data["tme_link"]),
    }


@router.post("/config")
async def update_telegram_config(request: Request, _=Depends(require_auth)):
    body = await request.json()
    mode = str(body.get("tunnel_mode") or TELEGRAM_CONFIG.get("tunnel_mode", "bore")).strip().lower()
    if mode not in ("bore", "direct"):
        raise HTTPException(status_code=400, detail="tunnel_mode must be 'bore' or 'direct'")

    async with TELEGRAM_LOCK:
        TELEGRAM_CONFIG["tunnel_mode"] = mode
        if "bore_server" in body:
            TELEGRAM_CONFIG["bore_server"] = str(body["bore_server"] or "bore.pub").strip()[:120] or "bore.pub"
        if "bore_secret" in body:
            TELEGRAM_CONFIG["bore_secret"] = str(body["bore_secret"] or "").strip()[:120]
        if "direct_host" in body:
            TELEGRAM_CONFIG["direct_host"] = str(body["direct_host"] or "").strip()[:120]

    await save_state()
    await stop_all_telegram_proxies()
    await start_all_telegram_proxies()
    log_activity("telegram", f"Updated Telegram tunnel config (mode={mode}, server={TELEGRAM_CONFIG['bore_server']})", "ok")
    return {"ok": True, "status": get_telegram_system_status()}
