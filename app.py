#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Czat WebSocket - wszystko w pamieci RAM, zero SQL. Jeden proces, jeden worker.
Uruchomienie:  uvicorn app:app --host 127.0.0.1 --port 8000 --workers 1 --ws-max-size 65536
--ws-max-size 65536 odcina ramki > 64 KB (zaszyfrowana wiadomosc 2000 znakow
to ~3 KB, wiec 64 KB to hojny limit chroniacy pamiec serwera).

Haslo pokoju = bramka (challenge):
- Pierwsza osoba zaklada pokoj: serwer generuje losowy ciag 32 znakow (RAM),
  wysyla go twórcy, przegladarka szyfruje go haslem (AES, CryptoJS) i odsyla
  kryptogram. Serwer zapisuje go jako pierwsza wiadomosc serwisowa historii.
- Kazdy nastepny chetny: serwer wysyla mu ten kryptogram. Klient deszyfruje
  haslem; odsylа odszyfrowany ciag. Zgadza sie -> wpuszcza do pokoju,
  nie -> blad i zamkniecie polaczenia (1008).
- Serwer NIGDY nie widzi hasla - zna tylko wygenerowany przez siebie ciag.
- Cigg zyje w RAM: restart serwisu = nowy ciag, pokoj trzeba zalozyc od nowa.

Ustawienia strony czytane z pliku settings.json lezacego OBOK app.py
(katalog /home/chat). Plik NIE jest serwowany publicznie; backend przekazuje
ustawienia klientom przez WebSocket (wiadomosc "settings") po polaczeniu:
- title, nick_placeholder, description - uzywa ich frontend
- history_len - ile wiadomosci trzymac na pokoj w pamieci
- max_msg - maksymalna dlugosc wiadomosci w znakach
- max_connections - limit rownoczesnych polaczen WebSocket (0 = brak limitu).
  Po jego osiagnieciu nowe polaczenia dostaja komunikat o pelnym serwerze
  i sa zamykane (kod 1013); zwolniony slot zwalnia kolejke nowych.
Hot-reload: plik jest sprawdzany po mtime przy kazdym zdarzeniu; edycja JSON
wchodzi w zycie bez restartu serwisu.

Historia pokoju zyje TYLKO dopoki sa w nim polaczenia WebSocket.
Ostatni wychodzi (leave lub rozlaczenie) -> pokoj, historia i klucz znikaja.
"""
import asyncio
import hmac
import json
import os
import secrets
import time
from collections import deque
from urllib.parse import urlsplit

from fastapi import FastAPI, WebSocket, WebSocketDisconnect

MAX_RATE = 5               # max wiadomosci / sekunde na polaczenie
MAX_CTL_RATE = 8           # max join/leave / sekunde na polaczenie
HEARTBEAT = 30             # co ile sekund serwer pyta o pong
TIMEOUT = 60               # brak pongu przez tyle sekund = rozlaczenie
PENDING_TIMEOUT = 30       # tyle sekund klient ma na weryfikacje hasla (potem zamkniecie)
MAX_ROOM_LEN = 32          # max dlugosc nazwy pokoju (jak maxlength we frontendzie)
MAX_ROOMS = 5              # max pokoi naraz na JEDNO polaczenie WebSocket
MAX_RAW = 8192             # ramka klienta wieksza (w znakach) leci do kosza bez parsowania
ALLOWED_ORIGINS = {"chat.121212.best", "121212.best"}  # tylko te strony moga laczyc z /ws

# --- ustawienia z pliku JSON (hot-reload po zmianie mtime) ---
SETTINGS_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "settings.json")

DEFAULT_SETTINGS = {
    "title": "Czat 121212 — szyfrowany",
    "nick_placeholder": "np. Michal",
    "description": "Hasło jest kluczem pokoju: pierwsza osoba zakłada je razem z pokojem, a każdy następny musi je znać, żeby w ogóle wejść. Serwer weryfikuje je w ciemno (sam go nie widzi). Nowy pokój wymaga hasła o długości co najmniej 12 znaków — przycisk 🔑 wygeneruje losowe. Po restarcie serwisu pokój zakłada się od nowa.",
    "history_len": 200,
    "max_msg": 2000,
    "max_connections": 500,   # limit rownoczesnych polaczen WebSocket
}

_settings_cache = {"mtime": None, "data": None}


def load_settings():
    """Czyta settings.json z dysku; przy bledzie/braku pliku zwraca domyslne."""
    s = dict(DEFAULT_SETTINGS)
    try:
        with open(SETTINGS_PATH, "r", encoding="utf-8") as f:
            raw = json.load(f)
        if isinstance(raw, dict):
            for k in DEFAULT_SETTINGS:
                if k in raw and raw[k] is not None:
                    s[k] = raw[k]
        for k in ("history_len", "max_msg"):
            try:
                s[k] = max(1, int(s[k]))
            except Exception:
                s[k] = DEFAULT_SETTINGS[k]
        try:
            s["max_connections"] = max(0, int(s["max_connections"]))   # 0 = brak limitu
        except Exception:
            s["max_connections"] = DEFAULT_SETTINGS["max_connections"]
    except Exception:
        pass
    return s


def get_settings():
    """Zwraca ustawienia; ponownie czyta plik tylko gdy zmienil sie mtime."""
    try:
        mtime = os.stat(SETTINGS_PATH).st_mtime
    except Exception:
        mtime = None
    if _settings_cache["mtime"] != mtime:
        _settings_cache["data"] = load_settings()
        _settings_cache["mtime"] = mtime
    return _settings_cache["data"]


app = FastAPI()

# referencje do zadań broadcast — bez tego GC niszczy task zanim wyśle (błąd "task was destroyed")
_bg = set()

# --- struktury w pamieci ---
rooms = {}        # nazwa pokoju -> set(WebSocket)
clients = {}      # WebSocket -> {"nick", "room_nicks": {pokoj: nick}, "connected", "last_pong", "sent": deque(ts)}
history = {}      # nazwa pokoju -> deque(maxlen=history_len) z {"ts", "nick", "text"[, "sys"]}
challenges = {}   # nazwa pokoju -> {"plain": losowy ciag 32 znaki, "cipher": kryptogram (1. wiadomosc serwisowa)}
pending = {}      # WebSocket -> {"room", "mode": "create"|"join"} — trwa weryfikacja hasla
pending_creations = {}  # nazwa pokoju -> {"plain", "ws"} — pokoj w trakcie zakladania (lock)
bridges = {}      # mosty miedzy pokojami: {"zrodlo": ["cel"]} — dzialaja tylko gdy pokoje maja to samo haslo

# --- pomocnicze ---
def room_set(name):
    return rooms.setdefault(name, set())

def room_hist(name):
    return history.setdefault(name, deque(maxlen=get_settings()["history_len"]))

_hist_len_seen = [None]

def sync_history_len():
    """Jesli zmieniono history_len w settings.json, przebuduj kolejki istniejacych pokoi."""
    hl = get_settings()["history_len"]
    if _hist_len_seen[0] != hl:
        for name, dq in list(history.items()):
            if dq.maxlen != hl:
                history[name] = deque(list(dq)[-hl:], maxlen=hl)
        _hist_len_seen[0] = hl

def prune_empty_room(room):
    """Ostatnie polaczenie opuscilo pokoj -> usun pokoj, historie i klucz z pamieci."""
    if room in rooms and not rooms[room]:
        rooms.pop(room, None)
        history.pop(room, None)
        challenges.pop(room, None)

def now_iso():
    return time.strftime("%Y-%m-%d %H:%M:%S")

def pack(obj):
    return json.dumps(obj, ensure_ascii=False)

def rate_exceeded(ws, key, limit=MAX_RATE):
    """True, gdy polaczenie przekroczylo limit zdarzen/sek. w danym koszyku
    ('sent' = msg/pm, 'ctl' = join/leave). Koszyki sa niezalezne — szybkie
    wysylanie wiadomosci nie zjada limitu na zmiane pokoju i odwrotnie."""
    now = time.time()
    buf = clients[ws][key]
    buf.append(now)
    while buf and buf[0] < now - 1.0:
        buf.popleft()
    return len(buf) > limit

def room_of(data):
    """Nazwa pokoju z ramki: strip + uciecie do MAX_ROOM_LEN (backend nie ufa frontendowi)."""
    return str(data.get("room", "")).strip()[:MAX_ROOM_LEN]

async def safe_send(ws, msg):
    try:
        await ws.send_text(msg)
    except Exception:
        pass

def broadcast(room, obj, skip=None):
    msg = pack(obj)
    for ws in list(room_set(room)):
        if ws is skip:
            continue
        t = asyncio.create_task(safe_send(ws, msg))
        _bg.add(t)
        t.add_done_callback(_bg.discard)

def broadcast_presence(room):
    nicks = []
    for ws in room_set(room):
        n = clients.get(ws, {}).get("room_nicks", {}).get(room)
        if n:
            nicks.append(n)
    broadcast(room, {"type": "presence", "room": room, "nicks": nicks})

def nick_for_room(ws, room):
    """Unikalny nick w pokoju: duplikat dostaje sufiks _2, _3..."""
    base = clients[ws]["nick"]
    taken = {clients[c].get("room_nicks", {}).get(room) for c in room_set(room) if c is not ws}
    taken.discard(None)
    if base not in taken:
        return base
    i = 2
    while f"{base}_{i}" in taken:
        i += 1
    return f"{base}_{i}"

def real_history(room):
    """Ostatnie wiadomosci bez wpisow serwisowych (klucz challenge) — max 100 szt."""
    sync_history_len()
    show = min(get_settings()["history_len"], 100)
    return [m for m in list(room_hist(room))[-show:] if not m.get("sys")]

# --- watchdog: zamykanie polaczen, ktore nie przeszly weryfikacji hasla ---
_watchdog_task = [None]

def ensure_watchdog():
    """Startuje (raz) globalny watchdog pending. Wolac po accept()."""
    if _watchdog_task[0] is None or _watchdog_task[0].done():
        t = asyncio.create_task(pending_watchdog())
        _watchdog_task[0] = t
        _bg.add(t)
        t.add_done_callback(_bg.discard)

async def pending_watchdog():
    """Klient, ktory w ciagu PENDING_TIMEOUT nie przeslal challenge_resp,
    dostaje blad i jest zamykany — nie mozna trzymac slotu z puli polaczen
    ani blokowac tworzenia pokoju (pending_creations) bez podania hasla."""
    try:
        while True:
            await asyncio.sleep(5)
            now = time.time()
            for ws, p in list(pending.items()):
                if now - p.get("since", now) <= PENDING_TIMEOUT:
                    continue
                room = p["room"]
                if p["mode"] == "create":
                    pc = pending_creations.get(room)
                    if pc and pc["ws"] is ws:
                        pending_creations.pop(room, None)
                pending.pop(ws, None)
                await safe_send(ws, pack({"type": "error", "msg":
                    f"Nie podano hasla do pokoju #{room} w ciagu {PENDING_TIMEOUT} s — polaczenie zamkniete."}))
                try:
                    await ws.close(code=1008, reason="auth timeout")
                except Exception:
                    pass
    except Exception:
        pass

async def admit(ws, room):
    """Wpusc klienta do pokoju (po pozytywnej weryfikacji hasla)."""
    room_set(room).add(ws)
    clients[ws]["room_nicks"][room] = nick_for_room(ws, room)
    await ws.send_text(pack({"type": "history", "room": room, "messages": real_history(room)}))
    broadcast_presence(room)

# --- endpointy ---
@app.get("/health")
async def health():
    return {"ok": True, "rooms": {r: len(s) for r, s in rooms.items()}, "clients": len(clients),
            "max_connections": int(get_settings().get("max_connections", DEFAULT_SETTINGS["max_connections"]))}

@app.get("/status")
async def status():
    """Publiczny licznik zajetosci — frontend pokazuje go na ekranie logowania."""
    return {"clients": len(clients), "max_connections": int(get_settings().get("max_connections", DEFAULT_SETTINGS["max_connections"]))}

@app.websocket("/ws")
async def ws_endpoint(ws: WebSocket):
    nick = (ws.query_params.get("nick") or "anonim").strip()[:24] or "anonim"
    # --- Origin: obca strona WWW nie moze otworzyc websocketa do czatu ---
    origin = ws.headers.get("origin")
    if origin:
        host = (urlsplit(origin).netloc or "").split(":")[0].lower()
        if host not in ALLOWED_ORIGINS:
            try:
                await ws.close(code=1008, reason="origin not allowed")
            except Exception:
                pass
            return
    await ws.accept()
    ensure_watchdog()
    # --- limit rownoczesnych polaczen (settings.json: max_connections) ---
    maxc = int(get_settings().get("max_connections", DEFAULT_SETTINGS["max_connections"]))
    if maxc > 0 and len(clients) >= maxc:
        await safe_send(ws, pack({"type": "error", "code": "full",
            "msg": f"Serwer jest pelny ({maxc} z {maxc} polaczen zajetych). Poczekaj, az zwolni sie polaczenie, i sprobuj ponownie."}))
        try:
            await ws.close(code=1013, reason="server full")
        except Exception:
            pass
        return
    clients[ws] = {
        "nick": nick,
        "room_nicks": {},
        "connected": time.time(),
        "last_pong": time.time(),
        "sent": deque(maxlen=MAX_RATE + 10),
        "ctl": deque(maxlen=MAX_CTL_RATE + 10),
    }
    try:
        await ws.send_text(pack({
            "type": "settings",
            "settings": {
                k: get_settings()[k]
                for k in ("title", "nick_placeholder", "description", "history_len", "max_msg", "max_connections")
            },
        }))
    except Exception:
        pass
    try:
        await ws.send_text(pack({
            "type": "welcome",
            "nick": nick,
            "rooms": sorted(rooms.keys()) or [],
            "ts": now_iso(),
            "msg": "Polaczono. Podaj pokoj, aby rozpoczac weryfikacje hasla."
        }))
    except Exception:
        pass

    heartbeat = asyncio.create_task(heartbeat_loop(ws))
    try:
        while True:
            raw = await ws.receive_text()
            if len(raw) > MAX_RAW:
                continue   # za duza ramka — bez parsowania JSON (warstwa po ws-max-size)
            try:
                data = json.loads(raw)
            except Exception:
                continue
            t = data.get("type")

            if t == "pong":
                clients[ws]["last_pong"] = time.time()
                continue

            if t == "join":
                room = room_of(data)
                if not room:
                    continue
                if room == "#all":
                    await ws.send_text(pack({"type": "error", "msg": "Pokoj #all jest wylaczony — hasla sa przypisywane per pokoj."}))
                    continue
                if ws in pending:
                    continue   # weryfikacja w toku
                if rate_exceeded(ws, "ctl", MAX_CTL_RATE):
                    await ws.close(code=1008, reason="rate limit")
                    break
                if room in clients[ws]["room_nicks"]:
                    continue   # juz jestesmy w tym pokoju — nic nie rob
                if len(clients[ws]["room_nicks"]) >= MAX_ROOMS:
                    await ws.send_text(pack({"type": "error", "msg": f"Limit to {MAX_ROOMS} pokoi na jedno polaczenie — opusc ktorys pokoj i sprobuj ponownie."}))
                    continue
                if room in pending_creations:
                    if pending_creations[room]["ws"] is not ws:
                        await ws.send_text(pack({"type": "error", "msg": f"Pokoj #{room} jest w trakcie zakladania, sprobuj za chwile."}))
                    continue
                if room in rooms:
                    ch = challenges.get(room)
                    if not ch:
                        await ws.send_text(pack({"type": "error", "msg": f"Pokoj #{room} nie ma klucza — zaloz go od nowa."}))
                        continue
                    pending[ws] = {"room": room, "mode": "join", "since": time.time()}
                    await ws.send_text(pack({"type": "challenge", "mode": "join", "room": room, "cipher": ch["cipher"]}))
                else:
                    plain = secrets.token_hex(16)   # 32 znaki, tylko RAM
                    pending_creations[room] = {"plain": plain, "ws": ws}
                    pending[ws] = {"room": room, "mode": "create", "since": time.time()}
                    await ws.send_text(pack({"type": "challenge", "mode": "create", "room": room, "challenge": plain}))
                continue

            if t == "challenge_resp":
                p = pending.pop(ws, None)
                if not p:
                    continue
                room = p["room"]
                if p["mode"] == "create":
                    cipher = str(data.get("cipher", "")).strip()[:4096]
                    pc = pending_creations.pop(room, None)
                    if not pc or not cipher:
                        continue
                    challenges[room] = {"plain": pc["plain"], "cipher": cipher}
                    room_hist(room).append({"ts": now_iso(), "nick": "SYSTEM", "text": cipher, "sys": True})
                    await admit(ws, room)
                else:
                    ch = challenges.get(room)
                    if ch and hmac.compare_digest(str(data.get("plain", "")), ch["plain"]):
                        await admit(ws, room)
                    else:
                        await ws.send_text(pack({"type": "error", "msg": f"Bledne haslo do pokoju #{room} — nie dolaczono."}))
                        await ws.close(code=1008, reason="wrong password")
                        break
                continue

            if t == "challenge_fail":
                p = pending.pop(ws, None)
                if not p:
                    continue
                room = p["room"]
                if p["mode"] == "create":
                    pending_creations.pop(room, None)
                await ws.send_text(pack({"type": "error", "msg": f"Bledne haslo do pokoju #{room} — nie dolaczono."}))
                await ws.close(code=1008, reason="wrong password")
                break

            if t == "leave":
                if ws in pending:
                    continue
                if rate_exceeded(ws, "ctl", MAX_CTL_RATE):
                    await ws.close(code=1008, reason="rate limit")
                    break
                room = room_of(data)
                if room == "#all":
                    for r in list(clients[ws]["room_nicks"]):
                        room_set(r).discard(ws)
                        clients[ws]["room_nicks"].pop(r, None)
                        broadcast_presence(r)
                        prune_empty_room(r)
                    await ws.send_text(pack({"type": "leave_ack", "room": "#all"}))
                    continue
                room_set(room).discard(ws)
                clients[ws]["room_nicks"].pop(room, None)
                broadcast_presence(room)
                prune_empty_room(room)
                await ws.send_text(pack({"type": "leave_ack", "room": room}))
                continue

            if t == "msg":
                if ws in pending:
                    continue
                room = room_of(data)
                text = str(data.get("text", "")).strip()
                if not room or not text:
                    continue
                # limit wysylki: 5 msg/s, nadmiar = rozlaczenie
                if rate_exceeded(ws, "sent"):
                    await ws.close(code=1008, reason="rate limit")
                    break
                text = text[:get_settings()["max_msg"]]
                if not text:
                    continue
                sync_history_len()
                entry = {"ts": now_iso(), "nick": clients[ws]["room_nicks"].get(room, clients[ws]["nick"]), "text": text}
                room_hist(room).append(entry)
                broadcast(room, {"type": "msg", "room": room, **entry})
                # mosty miedzy pokojami (tylko gdy pokoje dziela to samo haslo)
                for target in bridges.get(room, []):
                    room_hist(target).append(entry)
                    broadcast(target, {"type": "msg", "room": target, **entry})
                    prune_empty_room(target)
                continue

            if t == "pm":
                # Wiadomosc prywatna: trafia TYLKO do nadawcy i odbiorcy,
                # NIE jest zapisywana w historii pokoju (nowi nie zobacza jej).
                if ws in pending:
                    continue
                room = room_of(data)
                target = str(data.get("to", "")).strip()
                text = str(data.get("text", "")).strip()
                if not room or not text or not target:
                    continue
                # limit wysylki: jak przy zwyklej wiadomosci (5 msg/s)
                if rate_exceeded(ws, "sent"):
                    await ws.close(code=1008, reason="rate limit")
                    break
                text = text[:get_settings()["max_msg"]]
                if not text:
                    continue
                sender_nick = clients[ws]["room_nicks"].get(room)
                if not sender_nick:
                    continue
                if target.lower() == sender_nick.lower():
                    await ws.send_text(pack({"type": "error", "msg": "Nie mozesz wyslac wiadomosci prywatnej do samego siebie."}))
                    continue
                # szukaj odbiorcy po nicku w pokoju (bez wzgledu na wielkosc liter)
                tgt = None
                tl = target.lower()
                for c in list(room_set(room)):
                    if c is ws:
                        continue
                    if (clients.get(c, {}).get("room_nicks", {}).get(room) or "").lower() == tl:
                        tgt = c
                        break
                if tgt is None:
                    await ws.send_text(pack({"type": "error", "msg": f"@{target} nie jest teraz obecny w pokoju — wiadomosc prywatna NIE zostala wyslana."}))
                    continue
                entry = {"ts": now_iso(), "nick": sender_nick, "text": text}
                pm = {"type": "pm", "room": room, "from": sender_nick, "to": clients[tgt]["room_nicks"][room], **entry}
                await safe_send(tgt, pack(pm))
                await safe_send(ws, pack(pm))
                continue
    except WebSocketDisconnect:
        pass
    except Exception:
        pass
    finally:
        heartbeat.cancel()
        p = pending.pop(ws, None)
        if p and p["mode"] == "create":
            pc = pending_creations.get(p["room"])
            if pc and pc["ws"] is ws:
                pending_creations.pop(p["room"], None)
        if ws in clients:
            for r in list(clients[ws]["room_nicks"]):
                room_set(r).discard(ws)
                broadcast_presence(r)
                prune_empty_room(r)
            clients.pop(ws, None)

async def heartbeat_loop(ws: WebSocket):
    try:
        while True:
            await asyncio.sleep(HEARTBEAT)
            if time.time() - clients[ws]["last_pong"] > TIMEOUT:
                await ws.close(code=1001, reason="heartbeat timeout")
                return
            await ws.send_text(pack({"type": "ping"}))
    except Exception:
        try:
            await ws.close(code=1001)
        except Exception:
            pass
