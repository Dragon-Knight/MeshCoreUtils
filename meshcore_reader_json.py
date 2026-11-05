#!/usr/bin/env python3
"""MeshCore UDP receiver.

Принимает по UDP JSON-пакеты от SDRangel (LoRa-демодулятор), разбирает пакеты MeshCore
(все типы: ADVERT, сообщения в каналах, GRP_DATA, личные, ANON_REQ, ACK, TRACE, CONTROL и др.)
и выводит их в консоль и в лог по правилам-фильтрам.

Dragon_Knight при поддержке Claude (Anthropic)
"""

import argparse
import json
import os
import re
import socket
from datetime import datetime
from typing import Callable, Optional

from meshcore_proto import (HAVE_AES, HAVE_CURVES, INSTALL_HINT, KINDS, NODE_TYPES, PAYLOAD_TYPES,
                            REQ_TYPES, VERSION, KeyRing, Packet, ascii_dump, decode_packet,
                            grp_data_app, printable_text)

# ───────────────────────────── Настройки ─────────────────────────────

UDP_IP = "0.0.0.0"             # адрес приёма; "0.0.0.0" — все интерфейсы
UDP_PORT = 4404                # порт приёма (--port)
RCVBUF_SIZE = 1024 * 1024      # большой буфер, чтобы не терять UDP при плотном потоке
# Битые пакеты: ошибка CRC заголовка/payload (lora.header_crc, lora.payload_crc) или пустой payload.
#   "skip"   — не разбирать, вывести одну серую строку-заметку (по умолчанию)
#   "silent" — молча отбросить
#   "parse"  — разбирать как обычно, но пометить в шапке красным "BAD ..."
BAD_PACKET_MODE = "skip"       # переопределяется ключом --bad {skip,silent,parse}
SHOW_DEBUG_JSON = False        # печатать исходный JSON перед разбором (--debug включает)
SEPARATOR_WIDTH = 60           # длина линии между пакетами

# Ключи, которыми пробуем расшифровать пакеты. Форматы:
#   "#name"                 — хэштег-канал (ключ = SHA256("#name")[:16], имя в нижнем регистре)
#   "<32 hex>"              — ключ канала без имени: 16 байт, напр. "8b3387e9c5cdea6ac9e5edbaa115cd72";
#                             в выводе канал называется "key", фильтровать удобнее по хэшу
#   "name:<32 hex>"         — то же с именем канала (имя для вывода и фильтра "channel")
#   "<64 hex>", "name:<64 hex>" — общий секрет двух узлов (32 байта) для личных сообщений
#   "pub:[name:]<64 hex>"   — публичный ключ контакта для ECDH (ключи из эфира запоминаются сами,
#                             см. SAVE_CONTACTS)
#   "prv:<hex>"             — свой приватный ключ (удобнее задать в PRIVATE_KEY)
#   "public"                — публичный канал (добавлен всегда, --no-public отключает)
# Вместо hex везде можно base64; в hex допустимы разделители ":", "-", пробел и префикс 0x.
# Ещё ключи: -k SPEC (можно несколько раз) или файлом --keys-file (по SPEC на строку, "//" — комментарий).
KEYS = [
    "#test", "#ru", "#msk", "#moscow", "#russia", "#chat", "#general",
    "#mesh", "#meshcore", "#ping", "#wardrive", "#bot", "#hello", "#help",
    "#mytishchi", "#connections", "#robot",
]

# Свой приватный ключ для расшифровки личных сообщений и ANON_REQ, где один из узлов — вы:
# hex или base64, 64 B из экспорта приложения MeshCore или 32 B seed. Пусто — ECDH выключен.
# Переопределяется --private-key.
PRIVATE_KEY = ""

# Публичные ключи узлов из эфира (ADVERT с верной подписью, ANON_REQ) нужны для ECDH и имён узлов
# в DIRECT/ANON. SAVE_CONTACTS = True — сохранять их в CONTACTS_FILE при каждом новом/переименованном
# узле и загружать при запуске. Файл в формате ключей (pub:name:<hex>): подходит decoder'у как --keys-file.
# --contacts-file FILE — другой файл, --no-contacts — не загружать и не сохранять.
SAVE_CONTACTS = True
CONTACTS_FILE = "mesh_contacts.txt"

# ── Правила (общий формат для фильтров экрана и для лога) ──────────────────
# Правило — словарь. Список правил работает по ИЛИ: достаточно совпадения хотя бы одного.
# Внутри правила все указанные условия объединяются по И. Любое поле можно не указывать,
# пустое правило {} совпадает с любым пакетом. Неверное правило пропускается с предупреждением.
#
#   "type"     — тип пакета или список типов:
#                advert    — объявления узлов
#                message   — сообщения в каналах (расшифрованные GRP_TXT)
#                data      — данные в каналах (расшифрованные GRP_DATA)
#                direct    — личные: TXT_MSG, REQ, RESPONSE, PATH (без ключа видны только хэши узлов)
#                anon      — анонимные запросы ANON_REQ (вход на репитер/в комнату и др.)
#                ack       — подтверждения
#                trace     — трассировка маршрута с SNR по хопам
#                control   — служебные (DISCOVER_REQ / DISCOVER_RESP)
#                multipart — часть составного пакета
#                custom    — RAW_CUSTOM
#                raw       — всё, что не разобрано: каналы с неизвестным ключом, битые и
#                            нестандартные заголовки, зарезервированные типы
#   "channel"  — каналы: имена ["public", "#moscow", "name"] и/или хэши СТРОКАМИ в hex ["6c", "37"];
#                для message, data и raw (хэш виден и без ключа); у остальных типов не совпадает
#   "route"    — "flood" (с TRANSPORT_FLOOD) | "direct" (с TRANSPORT_DIRECT) | "transport_flood" |
#                "transport_direct" или список
#   "hops"     — диапазон хопов (Path len), границы включительно:
#                (0, 2) — от 0 до 2;  (3, None) — от 3 и больше;  (None, 1) — не больше 1;  2 — ровно 2
#   "snr"      — диапазон SNR в dB, как hops, можно дробные: (5, None) — от +5 dB и лучше
#   "rssi"     — диапазон RSSI в dB, как hops: (None, -110) — слабее -110 dB
#   "match"    — регулярное выражение (без учёта регистра) по имени узла (advert), отправителю и
#                тексту (message, расшифрованные direct/anon, custom): "dragon", "^Bob$", "привет|hello"
#
# ── Фильтр экрана ────────────────────────────────────────────────────────
# SHOW_RULES — что ПОКАЗЫВАТЬ в консоли; пустой список — показывать всё.
# HIDE_RULES — что СКРЫВАТЬ, даже если пакет прошёл SHOW_RULES; пустой — ничего не скрывать.
# Фильтр влияет только на экран; битые пакеты (CRC) и заметки о них фильтром не затрагиваются.
# --no-filter временно отключает оба списка.
SHOW_RULES = [
    #{"type": "message", "channel": ["public"]},
    #{"type": ["advert", "trace"], "hops": (None, 2)},
    #{"rssi": (-100, None)},
]
HIDE_RULES = [
    #{"type": "raw"},
    {"type": ["anon", "ack", "trace", "control", "multipart"]},
]

# ── Логирование ──────────────────────────────────────────────────────────
# Пакет пишется в лог, если совпало ХОТЯ БЫ ОДНО правило из LOG_RULES; пустой список — лог выключен.
# Лог НЕЗАВИСИМ от фильтра экрана: можно держать чистый экран и подробный лог (и наоборот).
# LOG_ONLY_SHOWN = True — писать в лог только то, что прошло фильтр экрана (И с LOG_RULES).
# LOG_ENABLED = False или --no-log — выключить лог; --log-file FILE — другой файл.
LOG_ONLY_SHOWN = False
LOG_ENABLED = True
LOG_FILE = "mesh_log.txt"
LOG_RULES = [
    #{"type": "advert", "hops": (0, 2)},
    #{"type": "message", "channel": ["public", "#moscow"], "hops": (0, 3)},
    #{"type": "message", "match": "dragon"},
    #{"type": "raw", "channel": ["6c", "37"]},
    #{"type": "raw", "channel": ["37"], "hops": (None, 3)},
]


# ───────────────────────────── Раскраска ─────────────────────────────

class Color:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    GRAY = "\033[90m"
    # Фоны для плашек типа пакета (отдельная палитра, не пересекается с цветами сигнала)
    BG_MAGENTA = "\033[45;97m"
    BG_BLUE = "\033[44;97m"
    BG_CYAN = "\033[46;30m"
    BG_GRAY = "\033[100;97m"
    BG_YELLOW = "\033[43;30m"
    BG_RED = "\033[41;97m"
    BG_GREEN = "\033[42;30m"


def paint(text, *styles: str) -> str:
    """paint("текст", Color.GREEN, Color.BOLD) -> раскрашенная строка."""
    return f"{''.join(styles)}{text}{Color.RESET}"


def enable_ansi_on_windows() -> None:
    if os.name == "nt":
        os.system("")  # включает обработку ANSI-последовательностей в cmd/PowerShell


CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")
ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


def clean(value) -> str:
    """Убираем управляющие символы из чужих данных (имя/текст), чтобы они не ломали терминал."""
    return CONTROL_CHARS.sub("", str(value))


def to_float(value, default: float = 0.0) -> float:
    try:
        return float(value)
    except (ValueError, TypeError):
        return default


# ───────────────────────────── Вывод ─────────────────────────────

LABEL_WIDTH = 10

# Блок пакета сначала собирается в буфер, и только потом уходит в консоль и/или в лог.
_out: list = []


def emit(text: str = "") -> None:
    _out.append(text)


def line(label: str, value, color: str = Color.YELLOW) -> None:
    emit(f"   {paint(label.ljust(LABEL_WIDTH), Color.GRAY)} {paint(value, color)}")


def snr_color(snr: float) -> str:
    if snr >= 5:
        return Color.GREEN
    if snr >= 0:
        return Color.YELLOW
    return Color.RED


# kind -> (плашка, иконка, фон)
BADGES = {
    "advert": ("ADVERT", "📣", Color.BG_MAGENTA),
    "message": ("MESSAGE", "💬", Color.BG_BLUE),
    "data": ("DATA", "📦", Color.BG_BLUE),
    "direct": ("DIRECT", "✉️ ", Color.BG_YELLOW),
    "anon": ("ANON", "🕵️ ", Color.BG_RED),
    "ack": ("ACK", "✅", Color.BG_GREEN),
    "trace": ("TRACE", "🛰️ ", Color.BG_CYAN),
    "control": ("CONTROL", "🔎", Color.BG_CYAN),
    "multipart": ("MULTIPART", "🧩", Color.BG_CYAN),
    "custom": ("CUSTOM", "❔", Color.BG_CYAN),
    "raw": ("RAW", "🔒", Color.BG_GRAY),
}


def print_header(pkt: Packet, ctx: dict) -> None:
    """Единая шапка: время, тип, сигнал, источник."""
    badge, icon, bg = BADGES[pkt.kind]
    rf = ctx["rf"]
    host, port = ctx["addr"][0], ctx["addr"][1]
    parts = [
        paint(ctx["time"], Color.GRAY),
        icon,
        paint(" " + badge.ljust(9) + " ", Color.BOLD, bg),
        paint("SNR {:+.1f} dB".format(ctx["snr"]), snr_color(ctx["snr"]), Color.BOLD),
        paint("RSSI {:.0f} dB".format(ctx["rssi"]), Color.GRAY),
        paint("SF{}".format(rf.get("spreading_factor", "?")), Color.GRAY),
        paint("{}:{}".format(host, port), Color.GRAY),
    ]
    if ctx.get("bad"):
        parts.append(paint(" BAD " + ctx["bad"] + " ", Color.BOLD, Color.BG_RED))
    emit(" ".join(parts))


def route_line(pkt: Packet, show_type: bool = False, extra: Optional[str] = None) -> None:
    """Вторая строка блока: [тип пакета ·] маршрут · хопы [· extra]."""
    if pkt.error and pkt.error != "empty payload":
        return
    sep = paint(" · ", Color.GRAY)
    parts = []
    if show_type:
        parts.append(paint(PAYLOAD_TYPES.get(pkt.ptype, f"0x{pkt.ptype:02X}"), Color.BOLD))
    parts.append(paint(pkt.route_name, Color.GRAY))
    hops = "{} hop{}".format(pkt.hops, "" if pkt.hops == 1 else "s")
    if pkt.hash_size > 1:
        hops += " ({} B)".format(pkt.hash_size)
    snr = pkt.trace_snr
    if pkt.hops and snr is not None:
        hops += ": SNR " + " → ".join(f"{s:+.1f}" for s in snr) + " dB"
    elif pkt.hops:
        hops += ": " + " → ".join(pkt.hop_list)
    parts.append(paint(hops, Color.GRAY))
    text = sep.join(parts)
    if extra:
        text += sep + extra
    emit("   " + text)


def print_footer() -> None:
    emit(paint("─" * SEPARATOR_WIDTH, Color.GRAY) + "\n")


def packet_lines(pkt: Packet) -> None:
    line("Length", f"{len(pkt.raw)} bytes", Color.GRAY)
    line("Packet", pkt.raw.hex() or "—", Color.GRAY)


def node_label(ring: KeyRing, h: int) -> str:
    """Хэш узла и имя, если по нему однозначно найден контакт."""
    if ring.identity is not None and h == ring.identity.hash:
        return f"{h:02x} (me)"
    names = {name for pub, name in ring.contacts.items() if pub[0] == h}
    return f"{h:02x} ({clean(names.pop())})" if len(names) == 1 and "" not in names else f"{h:02x}"


def data_line(label: str, data: bytes) -> None:
    text = printable_text(data)
    line(label, clean(text) if text is not None else f"{data.hex()}  |{ascii_dump(data)}|")


# ───────────────────────────── Обработчики типов ─────────────────────────────

def handle_advert(pkt: Packet, ctx: dict) -> None:
    info = pkt.info
    sig = info.get("sig_valid")
    if sig is True:
        extra = paint("sig valid", Color.GREEN)
    elif sig is None:
        extra = paint("sig not checked", Color.GRAY)
    else:
        extra = paint("sig INVALID", Color.RED, Color.BOLD)
    route_line(pkt, extra=extra)
    line("Name", clean(info.get("name", "—")))
    line("Key", info["pubkey"], Color.CYAN)
    if "flags" in info:
        line("Type", "0x{:02x} ({})".format(info["flags"], NODE_TYPES.get(info["node_type"], "Unknown")))
    if "lat" in info:
        lat, lon = f"{info['lat']:.6f}", f"{info['lon']:.6f}"
        url = f"https://www.openstreetmap.org/?mlat={lat}&mlon={lon}"
        emit("   {} {}  {}".format(paint("Position".ljust(LABEL_WIDTH), Color.GRAY),
                                    paint(f"{lat}, {lon}", Color.YELLOW), paint(url, Color.BLUE)))


def channel_line(pkt: Packet) -> None:
    line("Channel", "[{:02x}] {}".format(pkt.info["channel_hash"], clean(pkt.info["channel"])), Color.CYAN)


def handle_message(pkt: Packet, ctx: dict) -> None:
    route_line(pkt)
    channel_line(pkt)
    if pkt.info.get("sender"):
        line("From", clean(pkt.info["sender"]))
    line("Text", clean(pkt.info["text"]), Color.BOLD)


def handle_data(pkt: Packet, ctx: dict) -> None:
    route_line(pkt)
    channel_line(pkt)
    dt = pkt.info["data_type"]
    line("App", f"0x{dt:04x} ({grp_data_app(dt)})")
    data_line("Data", pkt.info["data"])


def decrypted_lines(pkt: Packet) -> None:
    """Содержимое расшифрованного личного пакета / ANON_REQ."""
    info = pkt.info
    line("Key", clean(info["key"]), Color.GRAY)
    if pkt.ptype == 0x02 and "text" in info:
        line("Text", clean(info["text"]), Color.BOLD)
    elif "req_type" in info and pkt.ptype == 0x00:
        line("Request", "0x{:02x} {}".format(info["req_type"], REQ_TYPES.get(info["req_type"], "unknown")))
    elif "return_path" in info:
        line("Path", " → ".join(info["return_path"]) or "—")
        if "extra_type" in info:
            line("Extra", PAYLOAD_TYPES.get(info["extra_type"], f"0x{info['extra_type']:02X}"))
    elif "text" in info:
        line("Content", clean(info["text"]), Color.BOLD)
    elif "data" in info:
        data_line("Data", info["data"])


def handle_direct(pkt: Packet, ctx: dict) -> None:
    """Личное сообщение/запрос: содержимое зашифровано общим секретом двух узлов."""
    route_line(pkt, show_type=True)
    ring = ctx["ring"]
    info = pkt.info
    if "dst" in info:
        line("Src Dst", "{} → {}".format(node_label(ring, info["src"]), node_label(ring, info["dst"])), Color.CYAN)
    if info.get("decrypted"):
        decrypted_lines(pkt)
    packet_lines(pkt)


def handle_anon(pkt: Packet, ctx: dict) -> None:
    """ANON_REQ: dest_hash(1) + sender_pubkey(32) + MAC(2) + ciphertext."""
    route_line(pkt)
    info = pkt.info
    line("Dest", node_label(ctx["ring"], info["dst"]) if "dst" in info else "—", Color.CYAN)
    line("Sender", info.get("sender_pub", "—"), Color.CYAN)
    if info.get("decrypted"):
        decrypted_lines(pkt)
    else:
        line("Content", "encrypted (no key)", Color.GRAY)
    packet_lines(pkt)


def handle_ack(pkt: Packet, ctx: dict) -> None:
    route_line(pkt)
    line("Checksum", pkt.info.get("checksum", "—"))


def handle_trace(pkt: Packet, ctx: dict) -> None:
    route_line(pkt)
    info = pkt.info
    if "route" in info:
        line("Route", " → ".join(info["route"]) or "—")
        line("Tag", f"0x{info['tag']:08x}", Color.GRAY)


def handle_control(pkt: Packet, ctx: dict) -> None:
    route_line(pkt)
    info = pkt.info
    line("Subtype", info.get("subtype", "—"), Color.BOLD)
    if "type_filter" in info:
        line("Looking", ", ".join(info["type_filter"]) or "—")
    if "pubkey" in info:
        line("Node", "{} ({})".format(info["pubkey"], NODE_TYPES.get(info["node_type"], "Unknown")), Color.CYAN)
        line("SNR", f"{info['snr']:+.2f} dB (heard by node)")
    if "tag" in info:
        line("Tag", info["tag"], Color.GRAY)


def handle_multipart(pkt: Packet, ctx: dict) -> None:
    route_line(pkt)
    info = pkt.info
    if "inner_type" in info:
        line("Parts left", info["remaining"])
        line("Inner", PAYLOAD_TYPES.get(info["inner_type"], f"0x{info['inner_type']:X}"))
    packet_lines(pkt)


def handle_custom(pkt: Packet, ctx: dict) -> None:
    route_line(pkt)
    data_line("Data", pkt.payload)
    packet_lines(pkt)


# Заготовка под свои декодеры нераспознанных пакетов (блок RAW).
# Декодер получает (raw: bytes, packet: dict из JSON) и возвращает строку с результатом или None.
RawDecoder = Callable[[bytes, dict], Optional[str]]
RAW_DECODERS: list = []


def register_raw_decoder(func: RawDecoder) -> RawDecoder:
    """Используй как декоратор: @register_raw_decoder"""
    RAW_DECODERS.append(func)
    return func


# Пример:
# @register_raw_decoder
# def my_channel_decoder(raw: bytes, packet: dict) -> Optional[str]:
#     ...расшифровка своим ключом...
#     return "текст сообщения"


def handle_raw(pkt: Packet, ctx: dict) -> None:
    """Пакет без расшифровки (неизвестный канал / нет ключа) или с нестандартным заголовком."""
    route_line(pkt, show_type=True)
    if "channel_hash" in pkt.info:
        name = clean(pkt.info.get("channel", "unknown key"))
        line("Channel", "[{:02x}] {}".format(pkt.info["channel_hash"], name), Color.GRAY)
    reasons = ([pkt.error] if pkt.error else []) + pkt.invalid
    if reasons:
        line("Reason", ", ".join(reasons), Color.RED)
    line("Length", f"{len(pkt.raw)} bytes", Color.GRAY)
    line("Header", f"0x{pkt.raw[0]:02x}" if pkt.raw else "—", Color.GRAY)
    line("Packet", pkt.raw.hex(), Color.GRAY)

    for decoder in RAW_DECODERS:
        try:
            result = decoder(pkt.raw, ctx["json"])
        except Exception as e:
            line("Decoder", f"{decoder.__name__}: {e}", Color.RED)
            continue
        if result:
            line("Decoded", clean(result), Color.GREEN)
            break


HANDLERS = {
    "advert": handle_advert, "message": handle_message, "data": handle_data, "direct": handle_direct,
    "anon": handle_anon, "ack": handle_ack, "trace": handle_trace, "control": handle_control,
    "multipart": handle_multipart, "custom": handle_custom, "raw": handle_raw,
}


# ───────────────────────────── Правила ─────────────────────────────

RULE_KEYS = {"type", "channel", "route", "hops", "snr", "rssi", "match"}
ROUTES = {"flood": {0, 1}, "direct": {2, 3}, "transport_flood": {0}, "transport_direct": {3}}
HEX_HASH = re.compile(r"[0-9a-fA-F]{2}")


def _as_list(value) -> list:
    return list(value) if isinstance(value, (list, tuple, set)) else [value]


def _as_range(value, name: str) -> Optional[tuple]:
    if value is None:
        return None
    if isinstance(value, (int, float)):
        return value, value
    try:
        lo, hi = value
    except (TypeError, ValueError):
        raise ValueError(f"{name}: expected a number or (min, max)")
    return lo, hi


def _in_range(value: Optional[float], rng: tuple) -> bool:
    lo, hi = rng
    return value is not None and (lo is None or value >= lo) and (hi is None or value <= hi)


class Rule:
    def __init__(self, spec: dict):
        extra = set(spec) - RULE_KEYS
        if extra:
            raise ValueError(f"unknown rule keys: {', '.join(sorted(extra))}")

        self.types = None
        if "type" in spec:
            self.types = {str(t).lower() for t in _as_list(spec["type"])}
            bad = self.types - set(KINDS)
            if bad:
                raise ValueError(f"unknown type {', '.join(sorted(bad))}; valid: {', '.join(KINDS)}")

        self.channels = self.hashes = None
        if "channel" in spec:
            items = [str(c).lower() for c in _as_list(spec["channel"])]
            self.channels = set(items)
            self.hashes = {int(c, 16) for c in items if HEX_HASH.fullmatch(c)}

        self.routes = None
        if "route" in spec:
            names = [str(r).lower() for r in _as_list(spec["route"])]
            bad = [n for n in names if n not in ROUTES]
            if bad:
                raise ValueError(f"unknown route {', '.join(bad)}; valid: {', '.join(ROUTES)}")
            self.routes = set().union(*(ROUTES[n] for n in names))

        self.hops = _as_range(spec.get("hops"), "hops")
        self.snr = _as_range(spec.get("snr"), "snr")
        self.rssi = _as_range(spec.get("rssi"), "rssi")
        self.match = re.compile(spec["match"], re.IGNORECASE) if spec.get("match") else None
        self.spec = spec

    def matches(self, pkt: Packet, ctx: dict) -> bool:
        if self.types is not None and pkt.kind not in self.types:
            return False
        if self.channels is not None:
            name, h = pkt.info.get("channel"), pkt.info.get("channel_hash")
            if name not in self.channels and h not in self.hashes:
                return False
        if self.routes is not None and (pkt.error or pkt.route not in self.routes):
            return False
        if self.hops is not None and (pkt.error or not _in_range(pkt.hops, self.hops)):
            return False
        if self.snr is not None and not _in_range(ctx["snr"], self.snr):
            return False
        if self.rssi is not None and not _in_range(ctx["rssi"], self.rssi):
            return False
        if self.match is not None and not self.match.search(pkt.search_text):
            return False
        return True

    def describe(self) -> str:
        parts = []
        for key in ("type", "channel", "route"):
            if key in self.spec:
                parts.append(f"{key}=" + ",".join(str(v) for v in _as_list(self.spec[key])))
        for key in ("hops", "snr", "rssi"):
            rng = getattr(self, key)
            if rng is not None:
                lo, hi = rng
                parts.append(f"{key}={'' if lo is None else lo}..{'' if hi is None else hi}")
        if self.match is not None:
            parts.append(f"match={self.match.pattern}")
        return " ".join(parts) or "any"


def first_match(rules: list, pkt: Packet, ctx: dict) -> Optional[Rule]:
    """Первое совпавшее правило из списка (ИЛИ) или None."""
    for rule in rules:
        if rule.matches(pkt, ctx):
            return rule
    return None


def build_rules(specs: list, title: str) -> list:
    """Собирает правила из словарей; неверные пропускает с предупреждением."""
    rules = []
    for i, spec in enumerate(specs, 1):
        try:
            rules.append(Rule(spec))
        except (ValueError, TypeError, re.error) as e:
            print(paint(f"⚠️  {title} #{i} skipped: {e}", Color.YELLOW))
    return rules


class PacketLogger:
    def __init__(self, path: str, rules: list):
        self.path = path
        self.rules = rules

    def write(self, rule: Rule, block: str) -> None:
        stamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        entry = f"▶ {stamp} | rule: {rule.describe()}\n{ANSI_RE.sub('', block)}\n"
        try:
            with open(self.path, "a", encoding="utf-8") as f:
                f.write(entry)
        except OSError as e:
            print(paint(f"💥 Cannot write log {self.path}: {e}", Color.RED))


LOGGER: Optional[PacketLogger] = None
SHOW_FILTER: list = []   # собранные SHOW_RULES; пусто — показывать всё
HIDE_FILTER: list = []   # собранные HIDE_RULES


def is_shown(pkt: Packet, ctx: dict) -> bool:
    if SHOW_FILTER and first_match(SHOW_FILTER, pkt, ctx) is None:
        return False
    return first_match(HIDE_FILTER, pkt, ctx) is None


# ───────────────────────────── Обработка пакета ─────────────────────────────

# JSON всегда начинается с {"lora": ...}; допускаем любые пробелы/переводы строк (LF и CRLF)
JSON_START = re.compile(rb'\{\s*"lora"\s*:')
_json = json.JSONDecoder()


def extract_json(data: bytes) -> Optional[dict]:
    """Находит начало JSON, отбрасывает мусор в начале и в конце. Возвращает dict или None."""
    match = JSON_START.search(data)
    if not match:
        return None
    text = data[match.start():].decode("utf-8", errors="ignore")
    obj, _ = _json.raw_decode(text)  # raw_decode игнорирует хвост после JSON
    return obj


def lora_errors(lora: dict) -> list:
    """Причины считать пакет битым. Пустой список — пакет целый.

    Проверяются только CRC: значения "ok" и "n/a" — норма, всё остальное ("err") — ошибка.
    FEC не смотрим: "fix" означает исправленные ошибки, а payload_fec почти всегда "n/a".
    """
    bad = []
    for name in ("header_crc", "payload_crc"):
        value = lora.get(name)
        if value is not None and str(value).strip().lower() not in ("ok", "n/a"):
            bad.append("{}={}".format(name, value))
    if not str(lora.get("payload_hex", "")).strip():
        bad.append("empty payload")
    return bad


def process_packet(ctx: dict) -> None:
    # из JSON берём только сигнал (rf) и payload_hex; остальное декодируем сами
    try:
        raw = bytes.fromhex(ctx["payload_hex"])
    except ValueError:
        raw = b""
    pkt = decode_packet(raw, ctx["ring"])

    shown = is_shown(pkt, ctx)
    rule = first_match(LOGGER.rules, pkt, ctx) if LOGGER else None
    if LOG_ONLY_SHOWN and not shown:
        rule = None
    if not shown and not rule:
        return

    _out.clear()
    print_header(pkt, ctx)
    HANDLERS[pkt.kind](pkt, ctx)
    print_footer()
    block = "\n".join(_out)

    if shown:
        print(block)
    if rule:
        LOGGER.write(rule, block)


# ───────────────────────────── Основной цикл ─────────────────────────────

def make_socket(port: int) -> socket.socket:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, RCVBUF_SIZE)
    sock.bind((UDP_IP, port))
    return sock


def build_ring(args) -> KeyRing:
    ring = KeyRing(public=not args.no_public)
    specs = list(KEYS) + args.key
    if args.keys_file:
        with open(args.keys_file, encoding="utf-8") as f:
            specs += f.read().splitlines()
    private_key = args.private_key or PRIVATE_KEY
    if private_key:
        specs.append("prv:" + private_key)
    for spec in specs:
        try:
            ring.add(spec)
        except Exception as e:
            print(paint(f"⚠️  Key '{spec}' skipped: {e}", Color.YELLOW))
    return ring


def save_contacts(ring: KeyRing, path: str) -> None:
    try:
        ring.save_contacts(path)
    except OSError as e:
        ring.contacts_changed = False   # не повторять ошибку на каждом пакете; следующий новый узел попробует снова
        print(paint(f"💥 Cannot write contacts {path}: {e}", Color.RED))


def main() -> None:
    global SHOW_DEBUG_JSON, LOGGER, BAD_PACKET_MODE, SHOW_FILTER, HIDE_FILTER

    parser = argparse.ArgumentParser(description=f"MeshCore UDP receiver v{VERSION}")
    parser.add_argument("--port", type=int, default=UDP_PORT, help=f"UDP port (default {UDP_PORT})")
    parser.add_argument("-k", "--key", action="append", default=[], metavar="SPEC",
                        help='key: "#name", "name:<hex|base64>", "pub:[name:]<hex>" (repeatable)')
    parser.add_argument("--keys-file", metavar="FILE", help="file with keys, one SPEC per line")
    parser.add_argument("--private-key", metavar="HEX", help="own private key for ECDH (overrides PRIVATE_KEY)")
    parser.add_argument("--no-public", action="store_true", help="do not add the Public channel key")
    parser.add_argument("--contacts-file", metavar="FILE", help=f"contacts file (default {CONTACTS_FILE})")
    parser.add_argument("--no-contacts", action="store_true", help="do not load or save contacts")
    parser.add_argument("--debug", action="store_true", help="print source JSON")
    parser.add_argument("--log-file", metavar="FILE", help=f"log file (default {LOG_FILE})")
    parser.add_argument("--no-log", action="store_true", help="disable logging")
    parser.add_argument("--no-filter", action="store_true", help="disable screen filters (SHOW_RULES, HIDE_RULES)")
    parser.add_argument("--bad", choices=("skip", "silent", "parse"), default=None,
                        help="packets with CRC errors: skip - one-line note (default), "
                             "silent - drop, parse - decode with a mark")
    parser.add_argument("--version", action="version", version=VERSION)
    args = parser.parse_args()

    SHOW_DEBUG_JSON = SHOW_DEBUG_JSON or args.debug
    BAD_PACKET_MODE = args.bad or BAD_PACKET_MODE

    enable_ansi_on_windows()
    ring = build_ring(args)
    contacts_path = (args.contacts_file or CONTACTS_FILE) if SAVE_CONTACTS and not args.no_contacts else None
    if contacts_path:
        try:
            ring.load_contacts(contacts_path)
        except (OSError, UnicodeDecodeError) as e:
            print(paint(f"⚠️  Cannot read contacts {contacts_path}: {e}", Color.YELLOW))
        if ring.contacts_changed:   # контакты из -k / KEYS ещё не в файле
            save_contacts(ring, contacts_path)
    if not HAVE_AES or not HAVE_CURVES:
        print(paint(f"⚠️  Decryption, signatures and ECDH are limited: {INSTALL_HINT}", Color.YELLOW))
    log_path = args.log_file or LOG_FILE
    if LOG_ENABLED and not args.no_log:
        rules = build_rules(LOG_RULES, "Log rule")
        LOGGER = PacketLogger(log_path, rules) if rules else None
    if not args.no_filter:
        SHOW_FILTER = build_rules(SHOW_RULES, "Show rule")
        HIDE_FILTER = build_rules(HIDE_RULES, "Hide rule")
    sock = make_socket(args.port)

    log_state = f"log: {log_path}, rules: {len(LOGGER.rules)}" if LOGGER else "log: off"
    filter_state = f"filter: show {len(SHOW_FILTER)}, hide {len(HIDE_FILTER)}" \
        if SHOW_FILTER or HIDE_FILTER else "filter: off"
    ecdh = f"ECDH: on (node {ring.identity.hash:02x})" if ring.identity else "ECDH: off"
    contacts_state = f"contacts: {len(ring.contacts)}" + (f" ({contacts_path})" if contacts_path else ", not saved")
    print(paint(f"📻 MeshCore receiver v{VERSION} on port {args.port} "
                f"(keys: {len(ring.keys)}, {contacts_state}, {ecdh}, {filter_state}, {log_state})",
                Color.BOLD, Color.CYAN) + "\n")

    while True:
        try:
            data, addr = sock.recvfrom(65535)

            packet = extract_json(data)
            if packet is None:
                continue  # в пакете нет JSON — просто мусор

            if SHOW_DEBUG_JSON:
                print(paint(json.dumps(packet, ensure_ascii=False, indent=2), Color.DIM))

            lora = packet.get("lora") or {}
            rf = packet.get("rf") or {}
            errors = lora_errors(lora)
            snr = to_float(rf.get("snr_db"))
            if errors and BAD_PACKET_MODE != "parse":
                if BAD_PACKET_MODE == "skip":
                    print(paint("{} ⚠ bad packet skipped ({}) SNR {:+.1f} dB {}:{}".format(
                        datetime.now().strftime("%H:%M:%S"), ", ".join(errors), snr, addr[0], addr[1]),
                        Color.GRAY) + "\n")
                continue

            ctx = {
                "bad": ", ".join(errors),
                "addr": addr,
                "rf": rf,
                "snr": snr,
                "rssi": to_float(rf.get("signal_db")),
                "time": datetime.now().strftime("%H:%M:%S"),
                "payload_hex": str(lora.get("payload_hex", "")),
                "json": packet,
                "ring": ring,
            }
            process_packet(ctx)
            if contacts_path and ring.contacts_changed:
                save_contacts(ring, contacts_path)

        except KeyboardInterrupt:
            print("\n" + paint("Receiver stopped.", Color.CYAN))
            break
        except json.JSONDecodeError:
            print(paint(f"⚠️  Invalid JSON from {addr[0]}:{addr[1]}", Color.YELLOW))
        except Exception as e:
            print(paint(f"💥 Packet processing error: {e!r}", Color.RED))


if __name__ == "__main__":
    main()
