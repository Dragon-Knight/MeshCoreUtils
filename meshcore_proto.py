#!/usr/bin/env python3
"""MeshCore: разбор пакетов, ключи, расшифровка. Общий модуль для meshcore_decoder и meshcore_reader_json.

Формат: https://docs.meshcore.io/packet_format/ и https://docs.meshcore.io/payloads/
Для расшифровки, проверки подписи и ECDH: pip install cryptography
"""

import base64
import binascii
import hashlib
import hmac
import os
import re
import struct
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

VERSION = "2.4"

# ───────────────────────────── Крипто-бэкенды ─────────────────────────────

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    def aes_ecb_decrypt(key: bytes, data: bytes) -> bytes:
        dec = Cipher(algorithms.AES(key), modes.ECB()).decryptor()
        return dec.update(data) + dec.finalize()

    HAVE_AES = True
except ImportError:
    try:
        from Crypto.Cipher import AES  # pycryptodome

        def aes_ecb_decrypt(key: bytes, data: bytes) -> bytes:
            return AES.new(key, AES.MODE_ECB).decrypt(data)

        HAVE_AES = True
    except ImportError:
        HAVE_AES = False

        def aes_ecb_decrypt(key: bytes, data: bytes) -> bytes:
            raise RuntimeError("install: pip install cryptography")

try:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey

    HAVE_CURVES = True
except ImportError:
    HAVE_CURVES = False

INSTALL_HINT = "pip install cryptography"

# ───────────────────────────── Константы протокола ─────────────────────────────

ROUTE_TYPES = {0: "TRANSPORT_FLOOD", 1: "FLOOD", 2: "DIRECT", 3: "TRANSPORT_DIRECT"}
PAYLOAD_TYPES = {
    0x00: "REQ", 0x01: "RESPONSE", 0x02: "TXT_MSG", 0x03: "ACK",
    0x04: "ADVERT", 0x05: "GRP_TXT", 0x06: "GRP_DATA", 0x07: "ANON_REQ",
    0x08: "PATH", 0x09: "TRACE", 0x0A: "MULTIPART", 0x0B: "CONTROL",
    0x0F: "RAW_CUSTOM",
}
NODE_TYPES = {0: "None", 1: "Chat", 2: "Repeater", 3: "Room server", 4: "Sensor"}
TXT_TYPES = {0: "plain text", 1: "CLI data", 2: "signed plain text", 3: "CLI command"}
REQ_TYPES = {
    0x01: "GET_STATS", 0x02: "KEEP_ALIVE", 0x03: "GET_TELEMETRY", 0x04: "GET_MIN_MAX_AVG",
    0x05: "GET_ACL", 0x06: "GET_NEIGHBOURS", 0x07: "GET_OWNER_INFO",
    0x08: "SUBSCRIBE", 0x09: "UNSUBSCRIBE",
}
ANON_REQ_TYPES = {0x01: "REGIONS", 0x02: "OWNER_INFO", 0x03: "CLOCK_STATUS"}
CONTROL_SUBTYPES = {0x8: "DISCOVER_REQ", 0x9: "DISCOVER_RESP"}
# Типы GRP_DATA: https://docs.meshcore.io/number_allocations/
GRP_DATA_APPS = [
    (0x0000, 0x00FF, "reserved"), (0x0100, 0x0100, "MeshCore Open"), (0x0110, 0x011F, "Ripple"),
    (0x0120, 0x0120, "MCO Advanced"), (0x0130, 0x013F, "StreamSensor"), (0x0140, 0x0140, "Nelos"),
    (0xFF00, 0xFFFF, "testing/dev"),
]

PT_REQ, PT_RESPONSE, PT_TXT_MSG, PT_ACK, PT_ADVERT, PT_GRP_TXT, PT_GRP_DATA, PT_ANON_REQ = range(8)
PT_PATH, PT_TRACE, PT_MULTIPART, PT_CONTROL, PT_RAW_CUSTOM = 0x08, 0x09, 0x0A, 0x0B, 0x0F
DIRECT_PTYPES = {PT_REQ, PT_RESPONSE, PT_TXT_MSG, PT_PATH}   # dst(1) src(1) MAC(2) ciphertext

MAX_PATH_SIZE = 64
MAX_PAYLOAD = 184
PUBLIC_KEY = base64.b64decode("izOH6cXN6mrJ5e26oRXNcg==")

# Тип пакета для фильтров и вывода (Packet.kind) определяется только типом payload, расшифровка на него
# не влияет (см. Packet.decrypted). "raw" — пакет не разобран: битый заголовок или payload,
# зарезервированный тип, нестандартная версия.
KINDS = ("advert", "message", "data", "direct", "anon", "ack", "trace",
         "control", "multipart", "custom", "raw")
_KIND_BY_PTYPE = {PT_ADVERT: "advert", PT_GRP_TXT: "message", PT_GRP_DATA: "data", PT_ANON_REQ: "anon",
                  PT_ACK: "ack", PT_TRACE: "trace", PT_CONTROL: "control", PT_MULTIPART: "multipart",
                  PT_RAW_CUSTOM: "custom", **{p: "direct" for p in DIRECT_PTYPES}}


# ───────────────────────────── Утилиты ─────────────────────────────

def fmt_ts(ts: int) -> str:
    """Unix-время -> 'ts (YYYY-MM-DD HH:MM:SS +0300)' в локальной зоне."""
    try:
        return f"{ts}  ({datetime.fromtimestamp(ts).astimezone():%Y-%m-%d %H:%M:%S %z})"
    except (OverflowError, OSError, ValueError):
        return str(ts)


def to_text(b: bytes) -> str:
    return b.rstrip(b"\0").decode("utf-8", errors="replace")


def printable_text(b: bytes) -> Optional[str]:
    """Текст, если данные похожи на текст, иначе None."""
    s = b.rstrip(b"\0")
    if not s:
        return None
    try:
        t = s.decode("utf-8")
    except UnicodeDecodeError:
        return None
    ok = sum(1 for ch in t if ch.isprintable() or ch in "\n\t")
    return t if ok / len(t) >= 0.9 else None


def ascii_dump(b: bytes) -> str:
    return "".join(chr(c) if 32 <= c < 127 else "." for c in b)


def hop_chunks(path: bytes, size: int) -> list:
    return [path[i:i + size].hex() for i in range(0, len(path), size)]


def split_sender(text: str) -> tuple:
    """MeshCore кладёт в текст 'Имя: сообщение' — разделяем, если это похоже на имя."""
    sender, sep, message = text.partition(": ")
    if sep and 0 < len(sender) <= 40 and "\n" not in sender:
        return sender, message
    return None, text


def grp_data_app(data_type: int) -> str:
    for lo, hi, name in GRP_DATA_APPS:
        if lo <= data_type <= hi:
            return name
    return "custom app"


def _s8(b: int) -> int:
    return b - 256 if b > 127 else b


# ───────────────────────────── Ключи ─────────────────────────────

class Key:
    """Симметричный ключ: ключ канала (16/32 B) или общий секрет ECDH (32 B)."""

    def __init__(self, label: str, secret: bytes):
        if len(secret) not in (16, 32):
            raise ValueError(f"key must be 16 or 32 bytes, got {len(secret)}")
        self.label = label
        self.secret = secret
        self.aes_key = secret[:16]
        self.hmac_key = secret.ljust(32, b"\0")           # HMAC всегда по 32-байтному секрету
        self.hash = hashlib.sha256(secret).digest()[0]    # 1-байтовый хэш канала, возможны коллизии

    def __str__(self) -> str:
        return f"{self.label}: {self.secret.hex()}  (channel hash 0x{self.hash:02X})"


def hashtag_key(name: str) -> Key:
    name = name.strip().lower()
    return Key(name, hashlib.sha256(name.encode("utf-8")).digest()[:16])


def parse_secret(text: str, sizes=(16, 32)) -> bytes:
    """hex (с разделителями ':' '-' пробел или префиксом 0x) или base64."""
    t = text.strip()
    h = re.sub(r"^0x|[\s:\-]", "", t, flags=re.I)
    if re.fullmatch(r"[0-9a-fA-F]+", h) and len(h) // 2 in sizes and len(h) % 2 == 0:
        return bytes.fromhex(h)
    try:
        b = base64.b64decode(t, validate=True)
        if len(b) in sizes:
            return b
    except (binascii.Error, ValueError):
        pass
    raise ValueError(f"cannot parse key: {t!r}")


def _split_named(text: str, sizes) -> tuple:
    """'[name:]<key>' -> (name, bytes). Имя может содержать ':', ключ в hex может быть с ':'."""
    for i in [-1] + [i for i, ch in enumerate(text) if ch == ":"]:
        try:
            return text[:max(i, 0)].strip(), parse_secret(text[i + 1:], sizes)
        except ValueError:
            continue
    raise ValueError(f"cannot parse key: {text.strip()!r}")


_P = 2 ** 255 - 19


def _ed_to_x25519(pub: bytes) -> bytes:
    """Публичный ключ Ed25519 -> X25519: u = (1 + y) / (1 - y) mod p."""
    y = int.from_bytes(pub, "little") & ((1 << 255) - 1)
    if (1 - y) % _P == 0:
        raise ValueError("invalid public key")
    u = (1 + y) * pow(1 - y, _P - 2, _P) % _P
    return u.to_bytes(32, "little")


def _clamp(scalar: bytes) -> bytes:
    s = bytearray(scalar)
    s[0] &= 248
    s[31] &= 63
    s[31] |= 64
    return bytes(s)


class Identity:
    """Свой приватный ключ для ECDH.

    MeshCore хранит 64 байта: скаляр(32) + префикс(32) (формат orlp/ed25519, его отдаёт экспорт).
    Принимаем также 32-байтный seed и 64-байтный формат libsodium seed(32) + pubkey(32).
    """

    def __init__(self, prv: bytes):
        if not HAVE_CURVES:
            raise RuntimeError(f"ECDH needs: {INSTALL_HINT}")
        if len(prv) == 32:
            scalar = _clamp(hashlib.sha512(prv).digest()[:32])
        elif len(prv) == 64:
            seed_pub = Ed25519PrivateKey.from_private_bytes(prv[:32]).public_key().public_bytes_raw()
            scalar = _clamp(hashlib.sha512(prv[:32]).digest()[:32]) if seed_pub == prv[32:] else prv[:32]
        else:
            raise ValueError(f"private key must be 32 or 64 bytes, got {len(prv)}")
        self._x = X25519PrivateKey.from_private_bytes(scalar)
        u = int.from_bytes(self._x.public_key().public_bytes_raw(), "little")
        y = (u - 1) * pow(u + 1, _P - 2, _P) % _P
        self.pub_y = y.to_bytes(32, "little")   # публичный ключ Ed25519 без бита знака x
        self.hash = self.pub_y[0]
        self._cache: dict = {}

    def secret_with(self, pub: bytes) -> Optional[bytes]:
        if pub not in self._cache:
            try:
                other = X25519PublicKey.from_public_bytes(_ed_to_x25519(pub))
                self._cache[pub] = self._x.exchange(other)
            except ValueError:
                self._cache[pub] = None
        return self._cache[pub]

    def is_me(self, pub: bytes) -> bool:
        return pub[:31] == self.pub_y[:31] and (pub[31] & 0x7F) == self.pub_y[31]


def ecdh_secret(prv: bytes, pub: bytes) -> Optional[bytes]:
    return Identity(prv).secret_with(pub)


class KeyRing:
    """Все известные ключи: каналы, общие секреты, свой приватный ключ и публичные ключи контактов.

    Формат spec (одинаковый для -k, файла ключей и поля ключей GUI):
      public              — публичный канал
      #name               — хэштег-канал, ключ = SHA256("#name")[:16], имя приводится к нижнему регистру
      <hex|base64>        — ключ канала без имени (16 B = 32 hex) или общий секрет (32 B = 64 hex)
      name:<hex|base64>   — то же с именем
      prv:<hex>           — свой приватный ключ (32 или 64 B) для ECDH
      pub:[name:]<hex>    — публичный ключ контакта (32 B) для ECDH
      // ...              — комментарий (в файле)
    """

    def __init__(self, public: bool = True):
        self.keys: list = []
        self.identity: Optional[Identity] = None
        self.contacts: dict = {}     # pubkey -> name
        self.contacts_changed = False   # есть новые/переименованные контакты, ещё не сохранённые
        self._ecdh_keys: dict = {}
        if public:
            self.add("public")

    def add_key(self, key: Key) -> None:
        if all(k.secret != key.secret for k in self.keys):
            self.keys.append(key)

    def add_contact(self, pub: bytes, name: str = "") -> None:
        name = re.sub(r"[\x00-\x1f\x7f]", "", name).strip()
        if len(pub) != 32 or (pub in self.contacts and (not name or self.contacts[pub] == name)):
            return
        self.contacts[pub] = name
        self.contacts_changed = True
        self._ecdh_keys.pop(pub, None)   # подпись ключа ECDH берёт новое имя

    def load_contacts(self, path: str) -> int:
        """Читает файл контактов (строки pub:[name:]<hex>). Нет файла — 0."""
        if not os.path.exists(path):
            return 0
        before, changed = len(self.contacts), self.contacts_changed
        with open(path, encoding="utf-8") as f:
            for spec in f.read().splitlines():
                if spec.strip().lower().startswith("pub:"):
                    try:
                        self.add(spec)
                    except ValueError:
                        pass
        self.contacts_changed = changed   # загруженное уже в файле
        return len(self.contacts) - before

    def save_contacts(self, path: str) -> None:
        """Перезаписывает файл целиком через временный файл, чтобы не оставить его обрезанным."""
        lines = [f"// MeshCore contacts v{VERSION}: pub:[name:]<pubkey hex>, usable as a keys file"]
        lines += [f"pub:{name}:{pub.hex()}" if name else f"pub:{pub.hex()}" for pub, name in self.contacts.items()]
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")
        os.replace(tmp, path)
        self.contacts_changed = False

    def add(self, spec: str) -> None:
        spec = spec.strip()
        if not spec or spec.startswith("//"):
            return
        low = spec.lower()
        if low == "public":
            self.add_key(Key("public", PUBLIC_KEY))
        elif spec.startswith("#"):
            self.add_key(hashtag_key(spec))
        elif low.startswith("prv:"):
            self.identity = Identity(parse_secret(spec[4:], (32, 64)))
            self._ecdh_keys.clear()
        elif low.startswith("pub:"):
            name, pub = _split_named(spec[4:], (32,))
            self.add_contact(pub, name)
        else:
            name, secret = _split_named(spec, (16, 32))
            self.add_key(Key(name or "key", secret))

    def add_many(self, text: str) -> None:
        """Несколько spec через запятую, точку с запятой или пробел (поле GUI)."""
        for token in re.split(r"[,;\s]+", text.strip()):
            if token:
                self.add(token)

    def channel_keys(self, ch_hash: int) -> list:
        return [k for k in self.keys if k.hash == ch_hash]

    def _ecdh_key(self, pub: bytes) -> Optional[Key]:
        if pub not in self._ecdh_keys:
            secret = self.identity.secret_with(pub)
            name = self.contacts.get(pub) or pub[:4].hex()
            self._ecdh_keys[pub] = Key(f"ECDH with {name}", secret) if secret else None
        return self._ecdh_keys[pub]

    def _contacts_by_hash(self, h: int) -> list:
        return [pub for pub in self.contacts if pub[0] == h]

    def direct_keys(self, dst: int, src: int) -> list:
        """Кандидаты для DIRECT: ECDH с контактами (если один из узлов — мы), затем все ключи."""
        found = []
        if self.identity is not None:
            me = self.identity.hash
            others = ([src] if dst == me else []) + ([dst] if src == me else [])
            for h in others:
                found += [self._ecdh_key(p) for p in self._contacts_by_hash(h)]
        return [k for k in found if k] + self.keys

    def anon_keys(self, dst: int, sender: bytes) -> list:
        found = []
        if self.identity is not None:
            if dst == self.identity.hash:
                found.append(self._ecdh_key(sender))
            if self.identity.is_me(sender):
                found += [self._ecdh_key(p) for p in self._contacts_by_hash(dst)]
        return [k for k in found if k] + self.keys


# ───────────────────────────── Результат разбора ─────────────────────────────

@dataclass
class Row:
    label: str
    value: str = ""
    note: str = ""
    status: str = ""   # "" | ok | bad | warn | text


@dataclass
class Section:
    title: str
    rows: list = field(default_factory=list)

    def row(self, label: str, value, note: str = "", status: str = "") -> None:
        self.rows.append(Row(label, str(value), note, status))

    def warn(self, text: str) -> None:
        self.rows.append(Row("", text, status="warn"))

    def text(self, text: str, status: str = "text") -> None:
        self.rows.append(Row("", text, status=status))


@dataclass
class Packet:
    raw: bytes
    header: int = 0
    route: int = 0
    ptype: int = 0
    version: int = 0
    transport: Optional[tuple] = None
    path_len: int = 0          # байт path_len как есть
    hops: int = 0
    hash_size: int = 1
    path: bytes = b""
    payload: bytes = b""
    error: str = ""            # заголовок или payload не разобран (обрезан, слишком короткий)
    invalid: list = field(default_factory=list)   # причины, по которым прошивка отбросит пакет
    decrypted: Optional[bool] = None   # None — тип без шифрования; True/False — расшифрован или нет
    sections: list = field(default_factory=list)
    info: dict = field(default_factory=dict)      # смысловые поля для вывода и фильтров
    kind: str = "raw"

    @property
    def type_name(self) -> str:
        return PAYLOAD_TYPES.get(self.ptype, f"0x{self.ptype:02X}")

    @property
    def route_name(self) -> str:
        return ROUTE_TYPES[self.route]

    @property
    def valid(self) -> bool:
        return not self.error and not self.invalid

    @property
    def is_flood(self) -> bool:
        return self.route in (0, 1)

    @property
    def hop_list(self) -> list:
        return hop_chunks(self.path, self.hash_size)

    @property
    def trace_snr(self) -> Optional[list]:
        """У TRACE в path накапливается SNR каждого хопа (байт со знаком, SNR*4)."""
        if self.ptype != PT_TRACE or self.hash_size != 1:
            return None
        return [_s8(b) / 4 for b in self.path]

    @property
    def packet_hash(self) -> bytes:
        """ID пакета для дедупликации: SHA256(type [+ path_len для TRACE] + payload)[:8]."""
        h = hashlib.sha256(bytes([self.ptype]))
        if self.ptype == PT_TRACE:
            h.update(bytes([self.path_len]))
        h.update(self.payload)
        return h.digest()[:8]

    @property
    def search_text(self) -> str:
        """Текст для фильтра match: имя узла, отправитель, текст."""
        return "\n".join(str(self.info[k]) for k in ("name", "sender", "text") if self.info.get(k))

    def section(self, title: str) -> Section:
        sec = Section(title)
        self.sections.append(sec)
        return sec

    def fail(self, sec: Section, reason: str) -> None:
        """Payload не разобран: пакет станет raw."""
        self.error = reason
        sec.warn(reason)


# ───────────────────────────── Расшифровка ─────────────────────────────

@dataclass
class Decrypted:
    status: str                 # ok | nolib | bad | nokey | short
    key: Optional[Key] = None
    plain: Optional[bytes] = None
    calc_mac: bytes = b""
    tried: int = 0
    reason: str = ""


def try_decrypt(mac: bytes, ct: bytes, keys: list, nokey_reason: str = "no keys") -> Decrypted:
    """MAC = первые 2 байта HMAC-SHA256(secret32, ciphertext); шифр AES-128-ECB."""
    if len(ct) < 16:
        return Decrypted("short", reason="ciphertext shorter than one block (16 B)")
    if not keys:
        return Decrypted("nokey", reason=nokey_reason)
    first = b""
    for k in keys:
        calc = hmac.new(k.hmac_key, ct, hashlib.sha256).digest()[:2]
        first = first or calc
        if hmac.compare_digest(calc, mac):
            if not HAVE_AES:
                return Decrypted("nolib", k)
            n = len(ct) - len(ct) % 16
            return Decrypted("ok", k, aes_ecb_decrypt(k.aes_key, ct[:n]))
    return Decrypted("bad", calc_mac=first, tried=len(keys))


def _crypto_rows(pkt: Packet, sec: Section, mac: bytes, ct: bytes, keys: list,
                 nokey_reason: str, hint: str) -> Optional[bytes]:
    """MAC ✔/✘, шифртекст, секция Decryption. Возвращает plaintext или None."""
    d = try_decrypt(mac, ct, keys, nokey_reason)
    pkt.decrypted = d.status == "ok"
    m = mac.hex()
    if d.status in ("ok", "nolib"):
        sec.row("MAC", f"{m}  ✔", "match", "ok")
    elif d.status == "bad":
        sec.row("MAC", f"{m}  ✘", f"no match; computed {d.calc_mac.hex()}, keys tried: {d.tried}", "bad")
    else:
        sec.row("MAC", f"{m}  —", f"not checked: {d.reason}")
    sec.row("Ciphertext len", f"{len(ct)} B")
    sec.row("Ciphertext", ct.hex())
    if len(ct) % 16:
        sec.warn(f"ciphertext length {len(ct)} B is not a multiple of 16 — packet probably truncated")

    out = pkt.section("Decryption")
    if d.status == "ok":
        pad = len(d.plain) - len(d.plain.rstrip(b"\0"))
        out.row("Key", d.key)
        out.row("Plaintext len", f"{len(d.plain)} B", f"padding: {pad} B")
        pkt.info["key"] = d.key.label
        return d.plain
    if d.status == "nolib":
        out.text(f"✘ MAC matches, but no AES library: {INSTALL_HINT}", "bad")
    elif d.status == "bad":
        out.text("✘ MAC mismatch: wrong key or damaged packet", "bad")
    else:
        out.text(f"✘ not decrypted: {d.reason}", "bad")
    if hint:
        out.text(hint)
    return None


def _data_rows(sec: Section, b: bytes, name: str = "Data") -> None:
    """Все байты, нулевой хвост не отрезается: это может быть и padding, и данные."""
    sec.row(f"{name} (hex)", b.hex() or "—")
    sec.row(f"{name} (ascii)", ascii_dump(b) or "—")
    t = printable_text(b)
    if t is not None and not t.isascii():
        sec.row(f"{name} (utf-8)", "".join(ch if ch.isprintable() else "." for ch in t))


def _txt_flags(flags: int) -> str:
    return f"0x{flags:02X}  →  {TXT_TYPES.get(flags >> 2, f'unknown({flags >> 2})')}, attempt {flags & 3}"


def _text_message(pkt: Packet, sec: Section, plain: bytes) -> None:
    """timestamp(4) txt_type+attempt(1) [signer prefix(4) для signed] text."""
    if len(plain) < 5:
        sec.warn("plaintext shorter than 5 B")
        return
    ts, flags = struct.unpack_from("<IB", plain, 0)
    sec.row("Timestamp", fmt_ts(ts))
    sec.row("Flags", _txt_flags(flags))
    body = plain[5:]
    if flags >> 2 == 2 and len(body) >= 4:
        sec.row("Signer pubkey[0:4]", body[:4].hex())
        pkt.info["signer"] = body[:4].hex()
        body = body[4:]
    pkt.info.update(timestamp=ts, txt_type=flags >> 2, text=to_text(body))


# ───────────────────────────── Декодеры payload ─────────────────────────────

def _advert(pkt: Packet, p: bytes, ring: KeyRing, sec: Section) -> None:
    """pubkey(32) timestamp(4) signature(64) appdata: flags [lat lon] [feature1] [feature2] [name]."""
    if len(p) < 100:
        pkt.fail(sec, "ADVERT too short (need ≥ 100 B)")
        return
    pub, ts, sig, app = p[:32], struct.unpack_from("<I", p, 32)[0], p[36:100], p[100:]
    info = pkt.info
    info.update(pubkey=pub.hex(), timestamp=ts)
    sec.row("Public key", pub.hex())
    sec.row("Node hash", f"0x{pub[0]:02X}", "first byte of public key; how the node appears in path")
    sec.row("Timestamp", fmt_ts(ts))
    sec.row("Signature", sig.hex())
    if HAVE_CURVES:
        try:
            Ed25519PublicKey.from_public_bytes(pub).verify(sig, pub + p[32:36] + app)
            info["sig_valid"] = True
            sec.row("Signature check", "✔ valid", status="ok")
        except (InvalidSignature, ValueError):
            info["sig_valid"] = False
            sec.row("Signature check", "✘ INVALID", status="bad")
    else:
        info["sig_valid"] = None
        sec.row("Signature check", f"— not checked ({INSTALL_HINT})")

    if not app:
        sec.row("Appdata", "— (empty)")
        return
    sec = pkt.section("Appdata")
    flags = app[0]
    names = [n for bit, n in ((0x10, "location"), (0x20, "feature1"), (0x40, "feature2"), (0x80, "name"))
             if flags & bit]
    node_type = flags & 0x0F
    info.update(flags=flags, node_type=node_type)
    sec.row("Flags", f"0x{flags:02X}", ", ".join(names) or "no extra fields")
    sec.row("Node type", NODE_TYPES.get(node_type, f"unknown({node_type})"))
    i = 1
    if flags & 0x10:
        if len(app) < i + 8:
            sec.warn("appdata truncated: no location")
            return
        lat, lon = (v / 1e6 for v in struct.unpack_from("<ii", app, i))
        info.update(lat=lat, lon=lon)
        sec.row("Location", f"{lat:.6f}, {lon:.6f}", f"https://www.openstreetmap.org/?mlat={lat:.6f}&mlon={lon:.6f}")
        i += 8
    for bit, label, key in ((0x20, "Feature 1", "feature1"), (0x40, "Feature 2", "feature2")):
        if flags & bit:
            if len(app) < i + 2:
                sec.warn(f"appdata truncated: no {label}")
                return
            info[key] = struct.unpack_from("<H", app, i)[0]
            sec.row(label, f"0x{info[key]:04X}")
            i += 2
    if flags & 0x80:
        info["name"] = to_text(app[i:])
        sec.row("Name", info["name"])
    if info["sig_valid"] is not False:
        ring.add_contact(pub, info.get("name", ""))


def _group(pkt: Packet, p: bytes, ring: KeyRing, sec: Section) -> None:
    """channel_hash(1) MAC(2) ciphertext. GRP_TXT: как текстовое сообщение; GRP_DATA: type(2) len(1) data."""
    if len(p) < 3:
        pkt.fail(sec, "payload too short (need ≥ 3 B)")
        return
    ch_hash, mac, ct = p[0], p[1:3], p[3:]
    pkt.info["channel_hash"] = ch_hash
    sec.row("Channel hash", f"0x{ch_hash:02X}", "first byte of SHA256 of the channel key")
    plain = _crypto_rows(pkt, sec, mac, ct, ring.channel_keys(ch_hash),
                         f"no key with channel hash 0x{ch_hash:02X}",
                         "  Add the channel key: hex / base64 / #hashtag.")
    if plain is None:
        return
    pkt.info["channel"] = pkt.info.pop("key").lower()
    sec = pkt.section("Content")

    if pkt.ptype == PT_GRP_DATA:
        # Стандарт: type(2) len(1) data, хвост до 16 B — нули. Иначе формат чужого приложения: не разбираем.
        data_len = plain[2] if len(plain) >= 3 else -1
        if data_len < 0 or 3 + data_len > len(plain) or plain[3 + data_len:].strip(b"\0"):
            pkt.info["data"] = plain
            sec.row("Format", "non-standard", "not type(2) + len(1) + data; shown as is")
            _data_rows(sec, plain)
            return
        data_type = struct.unpack_from("<H", plain, 0)[0]
        data = plain[3:3 + data_len]
        pkt.info.update(data_type=data_type, data=data)
        sec.row("Data type", f"0x{data_type:04X}", grp_data_app(data_type))
        sec.row("Data len", f"{data_len} B")
        _data_rows(sec, data)
        return

    _text_message(pkt, sec, plain)
    if "text" not in pkt.info:
        return
    sender, text = split_sender(pkt.info["text"])
    pkt.info["text"] = text
    if sender:
        pkt.info["sender"] = sender
        sec.row("Sender", sender)
    sec.row("Message", text)


def _request(pkt: Packet, sec: Section, plain: bytes) -> None:
    """timestamp(4) req_type(1) параметры."""
    if len(plain) < 5:
        _data_rows(sec, plain)
        return
    ts, rt = struct.unpack_from("<IB", plain, 0)
    rest = plain[5:]
    pkt.info.update(timestamp=ts, req_type=rt)
    sec.row("Timestamp", fmt_ts(ts))
    sec.row("Request type", f"0x{rt:02X} = {REQ_TYPES.get(rt, 'unknown')}")
    if rt == 0x03 and rest:
        sec.row("Permission mask", f"0x{rest[0]:02X}", "0 = all telemetry values")
    elif rt == 0x04 and len(rest) >= 8:
        start, end = struct.unpack_from("<II", rest, 0)
        sec.row("Range", f"{start} s .. {end} s ago")
    elif rt == 0x08 and len(rest) >= 8:
        tag, timeout, _, n = struct.unpack_from("<IHBB", rest, 0)
        sec.row("Push tag", f"0x{tag:08X}")
        sec.row("Timeout", f"{timeout} s")
        sec.row("Min deltas (LPP)", rest[8:8 + n].hex() or "—")
    elif rt in (0x02, 0x05, 0x09):
        pass
    elif rest.strip(b"\0"):
        _data_rows(sec, rest, "Params")


def _returned_path(pkt: Packet, sec: Section, plain: bytes) -> None:
    """path_len(1) path extra_type(1) extra."""
    n = plain[0]
    size, count = (n >> 6) + 1, n & 0x3F
    path = plain[1:1 + size * count]
    route = hop_chunks(path, size)
    pkt.info["return_path"] = route
    sec.row("Path len", f"0x{n:02X}", f"{count} hops × {size} B")
    sec.row("Return path", " → ".join(route) or "—")
    rest = plain[1 + size * count:]
    if not rest.strip(b"\0"):
        return
    et = rest[0]
    pkt.info["extra_type"] = et
    sec.row("Extra type", f"0x{et:02X}", PAYLOAD_TYPES.get(et, "unknown"))
    if et == PT_ACK and len(rest) >= 5:
        sec.row("ACK checksum", rest[1:5].hex())
    else:
        _data_rows(sec, rest[1:], "Extra data")


def _direct(pkt: Packet, p: bytes, ring: KeyRing, sec: Section) -> None:
    """REQ / RESPONSE / TXT_MSG / PATH: dst(1) src(1) MAC(2) ciphertext."""
    if len(p) >= 2:
        pkt.info.update(dst=p[0], src=p[1])
    if len(p) < 4:
        pkt.fail(sec, "payload too short (need ≥ 4 B)")
        return
    dst, src, mac, ct = p[0], p[1], p[2:4], p[4:]
    sec.row("Dest hash", f"0x{dst:02X}", "recipient")
    sec.row("Src hash", f"0x{src:02X}", "sender")
    hint = ("  Direct messages are encrypted with the ECDH secret of two nodes.\n"
            "  Give your private key (prv:...) and the peer's public key (pub:...),\n"
            "  or the 32-byte shared secret (64 hex chars).")
    plain = _crypto_rows(pkt, sec, mac, ct, ring.direct_keys(dst, src), "no keys", hint)
    if plain is None:
        return
    sec = pkt.section("Content")
    if pkt.ptype == PT_TXT_MSG:
        _text_message(pkt, sec, plain)
        if "text" in pkt.info:
            sec.row("Message", pkt.info["text"])
    elif pkt.ptype == PT_REQ:
        _request(pkt, sec, plain)
    elif pkt.ptype == PT_RESPONSE and len(plain) >= 4:
        tag = struct.unpack_from("<I", plain, 0)[0]
        pkt.info.update(tag=tag, data=plain[4:])
        sec.row("Tag", fmt_ts(tag), "usually the request timestamp")
        _data_rows(sec, plain[4:])
    elif pkt.ptype == PT_PATH and plain:
        _returned_path(pkt, sec, plain)
    else:
        pkt.info["data"] = plain
        _data_rows(sec, plain)


def _anon_content(pkt: Packet, sec: Section, plain: bytes) -> None:
    """timestamp(4), дальше по догадке: запрос к репитеру, вход в комнату или вход на репитер/сенсор."""
    if len(plain) < 4:
        _data_rows(sec, plain)
        return
    ts = struct.unpack_from("<I", plain, 0)[0]
    pkt.info["timestamp"] = ts
    sec.row("Timestamp", fmt_ts(ts))
    rest = plain[4:].rstrip(b"\0")
    if len(rest) >= 2 and rest[0] in ANON_REQ_TYPES:
        n = rest[1]
        size, count = (n >> 6) + 1, n & 0x3F
        if 2 + size * count <= len(rest):
            name = ANON_REQ_TYPES[rest[0]]
            pkt.info.update(req_type=rest[0], text=f"request {name}")
            sec.row("Request type", f"0x{rest[0]:02X} = {name}", "repeater request")
            sec.row("Reply path", " → ".join(hop_chunks(rest[2:2 + size * count], size)) or "—",
                    f"{count} hops × {size} B")
            return
    password = printable_text(rest)
    if password is not None:
        pkt.info["text"] = f"login, password: {password}"
        sec.row("Login", "repeater / sensor", "guess by format")
        sec.row("Password", password)
        return
    password = printable_text(rest[4:]) if len(rest) > 4 else None
    if password is not None:
        sync = struct.unpack_from("<I", rest, 0)[0]
        pkt.info["text"] = f"room login, password: {password}"
        sec.row("Login", "room server", "guess by format")
        sec.row("Sync since", fmt_ts(sync))
        sec.row("Password", password)
        return
    pkt.info["data"] = plain[4:]
    _data_rows(sec, plain[4:])


def _anon(pkt: Packet, p: bytes, ring: KeyRing, sec: Section) -> None:
    """dst(1) sender_pubkey(32) MAC(2) ciphertext."""
    if len(p) >= 1:
        pkt.info["dst"] = p[0]
    if len(p) >= 33:
        pkt.info["sender_pub"] = p[1:33].hex()
    if len(p) < 35:
        pkt.fail(sec, "payload too short (need ≥ 35 B)")
        return
    dst, pub, mac, ct = p[0], p[1:33], p[33:35], p[35:]
    ring.add_contact(pub)
    sec.row("Dest hash", f"0x{dst:02X}", "recipient")
    sec.row("Sender pubkey", pub.hex())
    sec.row("Sender hash", f"0x{pub[0]:02X}")
    hint = "  Needs the recipient's private key (prv:...) or the 32-byte shared secret."
    plain = _crypto_rows(pkt, sec, mac, ct, ring.anon_keys(dst, pub), "no keys", hint)
    if plain is not None:
        _anon_content(pkt, pkt.section("Content"), plain)


def _ack(pkt: Packet, p: bytes, ring: KeyRing, sec: Section) -> None:
    if len(p) < 4:
        pkt.fail(sec, "ACK shorter than 4 B")
        return
    pkt.info["checksum"] = p[:4].hex()
    sec.row("ACK checksum", p[:4].hex())
    if len(p) > 4:
        sec.warn(f"extra bytes after checksum: {p[4:].hex()}")


def _trace(pkt: Packet, p: bytes, ring: KeyRing, sec: Section) -> None:
    """tag(4) auth(4) flags(1) хэши узлов маршрута; SNR по хопам — в path пакета."""
    if len(p) < 9:
        pkt.fail(sec, "payload too short (need ≥ 9 B)")
        return
    tag, auth, flags = struct.unpack_from("<IIB", p, 0)
    size = 1 << (flags & 3)
    route = hop_chunks(p[9:], size)
    pkt.info.update(tag=tag, auth=auth, route=route, snr=pkt.trace_snr or [])
    sec.row("Tag", f"0x{tag:08X}")
    sec.row("Auth code", f"0x{auth:08X}")
    sec.row("Flags", f"0x{flags:02X}", f"node hash size {size} B")
    sec.row("Trace route", " → ".join(route) or "—", f"{len(route)} nodes")


def _multipart(pkt: Packet, p: bytes, ring: KeyRing, sec: Section) -> None:
    if not p:
        pkt.fail(sec, "empty payload")
        return
    inner = p[0] & 0x0F
    pkt.info.update(remaining=p[0] >> 4, inner_type=inner)
    sec.row("Remaining parts", p[0] >> 4)
    sec.row("Inner type", PAYLOAD_TYPES.get(inner, f"0x{inner:X}"))
    sec.row("Data (hex)", p[1:].hex())


def _control(pkt: Packet, p: bytes, ring: KeyRing, sec: Section) -> None:
    """flags(1): старшие 4 бита — подтип; дальше данные подтипа (не шифруются)."""
    if not p:
        pkt.fail(sec, "empty payload")
        return
    sub = p[0] >> 4
    name = CONTROL_SUBTYPES.get(sub, f"0x{sub:X}")
    pkt.info["subtype"] = name
    if sub == 0x8 and len(p) >= 6:
        mask = p[1]
        kinds = [NODE_TYPES.get(b, str(b)) for b in range(8) if mask & (1 << b)]
        pkt.info.update(tag=p[2:6].hex(), type_filter=kinds)
        sec.row("Subtype", name)
        sec.row("Prefix only", p[0] & 1)
        sec.row("Type filter", f"0x{mask:02X}", ", ".join(kinds) or "—")
        sec.row("Tag", p[2:6].hex())
        if len(p) >= 10:
            since = struct.unpack_from("<I", p, 6)[0]
            pkt.info["since"] = since
            sec.row("Since", fmt_ts(since))
    elif sub == 0x9 and len(p) >= 6:
        snr = _s8(p[1]) / 4
        node_type = p[0] & 0x0F
        pkt.info.update(node_type=node_type, snr=snr, tag=p[2:6].hex(), pubkey=p[6:].hex())
        sec.row("Subtype", name)
        sec.row("Node type", NODE_TYPES.get(node_type, f"unknown({node_type})"))
        sec.row("SNR", f"{snr:+.2f} dB", "as heard by the responder")
        sec.row("Tag", p[2:6].hex())
        sec.row("Public key", p[6:].hex(), f"{len(p) - 6} B")
    else:
        sec.row("Subtype", name, "not decoded")
        sec.row("Data (hex)", p.hex())


def _custom(pkt: Packet, p: bytes, ring: KeyRing, sec: Section) -> None:
    sec.row("Payload (hex)", p.hex())
    t = printable_text(p)
    if t is not None:
        pkt.info["text"] = t
        sec.row("Payload (text)", t)


_DECODERS = {
    PT_ADVERT: _advert, PT_GRP_TXT: _group, PT_GRP_DATA: _group, PT_ANON_REQ: _anon,
    PT_ACK: _ack, PT_TRACE: _trace, PT_MULTIPART: _multipart, PT_CONTROL: _control,
    PT_RAW_CUSTOM: _custom, **{p: _direct for p in DIRECT_PTYPES},
}


# ───────────────────────────── Разбор пакета ─────────────────────────────

def _parse_header(pkt: Packet) -> None:
    """header(1) [transport codes(4) для route 0 и 3] path_len(1) path(hops * hash_size) payload."""
    raw = pkt.raw
    sec = pkt.section(f"Header (packet {len(raw)} B)")
    if len(raw) < 2:
        pkt.error = "empty packet" if not raw else "packet too short"
        sec.warn(pkt.error)
        return
    hdr = raw[0]
    pkt.header, pkt.route, pkt.ptype, pkt.version = hdr, hdr & 3, (hdr >> 2) & 0x0F, hdr >> 6
    sec.row("Header", f"0x{hdr:02X}", f"{hdr:08b}")
    sec.row("Route type", f"{pkt.route} = {pkt.route_name}")
    sec.row("Payload type", f"0x{pkt.ptype:02X} = {PAYLOAD_TYPES.get(pkt.ptype, 'reserved')}")
    sec.row("Payload version", f"v{pkt.version + 1}")
    if pkt.version:
        pkt.invalid.append(f"payload version v{pkt.version + 1}")
        sec.warn(f"payload version v{pkt.version + 1} is not defined yet; decoded as v1")

    sec = pkt.section("Route")
    i = 1
    if pkt.route in (0, 3):
        if len(raw) < 5:
            pkt.error = "truncated: no transport codes"
            sec.warn(pkt.error)
            return
        pkt.transport = struct.unpack_from("<HH", raw, 1)
        sec.row("Transport codes", "0x{:04X}, 0x{:04X}".format(*pkt.transport), "region scope, reserved")
        i = 5
    if i >= len(raw):
        pkt.error = "truncated: no path_len"
        sec.warn(pkt.error)
        return
    pkt.path_len = raw[i]
    pkt.hops, pkt.hash_size = pkt.path_len & 0x3F, (pkt.path_len >> 6) + 1
    plen = pkt.hops * pkt.hash_size
    sec.row("Path len byte", f"0x{pkt.path_len:02X}", f"{pkt.hops} hops × {pkt.hash_size} B = {plen} B")
    if pkt.hash_size == 4:
        pkt.invalid.append("hash size 4 B")
        sec.warn("hash size 4 B is reserved")
    if plen > MAX_PATH_SIZE:
        pkt.invalid.append("path too long")
        sec.warn(f"path {plen} B > {MAX_PATH_SIZE} B (MAX_PATH_SIZE)")
    pkt.path = raw[i + 1:i + 1 + plen]
    if len(pkt.path) < plen:
        pkt.error = "truncated inside path"
        sec.warn(pkt.error)
        return
    snr = pkt.trace_snr
    if snr is not None:
        sec.row("SNR per hop", ", ".join(f"{s:+.2f}" for s in snr) or "—", "dB; TRACE collects SNR of each hop")
    else:
        sec.row("Path", " → ".join(pkt.hop_list) or "— (empty)",
                "nodes passed" if pkt.is_flood else "remaining route")
    pkt.payload = raw[i + 1 + plen:]
    tsz = "transport 4 + " if pkt.transport else ""
    sec.row("Structure", f"header 1 + {tsz}path_len 1 + path {plen} + payload {len(pkt.payload)} = {len(raw)} B")
    sec.row("Packet hash", pkt.packet_hash.hex(), "ID for deduplication")
    if len(pkt.payload) > MAX_PAYLOAD:
        sec.warn(f"payload {len(pkt.payload)} B > {MAX_PAYLOAD} B (MAX_PACKET_PAYLOAD)")
    if not pkt.payload:
        pkt.error = "empty payload"
        sec.warn(pkt.error)


def decode_packet(raw: bytes, ring: KeyRing) -> Packet:
    """Полный разбор пакета. Ошибки не бросаются: см. Packet.error / Packet.invalid и секции."""
    pkt = Packet(raw)
    _parse_header(pkt)
    if pkt.error:
        return pkt
    p = pkt.payload
    sec = pkt.section(f"Payload: {PAYLOAD_TYPES.get(pkt.ptype, f'reserved 0x{pkt.ptype:02X}')} ({len(p)} B)")
    decoder = _DECODERS.get(pkt.ptype)
    if decoder is None:
        pkt.invalid.append(f"reserved payload type 0x{pkt.ptype:02X}")
        _custom(pkt, p, ring, sec)
    else:
        decoder(pkt, p, ring, sec)
    pkt.kind = _KIND_BY_PTYPE[pkt.ptype] if pkt.valid else "raw"
    return pkt


def describe_kind(pkt: Packet) -> str:
    """Тип для фильтров с состоянием расшифровки: 'message, decrypted', 'raw: <причина>'."""
    if pkt.kind == "raw":
        return "raw: " + ", ".join(([pkt.error] if pkt.error else []) + pkt.invalid)
    if pkt.decrypted is None:
        return pkt.kind
    return f"{pkt.kind}, " + ("decrypted" if pkt.decrypted else "no key")
