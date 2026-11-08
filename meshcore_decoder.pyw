#!/usr/bin/env python3
"""MeshCore raw packet decoder: подробный разбор одного пакета.

GUI:  python meshcore_decoder.pyw [-k SPEC ...] [--keys-file FILE] [--private-key HEX]
      (--keys-file mesh_contacts.txt — контакты, сохранённые reader'ом)
CLI:  python meshcore_decoder.pyw <HEX|BASE64> [-k SPEC ...] [--keys-file FILE] [--private-key HEX] [--no-public]

SPEC — ключ в формате meshcore_proto.KeyRing:
  public, #name, <32 hex> (ключ канала без имени), name:<key>, <64 hex> (общий секрет),
  prv:<hex> (свой приватный ключ), pub:[name:]<hex> (публичный ключ контакта); вместо hex можно base64.
Ключи из командной строки при запуске GUI подставляются в его поля.

Dragon_Knight при поддержке Claude (Anthropic)
"""

import argparse
import base64
import binascii
import re
import sys

from meshcore_proto import HAVE_AES, INSTALL_HINT, VERSION, KeyRing, decode_packet, describe_kind

LABEL_WIDTH = 22


# ───────────────────────────── Ввод и вывод ─────────────────────────────

def read_input(text: str) -> bytes:
    """hex (с любыми разделителями и мусором вокруг) или base64."""
    s = text.strip()
    if not s:
        raise ValueError("empty input")
    c = re.sub(r"0x|[\s:,\-]", "", s, flags=re.I)
    if re.fullmatch(r"[0-9a-fA-F]+", c) and len(c) % 2 == 0:
        return bytes.fromhex(c)
    # строка с префиксами/мусором — берём самую длинную hex-последовательность
    runs = re.findall(r"(?:[0-9A-Fa-f]{2}[\s:,\-]?){4,}", s)
    if runs:
        c = re.sub(r"[^0-9a-fA-F]", "", max(runs, key=len))
        if len(c) % 2 == 0:
            return bytes.fromhex(c)
    try:
        return base64.b64decode(s, validate=True)
    except (binascii.Error, ValueError):
        raise ValueError("input is neither hex nor base64")


def render(raw: bytes, ring: KeyRing) -> str:
    lines = []
    pkt = decode_packet(raw, ring)
    pkt.sections[0].row("Filter type", describe_kind(pkt), "type for meshcore_reader_json rules")
    for sec in pkt.sections:
        lines.append(f"\n── {sec.title} " + "─" * max(3, 64 - len(sec.title)))
        for r in sec.rows:
            if r.status == "warn":
                lines.append(f"  ⚠ {r.value}")
            elif not r.label:
                lines.append(r.value)
            else:
                lines.append(f"{r.label:<{LABEL_WIDTH}}: {r.value}" + (f"   ({r.note})" if r.note else ""))
    return "\n".join(lines).lstrip("\n")


def build_ring(texts: list, file_specs: list = (), private_key: str = "", public: bool = True) -> KeyRing:
    """texts — строки с несколькими SPEC через пробел/запятую; file_specs — по SPEC на строку (имена с пробелами)."""
    ring = KeyRing(public=public)
    for spec in file_specs:
        ring.add(spec)
    for text in texts:
        ring.add_many(text)
    if private_key.strip():
        ring.add("prv:" + private_key.strip())
    return ring


def read_keys_file(path: str) -> list:
    with open(path, encoding="utf-8") as f:
        return [s.strip() for s in f.read().splitlines() if s.strip() and not s.strip().startswith("//")]


# ───────────────────────────── GUI ─────────────────────────────

def run_gui(specs: list, file_specs: list, keys_file: str, private_key: str, public: bool) -> None:
    import tkinter as tk
    from tkinter import messagebox, scrolledtext, ttk

    root = tk.Tk()
    root.title(f"MeshCore packet decoder v{VERSION}")
    root.geometry("940x800")
    if sys.platform.startswith("win"):
        mono = ("Consolas", 10)
    elif sys.platform == "darwin":
        mono = ("Menlo", 11)
    else:
        mono = ("DejaVu Sans Mono", 10)

    frm = ttk.Frame(root, padding=8)
    frm.pack(fill="both", expand=True)

    ttk.Label(frm, text="Raw packet (hex / base64):").pack(anchor="w")
    inp = scrolledtext.ScrolledText(frm, height=6, font=mono, wrap="char")
    inp.pack(fill="x")

    ttk.Label(frm, text="Keys: channel (hex, base64, #hashtag), shared secret, contacts pub:<hex> "
                        "— separated by comma or space:").pack(anchor="w", pady=(8, 0))
    key_var = tk.StringVar(value=" ".join(specs))
    ttk.Entry(frm, textvariable=key_var, font=mono).pack(fill="x")
    if keys_file:
        ttk.Label(frm, text=f"Keys file: {keys_file} ({len(file_specs)} keys)").pack(anchor="w")

    ttk.Label(frm, text="Own private key for ECDH (hex, 32 or 64 B):").pack(anchor="w", pady=(8, 0))
    prv_var = tk.StringVar(value=private_key)
    ttk.Entry(frm, textvariable=prv_var, font=mono, show="•").pack(fill="x")

    use_public = tk.BooleanVar(value=public)
    row = ttk.Frame(frm)
    row.pack(fill="x", pady=6)
    ttk.Checkbutton(row, text="Use Public channel key", variable=use_public).pack(side="left")

    outbox = scrolledtext.ScrolledText(frm, font=mono, wrap="none")
    for tag, color in (("ok", "#1a9c3c"), ("bad", "#d32f2f"), ("warn", "#c77700")):
        outbox.tag_config(tag, foreground=color)

    def colorize():
        for sym, tag in (("✔", "ok"), ("✘", "bad"), ("⚠", "warn")):
            idx = "1.0"
            while True:
                idx = outbox.search(sym, idx, "end")
                if not idx:
                    break
                end = f"{idx}+1c"
                outbox.tag_add(tag, idx, end)
                idx = end

    def do_decode(event=None):
        try:
            raw = read_input(inp.get("1.0", "end"))
            ring = build_ring([key_var.get()], file_specs, prv_var.get(), use_public.get())
            result = render(raw, ring)
        except Exception as e:
            messagebox.showerror("Error", str(e))
            return "break"
        outbox.delete("1.0", "end")
        outbox.insert("1.0", result)
        colorize()
        return "break"

    def clear():
        inp.delete("1.0", "end")
        outbox.delete("1.0", "end")

    ttk.Button(row, text="Decode (Ctrl+Enter)", command=do_decode).pack(side="right")
    ttk.Button(row, text="Clear", command=clear).pack(side="right", padx=6)
    root.bind("<Control-Return>", do_decode)

    outbox.pack(fill="both", expand=True)
    if not HAVE_AES:
        outbox.insert("1.0", f"⚠ For decryption, signature check and ECDH: {INSTALL_HINT}\n")
    root.mainloop()


# ───────────────────────────── CLI ─────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(description=f"MeshCore packet decoder v{VERSION} (no packet — GUI)")
    parser.add_argument("packet", nargs="*", help="packet in hex or base64 (spaces allowed)")
    parser.add_argument("-k", "--key", action="append", default=[], metavar="SPEC",
                        help="key: public, #name, <32 hex> channel key, name:<key>, <64 hex> shared secret, "
                             "pub:[name:]<hex> (repeatable)")
    parser.add_argument("--keys-file", metavar="FILE", help="file with keys, one SPEC per line")
    parser.add_argument("--private-key", default="", metavar="HEX", help="own private key for ECDH")
    parser.add_argument("--no-public", action="store_true", help="do not add the Public channel key")
    parser.add_argument("--version", action="version", version=VERSION)
    args = parser.parse_args()

    file_specs = read_keys_file(args.keys_file) if args.keys_file else []
    if not args.packet:
        run_gui(args.key, file_specs, args.keys_file, args.private_key, not args.no_public)
        return
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except (AttributeError, ValueError):
        pass
    ring = build_ring(args.key, file_specs, args.private_key, not args.no_public)
    print(render(read_input(" ".join(args.packet)), ring))


if __name__ == "__main__":
    main()
