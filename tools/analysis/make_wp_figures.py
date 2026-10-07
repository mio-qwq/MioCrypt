from __future__ import annotations

import re
import os
import subprocess
import sys
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont


ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / "docs" / "writeup" / "images"
OUT.mkdir(parents=True, exist_ok=True)

FONT_DIR = Path(os.environ.get("WINDIR", r"C:\Windows")) / "Fonts"
FONT_CJK = FONT_DIR / "msyh.ttc"
FONT_MONO = FONT_DIR / "consola.ttf"
BG = "#0b1020"
PANEL = "#131c31"
PANEL_ALT = "#18243c"
TEXT = "#edf3ff"
MUTED = "#a8b6d0"
CYAN = "#67d9ff"
PURPLE = "#b9a1ff"
GREEN = "#7df0bd"
AMBER = "#ffc978"
LINE = "#2b3a58"


def font(size: int, mono: bool = False) -> ImageFont.FreeTypeFont:
    return ImageFont.truetype(str(FONT_MONO if mono else FONT_CJK), size)


def make_canvas(width: int, height: int, title: str, subtitle: str) -> tuple[Image.Image, ImageDraw.ImageDraw]:
    image = Image.new("RGB", (width, height), BG)
    draw = ImageDraw.Draw(image)
    draw.rounded_rectangle((36, 32, width - 36, height - 32), radius=28, fill=PANEL, outline=LINE, width=2)
    draw.rounded_rectangle((64, 58, 78, 112), radius=7, fill=CYAN)
    draw.text((102, 56), title, font=font(42), fill=TEXT)
    draw.text((104, 113), subtitle, font=font(23), fill=MUTED)
    return image, draw


def panel(draw: ImageDraw.ImageDraw, box: tuple[int, int, int, int], fill: str = PANEL_ALT) -> None:
    draw.rounded_rectangle(box, radius=18, fill=fill, outline=LINE, width=2)


def save(image: Image.Image, name: str) -> None:
    image.save(OUT / name, optimize=True)


def pe_triage() -> None:
    image, draw = make_canvas(1600, 620, "DIE · 样本初筛", "数据来源：diec.exe -j dist\\MioCrypt.exe；下面是输出字段的排版摘要")
    cards = [
        ("文件类型", "PE64", CYAN),
        ("编译器", "Microsoft Visual C/C++", PURPLE),
        ("编译器版本", "19.36.36256", TEXT),
        ("链接器", "Microsoft Linker 14.36.36256", TEXT),
        ("工具链", "Visual Studio 2022 · 17.6", GREEN),
    ]
    x0, y0, gap = 78, 214, 20
    widths = [450, 450, 450]
    positions = [(x0, y0), (x0 + widths[0] + gap, y0), (x0 + 2 * (widths[0] + gap), y0),
                 (x0 + 140, y0 + 158), (x0 + 710, y0 + 158)]
    for (label, value, accent), (x, y) in zip(cards, positions):
        w = 450 if y == y0 else 450
        panel(draw, (x, y, x + w, y + 126))
        draw.text((x + 24, y + 18), label, font=font(21), fill=MUTED)
        draw.text((x + 24, y + 58), value, font=font(25), fill=accent)
    draw.text((82, 531), "初筛结论：原生 Windows x64 程序；后续直接查看入口与加密相关函数。", font=font(21), fill=TEXT)
    save(image, "01_die_triage.png")


def file_layout() -> None:
    image, draw = make_canvas(1800, 690, "加密文件布局", "对工作目录 dist\\flag 的字节检查：总长 299 bytes（0x12B）")
    x0, y, h = 82, 232, 190
    widths = [300, 820, 470]
    labels = [
        ("0x000 – 0x007", "8 bytes", "MIOCRYPT", CYAN),
        ("0x008 – 0x107", "256 bytes", "RSA-2048 / OAEP-SHA-256", PURPLE),
        ("0x108 – 0x12A", "35 bytes", "循环 XOR 正文", GREEN),
    ]
    x = x0
    for index, ((offset, size, label, color), w) in enumerate(zip(labels, widths)):
        panel(draw, (x, y, x + w, y + h), fill="#17233b" if index % 2 == 0 else "#1c2741")
        draw.rounded_rectangle((x + 18, y + 18, x + w - 18, y + 27), radius=5, fill=color)
        draw.text((x + 24, y + 52), offset, font=font(24, mono=True), fill=TEXT)
        draw.text((x + 24, y + 91), size, font=font(25), fill=color)
        draw.text((x + 24, y + 133), label, font=font(21), fill=MUTED)
        x += w + 18
    draw.text((86, 462), "文件头实际字节", font=font(21), fill=MUTED)
    draw.text((86, 501), "4d 49 4f 43 52 59 50 54", font=font(27, mono=True), fill=CYAN)
    draw.text((86, 551), " M  I  O  C  R  Y  P  T", font=font(22, mono=True), fill=TEXT)
    draw.text((920, 486), "0x108 = 8 + 256 = 264", font=font(28, mono=True), fill=AMBER)
    draw.text((920, 537), "正文长度不变：加密文件 = 8 + 256 + 35 = 299 bytes", font=font(22), fill=TEXT)
    save(image, "02_file_layout.png")


def known_plaintext() -> None:
    image, draw = make_canvas(1800, 790, "已知明文恢复密钥", "对当前 dist\\flag 样本的逐字节复核；重新加密后随机会话密钥会变化")
    panel(draw, (80, 211, 1720, 412))
    draw.text((112, 235), "明文前缀 P", font=font(22), fill=MUTED)
    draw.text((112, 277), "PKWCTF{", font=font(34, mono=True), fill=TEXT)
    draw.text((550, 235), "XOR 正文 C 的前 7 字节", font=font(22), fill=MUTED)
    draw.text((550, 277), "5a f2 da af 62 8f ae", font=font(31, mono=True), fill=CYAN)
    draw.text((1090, 235), "K[0..6] = C XOR P", font=font(22), fill=MUTED)
    draw.text((1090, 277), "0a b9 8d ec 36 c9 d5", font=font(31, mono=True), fill=GREEN)
    draw.text((112, 355), "C[i] = P[i] XOR K[i mod 8]    =>    K[i] = C[i] XOR P[i]", font=font(25, mono=True), fill=PURPLE)
    panel(draw, (80, 438, 1720, 665), fill="#17233b")
    draw.text((112, 461), "第 8 个密钥字节仍未知，只需枚举 0x00–0xFF。它会影响正文下标 7、15、23、31：", font=font(22), fill=TEXT)
    checks = [
        ("C[7]   0x62 XOR 'z'", "= 0x18"),
        ("C[15]  0x77 XOR 'o'", "= 0x18"),
        ("C[23]  0x77 XOR 'o'", "= 0x18"),
        ("C[31]  0x53 XOR 'K'", "= 0x18"),
    ]
    for i, (left, right) in enumerate(checks):
        x = 116 + (i % 2) * 790
        y = 515 + (i // 2) * 68
        draw.text((x, y), left, font=font(24, mono=True), fill=AMBER)
        draw.text((x + 470, y), right, font=font(24, mono=True), fill=GREEN)
    draw.text((112, 690), "四处反推一致，因此当前样本的 K[7] = 0x18；前 7 字节来自已知前缀。", font=font(21), fill=MUTED)
    save(image, "03_known_plaintext.png")


def exp_candidates() -> None:
    command = [sys.executable, str(ROOT / "solutions" / "exp.py"), str(ROOT / "dist" / "flag")]
    child_env = os.environ.copy()
    child_env["PYTHONIOENCODING"] = "utf-8"
    result = subprocess.run(command, check=True, capture_output=True, text=True, encoding="utf-8", env=child_env)
    lines = result.stdout.splitlines()
    candidates = [line for line in lines if re.match(r"\[\d+\] PKWCTF\{", line)]
    if len(candidates) != 33:
        raise RuntimeError(f"Expected the current sample to produce 33 candidates; got {len(candidates)}")

    image, draw = make_canvas(2000, 1120, "EXP · 33 个格式候选", "以下候选来自 python solutions\\exp.py dist\\flag；EXP 只按 flag 正则筛选")
    panel(draw, (78, 205, 1922, 1044))
    left_x, right_x, start_y, row_h = 112, 1050, 245, 43
    mono = font(22, mono=True)
    for index, line in enumerate(candidates):
        column = 0 if index < 17 else 1
        row = index if index < 17 else index - 17
        x = left_x if column == 0 else right_x
        y = start_y + row * row_h
        selected = line.startswith("[14]")
        if selected:
            draw.rounded_rectangle((x - 12, y - 5, x + 835, y + 34), radius=8, fill="#194638", outline=GREEN, width=2)
        draw.text((x, y), line, font=mono, fill=GREEN if selected else TEXT)
    draw.text((112, 1057), "第 14 项不是按枚举顺序“自动正确”：要结合题面里的 Mio / 杂鱼线索判断可读语义。", font=font(21), fill=MUTED)
    save(image, "04_exp_candidates.png")


def ida_excerpt() -> None:
    image, draw = make_canvas(1800, 720, "IDA · 反编译定位到循环 XOR", "IDA Pro 9.2 CLI + 同名 PDB；摘录自 XorEncryptInPlace / EncryptFlagFile")
    panel(draw, (82, 208, 1718, 610))
    lines = [
        ("for (index = 0; index < plaintext->length; ++index)", CYAN),
        ("    plaintext->data[index] ^= sessionKey[index % 8];", GREEN),
        ("", TEXT),
        ("encryptedFile.length = encryptedSessionKey.length", MUTED),
        ("                       + plaintext.length + 8;", MUTED),
        ("memmove(encryptedFile.data, kMagic, 8);", PURPLE),
        ("memmove(encryptedFile.data + 8, encryptedSessionKey.data, encryptedSessionKey.length);", PURPLE),
        ("memmove(encryptedFile.data + 8 + encryptedSessionKey.length, plaintext.data, plaintext.length);", PURPLE),
    ]
    y = 248
    for text, color in lines:
        draw.text((125, y), text, font=font(24, mono=True), fill=color)
        y += 43
    draw.text((84, 635), "关键观察：RSA 只包装 8 字节会话密钥；正文每隔 8 字节重复使用同一密钥字节。", font=font(21), fill=MUTED)
    save(image, "05_ida_xor_excerpt.png")


def theme_clue() -> None:
    source = Image.open(ROOT / "assets" / "mio-ransomware-bg-denoised.png").convert("RGB")
    crop = source.crop((18, 270, 210, 710))
    image = Image.new("RGB", (600, 560), BG)
    draw = ImageDraw.Draw(image)
    draw.rounded_rectangle((18, 18, 582, 542), radius=22, fill=PANEL, outline=LINE, width=2)
    crop.thumbnail((260, 385))
    x = (600 - crop.width) // 2
    y = 38 + (450 - crop.height) // 2
    image.paste(crop, (x, y))
    draw.text((70, 492), "程序内嵌背景素材中的「杂鱼」提示", font=font(21), fill=TEXT)
    save(image, "06_theme_clue.png")


if __name__ == "__main__":
    pe_triage()
    file_layout()
    known_plaintext()
    exp_candidates()
    ida_excerpt()
    theme_clue()
    print(f"Created 6 evidence figures in {OUT}")
