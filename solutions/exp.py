#!/usr/bin/env python3
"""MioCrypt 爆破 EXP：恢复已知密钥字节，枚举最后一字节并打印所有正则候选。"""

from __future__ import annotations

import argparse
import re
from pathlib import Path


# ------------------------------ 文件格式常量 ------------------------------
#
# 加密文件为：
#     8 字节魔数 || 256 字节 RSA 密文 || 循环 XOR 密文
#
# RSA 段只是用来包装 XOR 会话密钥的烟雾弹；本 EXP 不尝试解析或攻击它，
# 而是直接跳过这 256 字节，从后面的 XOR 数据区开始处理。
MAGIC = b"MIOCRYPT"
RSA_CIPHERTEXT_SIZE = 256
XOR_PAYLOAD_OFFSET = len(MAGIC) + RSA_CIPHERTEXT_SIZE  # 8 + 256 = 264 = 0x108

# 题目名称给出的已知明文。它恰好只有 7 字节，而 XOR 密钥有 8 字节。
# 因此 K[0]..K[6] 可直接恢复，K[7] 只能枚举 0x00..0xFF。
KNOWN_PREFIX = b"PKWCTF{"
KEY_SIZE = 8

# 正则只约束 flag 外观，不负责判断语义。故它可能保留多个候选，这正是
# 本题希望选手观察并手动判断的部分。
FLAG_PATTERN = re.compile(rb"^PKWCTF\{[A-Za-z0-9_]+\}$")

def xor_with_repeating_key(ciphertext: bytes, key: bytes) -> bytes:
    """用循环 XOR 密钥解密或加密数据。

    XOR 是可逆的：C = P XOR K，因此 P = C XOR K。密钥只有 8 字节，
    第 i 个密文使用 key[i % 8]，所以同一密钥字节会影响每隔 8 字节的
    所有位置。
    """

    return bytes(
        encrypted_byte ^ key[index % len(key)]
        for index, encrypted_byte in enumerate(ciphertext)
    )


def read_xor_payload(encrypted_path: Path) -> bytes:
    """读取并校验加密文件，返回位于偏移 0x108 的 XOR 数据区。"""

    encrypted_file = encrypted_path.read_bytes()

    if not encrypted_file.startswith(MAGIC):
        raise ValueError(
            "文件前 8 字节不是 MIOCRYPT；请确认传入的是已加密的 flag。"
        )
    if len(encrypted_file) <= XOR_PAYLOAD_OFFSET:
        raise ValueError("文件没有 XOR 数据区，无法继续。")

    return encrypted_file[XOR_PAYLOAD_OFFSET:]


def recover_first_seven_key_bytes(ciphertext: bytes) -> bytes:
    """使用已知明文 PKWCTF{ 恢复 K[0] 至 K[6]。

    对每个已知位置 i：
        C[i] = P[i] XOR K[i]
        K[i] = C[i] XOR P[i]

    KNOWN_PREFIX 长度为 7，故这里不会触及仍未知的 K[7]。
    """

    if len(ciphertext) < len(KNOWN_PREFIX):
        raise ValueError("XOR 数据区短于已知 flag 前缀。")

    return bytes(
        ciphertext[index] ^ KNOWN_PREFIX[index]
        for index in range(len(KNOWN_PREFIX))
    )


def brute_force_last_key_byte(ciphertext: bytes, known_key_bytes: bytes) -> list[tuple[bytes, bytes]]:
    """枚举 K[7] 的 256 种取值，返回所有匹配 flag 正则的 (key, plaintext)。

    注意：此函数故意只以正则筛选，不在此处加入任何语义关键词。
    这样调用方可以完整看到所有通过格式检查的候选，避免“EXP 偷偷替人
    做语义判断”。
    """

    if len(known_key_bytes) != KEY_SIZE - 1:
        raise ValueError("已恢复的密钥前缀长度应为 7 字节。")

    candidates: list[tuple[bytes, bytes]] = []
    for last_key_byte in range(256):
        # 拼出 K[0]..K[7]。这是唯一需要暴力枚举的未知量。
        key = known_key_bytes + bytes([last_key_byte])
        plaintext = xor_with_repeating_key(ciphertext, key)

        # fullmatch 同时确认固定前缀、右花括号以及内部字符集。
        if FLAG_PATTERN.fullmatch(plaintext):
            candidates.append((key, plaintext))

    return candidates


def show_all_candidates(candidates: list[tuple[bytes, bytes]]) -> None:
    """按枚举顺序打印全部正则候选。

    这里有意只输出候选 flag 本身。EXP 不负责根据可读性或题意替选手
    作判断；多个候选之间的人工推理应由选手自行完成。
    """

    print("=" * 72)
    print(f"符合正则 {FLAG_PATTERN.pattern.decode('ascii')} 的全部候选：{len(candidates)} 个")
    print("=" * 72)
    for number, (_, plaintext) in enumerate(candidates, start=1):
        print(f"[{number:02d}] {plaintext.decode('ascii')}")


def main() -> None:
    """解析命令行、恢复 7 字节密钥、枚举最后 1 字节并输出结果。"""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("encrypted_flag", type=Path, help="加密后的 flag 文件路径")
    args = parser.parse_args()

    ciphertext = read_xor_payload(args.encrypted_flag)
    known_key_bytes = recover_first_seven_key_bytes(ciphertext)
    candidates = brute_force_last_key_byte(ciphertext, known_key_bytes)

    if not candidates:
        raise SystemExit("没有候选通过 flag 正则；请检查文件、魔数或 flag 格式。")

    # 到此为止：EXP 只负责列出正则候选，不进行任何额外判断。
    show_all_candidates(candidates)


if __name__ == "__main__":
    main()
