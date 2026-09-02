#!/usr/bin/env python3
"""WOP Java SDK 手工变异测试（PIT 在本环境 minion 崩溃的替代方案，过渡门禁）。

对协议核心源码施加等价变异算子（对照 PIT 默认 mutators），逐个变异→编译→跑测试→
记录 killed/survived，计算变异击杀率。变异后源码恢复原样。

定位：CI PIT job（.github/workflows/ci.yml mutation 作业）在本环境外稳定跑通前的
过渡回归门禁；14 个变异点绑定源码文本快照，重构漂移会以 SKIP 报警（显性，非静默）。
终态：CI PIT 稳定后本脚本退役，回归锚点移交 pit-reports。

用法: python3 scripts/mutation-check.py
退出码: 0 = 14/14 全击杀；1 = 存在 SURVIVED/SKIP/TIMEOUT（任一均为门禁失败）。
"""
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CORE = ROOT / "wop-sdk-core"

# (相对 core 的源码路径, 旧串, 新串, 变异描述, mutator 类别)
MUTATIONS = [
    # --- 条件边界/反转（PIT: CONDITIONALS_BOUNDARY / NEGATE_CONDITIONALS）---
    ("src/main/java/com/wanlianyida/wop/crypto/Codec.java",
     "if (length % 4 == 1)", "if (length % 4 == 0)",
     "b64UrlDecode 长度校验 %4==1 → %4==0", "CONDITIONALS_BOUNDARY"),
    ("src/main/java/com/wanlianyida/wop/crypto/Codec.java",
     "if (data == null) {\n            return \"\";",
     "if (data != null) {\n            return \"\";",
     "hexLower null 检查取反", "NEGATE_CONDITIONALS"),
    ("src/main/java/com/wanlianyida/wop/crypto/DekPayload.java",
     "if (segments.length != 3)", "if (segments.length == 3)",
     "DEK 三段校验反转", "NEGATE_CONDITIONALS"),
    ("src/main/java/com/wanlianyida/wop/WopClient.java",
     "if (level == SecurityLevel.L2)", "if (level != SecurityLevel.L2)",
     "buildRequest L2 分支反转", "NEGATE_CONDITIONALS"),
    # --- 数学运算（PIT: MATH）---
    ("src/main/java/com/wanlianyida/wop/crypto/Codec.java",
     "int v = data[i] & 0xFF;", "int v = data[i] & 0xFE;",
     "hexLower 掩码 0xFF → 0xFE", "MATH"),
    ("src/main/java/com/wanlianyida/wop/crypto/Codec.java",
     "out[i * 2] = HEX[v >>> 4];", "out[i * 2] = HEX[(v >>> 4) + 1];",
     "hexLower 高半字节偏移", "MATH"),
    # --- 逻辑取反（PIT: NEGATE_CONDITIONALS / REMOVE_CONDITIONALS）---
    ("src/main/java/com/wanlianyida/wop/WopClient.java",
     "if (hasBody && (lower.get(HEADER_DIGEST) == null || lower.get(HEADER_DIGEST).trim().isEmpty()))",
     "if (hasBody || (lower.get(HEADER_DIGEST) == null || lower.get(HEADER_DIGEST).trim().isEmpty()))",
     "verifyInbound digest 缺失判定 && → ||", "NEGATE_CONDITIONALS"),
    ("src/main/java/com/wanlianyida/wop/crypto/Codec.java",
     "return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_';",
     "return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || false;",
     "isB64UrlChar 下划线分支删除", "REMOVE_CONDITIONALS"),
    ("src/main/java/com/wanlianyida/wop/crypto/Codec.java",
     "if (text == null || text.length() != 64) {\n            return false;\n        }",
     "if (text == null || text.length() != 64) {\n            return true;\n        }",
     "isLowerHex64 非法长度返回取反", "RETURN_VALS"),
    # --- 返回值/常量（PIT: RETURN_VALS / INLINE_CONSTANT）---
    ("src/main/java/com/wanlianyida/wop/crypto/ContentDigest.java",
     "suite.digestLabel() + \" \" + Codec.hexLower",
     "suite.digestLabel() + \"  \" + Codec.hexLower",
     "digest 前缀双空格", "INLINE_CONSTANT"),
    ("src/main/java/com/wanlianyida/wop/crypto/EncryptHeader.java",
     "\"L2;dek=\"", "\"L1;dek=\"",
     "encrypt 头级别常量", "INLINE_CONSTANT"),
    ("src/main/java/com/wanlianyida/wop/WopClient.java",
     "return new RequestDraft(upperMethod, path, headers, wireBody);",
     "return new RequestDraft(upperMethod, path, headers, new byte[0]);",
     "buildRequest wireBody 返回空数组", "RETURN_VALS"),
    # --- 空返回/移除（PIT: EMPTY_RETURNS）---
    ("src/main/java/com/wanlianyida/wop/crypto/Codec.java",
     "return B64URL.encodeToString(data);",
     "return \"\";",
     "b64UrlEncode 返回空串", "EMPTY_RETURNS"),
    # --- 字符串/成员变异 ---
    ("src/main/java/com/wanlianyida/wop/crypto/CanonicalRequest.java",
     "return (authString == null ? \"\" : authString) + \"\\n\"",
     "return (authString == null ? \"\" : authString) + \"\\r\\n\"",
     "canonical 分隔符 \\n → \\r\\n", "INLINE_CONSTANT"),
]


def run_mutation(path, old, new, desc, cat):
    src = CORE / path
    orig = src.read_text()
    if old not in orig:
        return ("SKIP", f"变异点未找到: {old[:50]}")
    mutated = orig.replace(old, new, 1)
    src.write_text(mutated)
    try:
        r = subprocess.run(
            ["mvn", "-pl", "wop-sdk-core", "test"],
            cwd=ROOT, capture_output=True, text=True, timeout=180)
        out = r.stdout + r.stderr
        killed = r.returncode != 0 and ("Tests run" in out and ("Failures: [1-9]" in out or "Failures: [1-9]" in out or "Errors: [1-9]" in out or "BUILD FAILURE" in out))
        # 编译失败（无 Tests run）算 SURVIVED(编译失败)——变异未被测试拦截
        if "Tests run" not in out:
            return ("SURVIVED(编译失败)", f"变异导致编译失败: {out[-300:]}")
        return ("KILLED" if killed else "SURVIVED", "")
    except subprocess.TimeoutExpired:
        return ("TIMEOUT", "测试超时 180s")
    finally:
        src.write_text(orig)


def main():
    results = []
    for i, (path, old, new, desc, cat) in enumerate(MUTATIONS, 1):
        status, note = run_mutation(path, old, new, desc, cat)
        results.append((desc, cat, status, note))
        print(f"[{i:2d}] {cat:26s} {status:22s} {desc}")
        if note:
            print(f"      {note[:200]}")
    killed = sum(r[2] == "KILLED" for r in results)
    total = len(results)
    print(f"\n=== 变异击杀率: {killed}/{total} = {killed/total*100:.1f}% ===")
    surv = [r for r in results if r[2] != "KILLED"]
    if surv:
        print("存活/漂移变异:")
        for s in surv:
            print(f"  - [{s[1]}] {s[0]} ({s[2]})")
    else:
        print("全部变异被击杀")
    return 1 if surv else 0


if __name__ == "__main__":
    sys.exit(main())
