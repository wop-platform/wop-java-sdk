#!/usr/bin/env python3
"""变异点快照漂移检测（六仓统一模式，wop-java-sdk 实例）。

scripts/mutation-check.py 的 14 个变异点以「原文快照」绑定源码（SKIP 显性
报警），但完整跑一遍需 14 次 mvn 编译（分钟级），仅适合定期档。本脚本提取
同一 MUTATIONS 表做**秒级**校验：每条原文快照仍能在源文件中找到——
重构导致快照失配时 PR 即刻失败，把漂移防线从「跑变异时」提前到「每 PR」。

用法: python3 scripts/check-equivalent-anchors.py
退出码: 0 = 全部快照命中；1 = 存在漂移（同步 MUTATIONS 快照后重跑）。
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

import importlib.util

_spec = importlib.util.spec_from_file_location("mutation_check", ROOT / "scripts" / "mutation-check.py")
_mc = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_mc)
MUTATIONS = _mc.MUTATIONS


def main() -> int:
    drifted = []
    for i, (file, original, _mutated, desc, _op) in enumerate(MUTATIONS, 1):
        path = ROOT / "wop-sdk-core" / file
        if not path.exists():
            drifted.append(f"#{i} {desc}: {file} 不存在")
            continue
        if original not in path.read_text(encoding="utf-8"):
            drifted.append(f"#{i} {desc}: 原文快照失配于 {file}")
    if drifted:
        for d in drifted:
            print(f"ANCHOR DRIFT: {d}", file=sys.stderr)
        return 1
    print(f"anchors ok ({len(MUTATIONS)} 条快照全部命中)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
