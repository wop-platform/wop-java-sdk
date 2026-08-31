#!/usr/bin/env python3
"""docstring 门检查器(wop-java-sdk):javadoc 覆盖率门禁。

度量口径(统一契约 2026-08-31):
  对外 API(100%):顶层 public class/interface/enum/record + 任意层 public/protected 方法(含构造器);
  内部 API(≥80%,空集=达标):package/private 方法 + 非 public 顶层类型。

docstring 判定:标准 javadoc 归属——声明上方(可穿透注解行,不可跨空行)
紧邻的注释块必须是 /** 开头的 javadoc,装饰性 // 与普通 /* */ 不算。

反作弊:扫描面 = git ls-files 枚举(非 glob 全扫),排除 tests/示例/生成物;
逐符号缺失清单输出;--self-test 负控制(喂已知坏输入断言能红)。

CLI:无参 → exit 0 达标 / 1 未达标;--self-test;--json。
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SCAN_PATHSPEC = "wop-sdk-core/src/main/java"
EXCLUDE_SEGMENTS = ("test", "example", "examples", "generated", "build")

EXTERNAL_MIN = 1.0
INTERNAL_MIN = 0.8

# ── Java 词法:注释/字符串剥离 ────────────────────────────────────────

def strip_java(text: str) -> tuple[str, list[tuple[int, int, bool]]]:
    """剥离注释与字符串/字符字面量内容(保留换行与结构),返回 (剥离文本, 注释块)。

    注释块 = (起始行, 结束行, 是否 javadoc/**开头)。字符串/文本块内容置空格,
    引号保留为占位,确保括号/花括号计数不被字面量污染。
    """
    out: list[str] = []
    comments: list[tuple[int, int, bool]] = []
    i, n, line = 0, len(text), 1

    def blank(ch: str) -> None:
        """输出占位:换行保留,其余置空格。"""
        nonlocal line
        if ch == "\n":
            out.append("\n")
            line += 1
        else:
            out.append(" ")

    while i < n:
        c = text[i]
        nxt = text[i + 1] if i + 1 < n else ""
        if c == "/" and nxt == "/":                       # 行注释
            while i < n and text[i] != "\n":
                blank(text[i]); i += 1
        elif c == "/" and nxt == "*":                     # 块注释
            is_doc = i + 2 < n and text[i + 2] == "*"
            start = line
            blank(c); blank(nxt); i += 2
            while i < n:
                if text[i] == "*" and i + 1 < n and text[i + 1] == "/":
                    blank("*"); blank("/"); i += 2
                    break
                blank(text[i]); i += 1
            comments.append((start, line, is_doc))
        elif c == '"' and text[i:i + 3] == '"""':         # 文本块
            for ch in text[i:i + 3]:
                blank(ch)
            i += 3
            while i < n and text[i:i + 3] != '"""':
                blank(text[i]); i += 1
            for ch in text[i:i + 3]:
                blank(ch)
            i += 3
        elif c == '"':                                    # 字符串
            out.append('"'); i += 1
            while i < n and text[i] != '"':
                if text[i] == "\\" and i + 1 < n:
                    blank(text[i]); blank(text[i + 1]); i += 2
                else:
                    blank(text[i]); i += 1
            out.append('"'); i += 1
        elif c == "'":                                    # 字符字面量
            out.append("'"); i += 1
            while i < n and text[i] != "'":
                if text[i] == "\\" and i + 1 < n:
                    blank(text[i]); blank(text[i + 1]); i += 2
                else:
                    blank(text[i]); i += 1
            out.append("'"); i += 1
        else:
            out.append(c)
            if c == "\n":
                line += 1
            i += 1
    return "".join(out), comments


# ── 声明识别(剥离文本上的 token 流状态机)────────────────────────────

TYPE_MODS = r"(?:public|protected|private|static|final|abstract|sealed|non-sealed|strictfp)"
METHOD_MODS = r"(?:public|protected|private|static|final|abstract|synchronized|native|strictfp|default|transient|volatile)"
INLINE_ANNO = r"(?:@[\w$.]+(?:\((?:[^()]|\([^()]*\))*\))?)"

TYPE_RE = re.compile(
    rf"(?:{INLINE_ANNO}\s*)*(?:{TYPE_MODS}\s+)*(?:@\s*interface|(class|interface|enum|record))\s+([\w$]+)")
METHOD_RE = re.compile(
    rf"(?:{INLINE_ANNO}\s*)*(?:(?:{METHOD_MODS})\s+)*"
    rf"(?:<[^<>]*>\s*)?"
    rf"(?:([\w$][\w$.\[\]<>?,\s]*?)\s+)?"
    rf"([\w$]+)\s*\(")

RESERVED_NAMES = {"if", "for", "while", "switch", "catch", "return", "new", "throw",
                  "else", "do", "try", "assert", "super", "this", "case", "yield"}
RESERVED_TYPES = {"return", "new", "throw", "else", "do", "try", "case", "yield", "assert"}


class Ctx:
    """花括号上下文:type = 类型体(block 成员可声明),block = 方法体/初始化块(跳过)。"""

    __slots__ = ("kind", "name", "kind_kw", "top_level")

    def __init__(self, kind: str, name: str = "", kind_kw: str = "", top_level: bool = False):
        self.kind = kind
        self.name = name
        self.kind_kw = kind_kw
        self.top_level = top_level


class Symbol:
    __slots__ = ("name", "line", "kind", "external", "file", "has_doc")

    def __init__(self, name: str, line: int, kind: str, external: bool, file: str):
        self.name = name
        self.line = line
        self.kind = kind
        self.external = external
        self.file = file


def _mods_in(mod_run: str) -> set[str]:
    return set(mod_run.split())


def analyze(text: str, rel_path: str) -> list[Symbol]:
    """解析单个 Java 编译单元,返回可文档化符号清单。"""
    stripped, comments = strip_java(text)
    javadoc_ends = {end: True for (_s, end, is_doc) in comments if is_doc}
    orig_lines = text.split("\n")
    n = len(stripped)
    symbols: list[Symbol] = []
    stack: list[Ctx] = []
    pending: Ctx | None = None          # 已声明、等待 { 落位的上下文
    member_pos = True                    # 处于成员声明位置(文件头/;/{/} 之后)
    i = 0
    line_of = lambda pos: stripped.count("\n", 0, pos) + 1

    def innermost() -> Ctx | None:
        return stack[-1] if stack else None

    while i < n:
        c = stripped[i]
        if c.isspace():
            i += 1
            continue
        if c in ";{}":
            if c == "{":
                if pending is not None:
                    stack.append(pending)
                    pending = None
                else:
                    stack.append(Ctx("block"))
            elif c == "}":
                if stack:
                    stack.pop()
            member_pos = True
            i += 1
            continue
        if member_pos:
            m_type = TYPE_RE.match(stripped, i) if innermost() is None or innermost().kind == "type" else None
            m_meth = None
            if m_type is None and innermost() is not None and innermost().kind == "type":
                m_meth = METHOD_RE.match(stripped, i)
            if m_type is not None:
                kind_kw, name = m_type.group(1), m_type.group(2)
                mods = _mods_in(m_type.group(0))
                top = innermost() is None
                if top:  # 顶层类型计符号;嵌套类型只建上下文(契约口径)
                    symbols.append(Symbol(name, line_of(m_type.start()), kind_kw,
                                          "public" in mods, rel_path))
                pending = Ctx("type", name, kind_kw, top)
                i = m_type.end(2)
                member_pos = False
                continue
            if m_meth is not None:
                mods = _mods_in(m_meth.group(0)[: m_meth.start(2) - m_meth.start()])
                ret, name = m_meth.group(1), m_meth.group(2)
                prefix = stripped[m_meth.start(): m_meth.start(2)]
                ok = name not in RESERVED_NAMES and "=" not in prefix
                if ok and ret is not None:
                    ok = ret.split()[-1].strip("[], ") not in RESERVED_TYPES
                if ok and ret is None:
                    ok = name == innermost().name  # 无返回类型 → 必须是构造器
                if ok:
                    # 头部收尾:平衡括号后须是 { ; throws default 之一
                    j, depth = m_meth.end() - 1, 0
                    while j < n:
                        if stripped[j] == "(":
                            depth += 1
                        elif stripped[j] == ")":
                            depth -= 1
                            if depth == 0:
                                break
                        j += 1
                    tail = stripped[j + 1: j + 200].lstrip()
                    if tail[:1] in ("{", ";") or tail.startswith(("throws", "default")):
                        vis = mods & {"public", "protected", "private"}
                        if not vis and innermost().kind_kw == "interface":
                            external = True   # 接口方法无修饰符 = 隐式 public
                        else:
                            external = bool(vis & {"public", "protected"})
                        symbols.append(Symbol(name, line_of(m_meth.start()),
                                              "method", external, rel_path))
                        pending = Ctx("block")
                i = m_meth.end() - 1 if m_meth.end() > i else i + 1
                member_pos = False
                continue
        member_pos = False
        i += 1

    # javadoc 归属:前一非空行(穿透注解行)必须是 javadoc 块结束行,且无空行间隔
    for sym in symbols:
        sym.has_doc = _has_javadoc(orig_lines, sym.line, javadoc_ends)  # type: ignore[attr-defined]
    return symbols


def _true_decl_line(orig_lines: list[str], sym_line: int) -> int:
    """向下穿透注解行(含参数续行),得到真实声明所在行(1 基)。"""
    i = sym_line - 1
    paren = 0
    while 0 <= i < len(orig_lines):
        s = orig_lines[i].strip()
        if paren > 0 or s.startswith("@"):
            paren += s.count("(") - s.count(")")
            i += 1
            continue
        return i + 1
    return sym_line


def _has_javadoc(orig_lines: list[str], decl_line: int, javadoc_ends: dict[int, bool]) -> bool:
    """v2 标准 javadoc 归属:先向下穿透注解定位真实声明行,再向上穿透注解行
    (空行一律阻断),第一个普通行必须是 javadoc 块结束行。装饰性 // 与
    普通 /* */ 注释不以 /** 开头,天然不满足。"""
    true_line = _true_decl_line(orig_lines, decl_line)
    i = true_line - 2
    paren = 0
    while i >= 0:
        s = orig_lines[i].strip()
        if not s:
            return False          # 空行阻断归属
        if paren > 0 or s.startswith("@"):
            paren += s.count("(") - s.count(")")
            i -= 1
            continue
        return javadoc_ends.get(i + 1, False)
    return False


# ── 门判定 ──────────────────────────────────────────────────────────

def judge(symbols: list[Symbol]) -> dict:
    ext = [s for s in symbols if s.external]
    inn = [s for s in symbols if not s.external]
    ext_ok = [s for s in ext if s.has_doc]  # type: ignore[attr-defined]
    inn_ok = [s for s in inn if s.has_doc]  # type: ignore[attr-defined]
    return {
        "missing": [s for s in symbols if not s.has_doc],  # type: ignore[attr-defined]
        "external_total": len(ext), "external_doc": len(ext_ok),
        "internal_total": len(inn), "internal_doc": len(inn_ok),
    }


def passes(stats: dict) -> bool:
    ext_rate = stats["external_doc"] / stats["external_total"] if stats["external_total"] else 1.0
    inn_rate = stats["internal_doc"] / stats["internal_total"] if stats["internal_total"] else 1.0
    return ext_rate >= EXTERNAL_MIN and inn_rate >= INTERNAL_MIN


def scan_files(repo_root: Path) -> list[Path]:
    """git ls-files 枚举扫描面(防未跟踪文件混入),排除 tests/示例/生成物。"""
    proc = subprocess.run(
        ["git", "-C", str(repo_root), "ls-files", "--", SCAN_PATHSPEC],
        capture_output=True, text=True, check=True)
    files = []
    for rel in proc.stdout.splitlines():
        if not rel.endswith(".java"):
            continue
        segs = Path(rel).parts
        if any(s.lower() in EXCLUDE_SEGMENTS for s in segs):
            continue
        files.append(repo_root / rel)
    return sorted(files)


def run_gate(repo_root: Path, as_json: bool = False) -> tuple[bool, list[Symbol], dict]:
    all_symbols: list[Symbol] = []
    for f in scan_files(repo_root):
        all_symbols.extend(analyze(f.read_text(encoding="utf-8"), str(f.relative_to(repo_root))))
    stats = judge(all_symbols)
    ok = passes(stats)
    if as_json:
        payload = {
            "pass": ok,
            "external": {"total": stats["external_total"], "documented": stats["external_doc"]},
            "internal": {"total": stats["internal_total"], "documented": stats["internal_doc"]},
            "missing": [{"file": s.file, "line": s.line, "symbol": s.name,
                         "surface": "external" if s.external else "internal"}
                        for s in stats["missing"]],
        }
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    else:
        for s in stats["missing"]:
            surface = "对外" if s.external else "内部"
            print(f"缺失[{surface}] {s.file}:{s.line} {s.name}")
        print(f"对外 {stats['external_doc']}/{stats['external_total']}、"
              f"内部 {stats['internal_doc']}/{stats['internal_total']}")
        print("docstring 门: " + ("达标" if ok else "未达标"))
    return ok, stats["missing"], stats


# ── 负控制自测 ──────────────────────────────────────────────────────

GOOD_FILE = '''package demo;

/** 有 javadoc 的公开类。 */
public class Good {
    /** 有 javadoc 的公开方法。 */
    public void documented() {}

    /** 注解之上仍归属。 */
    @Override
    public String toString() { return "x"; }

    /** 内部方法同样有 javadoc。 */
    private void hidden() {}

    /** 有 javadoc 的构造器。 */
    public Good() {}

    /** 包可见构造器。 */
    Good(int x) {}
}
'''

BAD_FILE = '''package demo;

/** 类有 javadoc。 */
public class Bad {
    /** 构造器有 javadoc。 */
    public Bad() {}

    public void noDoc() {}

    /** 与声明之间隔了空行,不算归属。 */

    public void blankSeparated() {}

    // 装饰性行注释不算。
    public void lineComment() {}

    protected void protNoDoc() {}

    /* 普通 block 注释不算。 */
    public void blockComment() {}
}
'''


def self_test() -> int:
    """负控制:已知坏输入必须被识别为缺失,已知好输入不得误报。"""
    failures: list[str] = []

    good = analyze(GOOD_FILE, "Good.java")
    missing_good = [s.name for s in good if not s.has_doc]
    if missing_good:
        failures.append(f"好样本误报缺失: {missing_good}")
    ext = [s for s in good if s.external]
    if len(ext) != 4:
        failures.append(f"好样本对外符号数期望 4(class+toString+documented+ctor),实际 {len(ext)}: {[s.name for s in ext]}")
    if any(s.name != s.name.capitalize() and s.name in ("ood", "WopClient") for s in good):
        failures.append(f"符号名被截首字母: {[s.name for s in good]}")
    ctors = [s for s in good if s.kind == "method" and s.name == "Good"]
    if len(ctors) != 2:
        failures.append(f"构造器识别数期望 2,实际 {[s.name for s in good]}")
    if ctors and ctors[0].name != "Good":
        failures.append(f"构造器名字被截: {ctors[0].name!r}")

    bad = analyze(BAD_FILE, "Bad.java")
    missing = {s.name for s in bad if not s.has_doc}
    expect_missing = {"noDoc", "blankSeparated", "lineComment", "protNoDoc", "blockComment"}
    if missing != expect_missing:
        failures.append(f"坏样本缺失集不符: 期望 {sorted(expect_missing)}, 实际 {sorted(missing)}")

    st = judge([s for s in bad if s.name != "__class__"])
    if passes(st):
        failures.append("坏样本门判定应红(对外 <100%)却判绿")

    # 内部阈值:5 个 private,4 有 javadoc = 80% 恰好达标;3 有 = 60% 应红
    thr = '''package demo;

/** 类。 */
public class Thr {
    /** d1 */
    private void a() {}
    /** d2 */
    private void b() {}
    /** d3 */
    private void c() {}
    /** d4 */
    private void d() {}
    private void e() {}
}
'''
    thr_syms = analyze(thr, "Thr.java")
    st2 = judge(thr_syms)
    if not passes(st2):
        failures.append(f"内部 4/5=80% 应达标却红: {st2['internal_doc']}/{st2['internal_total']}")
    for s in thr_syms:
        if s.name == "b":
            s.has_doc = False
    st3 = judge(thr_syms)
    if passes(st3):
        failures.append("内部 3/5=60% 应红却绿")

    # 空内部集 = 达标
    only = Symbol("Only", 1, "class", True, "X.java")
    only.has_doc = True
    st4 = judge([only])
    st4["missing"] = []
    if not passes(st4):
        failures.append("空内部集应视为达标")

    # 端到端负控制:临时 git 仓,坏文件必须让门整体 exit 1 语义(非零)
    with tempfile.TemporaryDirectory() as td:
        repo = Path(td)
        (repo / ".git").mkdir()  # 轻量假仓:scan_files 只需 git ls-files 可用性
        proc = subprocess.run(["git", "-C", td, "init", "-q"], capture_output=True)
        if proc.returncode != 0:
            failures.append("临时仓 init 失败,端到端负控制未执行")
        else:
            base = repo / SCAN_PATHSPEC / "demo"
            base.mkdir(parents=True)
            (base / "Good.java").write_text(GOOD_FILE, encoding="utf-8")
            subprocess.run(["git", "-C", td, "add", "-A"], capture_output=True)
            subprocess.run(["git", "-C", td, "-c", "user.email=t@t", "-c", "user.name=t",
                            "commit", "-qm", "init"], capture_output=True)
            ok1, miss1, _st = run_gate(repo)
            (base / "Bad.java").write_text(BAD_FILE, encoding="utf-8")
            ok2, miss2, _st = run_gate(repo)
            if ok1 is not True or miss1:
                failures.append(f"干净仓应绿: pass={ok1} missing={len(miss1)}")
            subprocess.run(["git", "-C", td, "add", "-A"], capture_output=True)
            ok2, miss2, _st = run_gate(repo)
            if ok2 is not False or not miss2:
                failures.append("注入坏文件后门应红(端到端负控制失败)")

    if failures:
        print("SELF-TEST FAIL:")
        for f in failures:
            print(f"  - {f}")
        return 1
    print("SELF-TEST PASS: 负控制全部生效(坏输入必红、好输入无误报、阈值边界正确)")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true", help="负控制自测")
    parser.add_argument("--json", action="store_true", help="JSON 统计输出")
    args = parser.parse_args()
    if args.self_test:
        return self_test()
    ok, _missing, _stats = run_gate(REPO_ROOT, as_json=args.json)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
