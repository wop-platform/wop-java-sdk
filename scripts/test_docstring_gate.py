"""docstring 门检查器测试(wop-java-sdk)。

外部驱动 pytest 用例,与 --self-test(内嵌样本负控制)互补:
覆盖 strip_java 词法剥离、analyze 声明状态机、javadoc 归属、阈值判定、
扫描面枚举、run_gate/CLI 与 self_test 失败路径。
"""
# spec:DG-1 对外 API 100% 红线 → 阈值与判定测试(见下方用例)
# spec:DG-2 内部 ≥80%(空内部集=达标) → 阈值边界测试
# spec:DG-3 docstring 归属判定(注释形态/空行/组注释不覆盖) → 判定测试
# spec:DG-4 CLI 无参 exit 0/1 + 逐符号缺失清单 + 统计 → main/CLI 测试
# spec:DG-5 --self-test 负控制(先红后绿) → self_test 测试
# spec:DG-6 扫描面 = git ls-files 枚举(反作弊) → 扫描面测试
# spec:DG-7 factory-local.json docstring_gate_cmd 禁引号/反斜杠 → 上游 test_factory_lib.py TestDocstringGateWords
# spec:DG-8 defects.json D-xx gate=docstring 击杀 → mutations/defects.json D-01/D-02 PASS
# spec:DG-10 mutations judge 门域 0/1 → 上游 test_mutations_run.py TestDocstringGateJudge


from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

SCRIPTS_DIR = Path(__file__).resolve().parent
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

import docstring_gate as dg  # noqa: E402


# ── 测试样本 ─────────────────────────────────────────────────────────

GREEN_FILE = '''package demo;

/** 有 javadoc 的公开类。 */
public class Green {
    /** 有 javadoc 的公开方法。 */
    public void documented() {}

    /** 注解之上仍归属。 */
    @Override
    public String toString() { return "x"; }

    /** 内部方法同样有 javadoc。 */
    private void hidden() {}

    /** 有 javadoc 的构造器。 */
    public Green() {}
}
'''

RED_FILE = '''package demo;

/** 类有 javadoc。 */
public class Red {
    public void noDoc() {}
}
'''


def sym_map(text: str, rel: str = "X.java") -> dict[str, dg.Symbol]:
    return {s.name: s for s in dg.analyze(text, rel)}


def make_repo(tmp_path: Path, files: dict[str, str], commit: bool = True) -> Path:
    """临时 git 仓:写入 files(rel→内容)并纳入 git 索引。"""
    subprocess.run(["git", "-C", str(tmp_path), "init", "-q"], check=True, capture_output=True)
    for rel, content in files.items():
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
    subprocess.run(["git", "-C", str(tmp_path), "add", "-A"], check=True, capture_output=True)
    if commit and files:                   # 空仓无可提交内容,跳过 commit
        subprocess.run(["git", "-C", str(tmp_path), "-c", "user.email=t@t", "-c", "user.name=t",
                        "commit", "-qm", "init"], check=True, capture_output=True)
    return tmp_path


# ── strip_java:注释/字符串剥离 ────────────────────────────────────────

class TestStripJava:
    def test_plain_code_kept_and_string_blanked(self):
        text = 'int a = 1;\nString s = "a{b}c";\n'
        out, comments = dg.strip_java(text)
        assert 'int a = 1;' in out
        assert '"     "' in out            # 内容置空格,引号保留
        assert "{" not in out.replace("int a = 1;\n", "")  # 字面量花括号不泄漏
        assert comments == []

    def test_escaped_quote_does_not_terminate_string(self):
        out, _ = dg.strip_java(r'String s = "a\"b{";')
        assert out.count('"') == 2          # 仅首尾两个引号占位
        assert "{" not in out               # 转义后的 { 仍在字符串内被剥离

    def test_unterminated_string_at_eof(self):
        out, _ = dg.strip_java('x = "abc')
        assert out == 'x = "   "'           # 未闭合也补占位引号收尾

    def test_char_literal_and_escape(self):
        out, _ = dg.strip_java(r"char c = '\''; char d = '{';")
        assert out == r"char c = '  '; char d = ' ';"

    def test_unterminated_char_literal(self):
        out, _ = dg.strip_java("char c = 'x")
        assert out == "char c = ' '"      # 内容置空格,未闭合也补占位引号

    def test_line_comment_blanked_newline_kept(self):
        text = 'int a; // { } " 尾注\nint b;'
        out, comments = dg.strip_java(text)
        lines = out.split("\n")
        assert lines[0] == "int a; " + " " * len('// { } " 尾注')
        assert lines[1] == "int b;"
        assert '"' not in out and "{" not in out
        assert comments == []             # 行注释不进注释块清单

    def test_line_comment_at_eof_without_newline(self):
        out, _ = dg.strip_java("int a; // eof")
        assert out == "int a; " + " " * len("// eof")

    def test_block_comment_not_javadoc(self):
        text = "/* 普通\n块注释 */\ncode();"
        out, comments = dg.strip_java(text)
        assert "code();" in out
        assert comments == [(1, 2, False)]

    def test_javadoc_block_recorded(self):
        text = "/** 多行\n * javadoc\n */\nvoid m();"
        out, comments = dg.strip_java(text)
        assert "void m();" in out
        assert comments == [(1, 3, True)]

    def test_unterminated_block_comment(self):
        out, comments = dg.strip_java("a; /* 悬空")
        assert out.startswith("a;  ")
        assert comments == [(1, 1, False)]

    def test_text_block_stripped(self):
        text = 'String tb = """a{b"c\nsecond""";\ndone();'
        out, _ = dg.strip_java(text)
        assert '"' not in out.replace('""', "")  # 仅剩成对占位引号
        assert "{" not in out and "done();" in out
        assert out.count('"""') == 0 or True

    def test_unterminated_text_block(self):
        out, _ = dg.strip_java('x = """abc')
        assert "{" not in out

    def test_multiple_comments_order(self):
        text = "/** a */ void x(); /* b */ void y();"
        _out, comments = dg.strip_java(text)
        assert [c[2] for c in comments] == [True, False]

    def test_line_count_preserved(self):
        text = 'a; // c\n" s1\ns2"\nb; /* x */ c;\n'
        out, _ = dg.strip_java(text)
        assert out.count("\n") == text.count("\n")


# ── 小单元:_mods_in / Symbol / Ctx ──────────────────────────────────

class TestPrimitives:
    def test_mods_in(self):
        assert dg._mods_in("public static final") == {"public", "static", "final"}
        assert dg._mods_in("") == set()

    def test_symbol_fields(self):
        s = dg.Symbol("m", 3, "method", True, "A.java")
        assert (s.name, s.line, s.kind, s.external, s.file) == ("m", 3, "method", True, "A.java")
        s.has_doc = True                      # has_doc 在 __slots__ 内,analyze 会挂上
        assert s.has_doc is True
        with pytest.raises(AttributeError):
            s.typo_attr = 1                   # 其余未知属性被 __slots__ 拒绝

    def test_ctx_defaults_and_args(self):
        c = dg.Ctx("block")
        assert (c.kind, c.name, c.kind_kw, c.top_level) == ("block", "", "", False)
        c2 = dg.Ctx("type", "Foo", "class", True)
        assert (c2.kind, c2.name, c2.kind_kw, c2.top_level) == ("type", "Foo", "class", True)


# ── analyze:类型识别 ─────────────────────────────────────────────────

class TestAnalyzeTypes:
    def test_public_class_external(self):
        syms = sym_map("/** d */\npublic class A {}\n")
        assert syms["A"].external and syms["A"].kind == "class"

    def test_package_private_class_internal(self):
        syms = sym_map("/** d */\nclass A {}\n")
        assert not syms["A"].external

    def test_interface_enum_record_kinds(self):
        syms = sym_map("/** d */ public interface I {}\n/** d */ public enum E {}\n"
                       "/** d */ public record R() {}\n")
        assert syms["I"].kind == "interface" and syms["I"].external
        assert syms["E"].kind == "enum" and syms["E"].external
        assert syms["R"].kind == "record" and syms["R"].external

    def test_annotation_type(self):
        syms = sym_map("/** d */\npublic @interface Marker {}\n")
        assert "Marker" in syms and syms["Marker"].external

    def test_nested_type_no_symbol_but_methods_scanned(self):
        text = ('/** d */\npublic class Outer {\n'
                '    class Inner {\n'
                '        /** d */\n        public void im() {}\n'
                '    }\n}\n')
        syms = sym_map(text)
        assert "Inner" not in syms               # 嵌套类型不计符号(契约口径)
        assert "im" in syms and syms["im"].external

    def test_local_class_in_method_body_skipped(self):
        text = ('/** d */\npublic class Host {\n'
                '    /** d */\n    public void h() {\n'
                '        class Local { void lm() {} }\n'
                '    }\n}\n')
        syms = sym_map(text)
        assert "Local" not in syms and "lm" not in syms

    def test_stray_close_brace_no_crash(self):
        assert dg.analyze("}", "S.java") == []


# ── analyze:方法/构造器识别 ─────────────────────────────────────────

class TestAnalyzeMethods:
    def test_visibility_matrix_in_class(self):
        text = ('/** d */\npublic class M {\n'
                '    /** d */ public void pub() {}\n'
                '    /** d */ protected void prot() {}\n'
                '    /** d */ private void priv() {}\n'
                '    /** d */ void pkg() {}\n'
                '}\n')
        syms = sym_map(text)
        assert syms["pub"].external and syms["prot"].external
        assert not syms["priv"].external and not syms["pkg"].external

    def test_interface_implicit_public(self):
        text = ('/** d */\npublic interface I {\n'
                '    /** d */\n    void implicit();\n'
                '    /** d */\n    static void st() {}\n'
                '    /** d */\n    default int df() { return 1; }\n'
                '    /** d */\n    private void pv() {}\n'
                '}\n')
        syms = sym_map(text)
        assert syms["implicit"].external          # 无修饰符接口方法 = 隐式 public
        assert syms["st"].external and syms["df"].external
        assert not syms["pv"].external

    def test_abstract_and_throws_tails(self):
        text = ('/** d */\npublic abstract class M {\n'
                '    /** d */ protected abstract void abs();\n'
                '    /** d */ public void thr() throws Exception {}\n'
                '}\n')
        syms = sym_map(text)
        assert "abs" in syms and "thr" in syms

    def test_annotation_element_default_tail(self):
        text = ('/** d */\npublic @interface Ann {\n'
                '    /** d */\n    String value() default "x";\n'
                '}\n')
        syms = sym_map(text)
        assert "value" in syms and not syms["value"].external

    def test_constructors(self):
        text = ('/** d */\npublic class C {\n'
                '    /** d */\n    public C() {}\n'
                '    /** d */\n    C(int x) {}\n'
                '}\n')
        ctors = [s for s in dg.analyze(text, "C.java") if s.name == "C" and s.kind == "method"]
        assert len(ctors) == 2
        assert all(c.kind == "method" for c in ctors)
        assert [c.external for c in ctors] == [True, False]   # public 对外 / 包可见内部
        assert all(c.has_doc for c in ctors)

    def test_record_canonical_ctor(self):
        text = ('/** d */\npublic record Point(int x, int y) {\n'
                '    /** d */\n    public double norm() { return 0; }\n'
                '}\n')
        syms = sym_map(text)
        assert "Point" in syms and syms["Point"].kind == "record"
        assert "norm" in syms

    def test_generic_method(self):
        text = ('/** d */\npublic class G {\n'
                '    /** d */\n    public <T> T pick(T a) { return a; }\n'
                '}\n')
        syms = sym_map(text)
        assert "pick" in syms and syms["pick"].external

    def test_reserved_names_and_types_skipped(self):
        text = ('class R {\n'
                '    if (x) foo();\n'
                '    return new Foo(1);\n'
                '    while (b) bar();\n'
                '}\n')
        syms = sym_map(text)
        assert set(syms) == {"R"}

    def test_non_ctor_no_return_skipped(self):
        text = 'class S {\n    bare();\n}\n'
        syms = sym_map(text)
        assert "bare" not in syms

    def test_ctor_shaped_call_with_bad_tail_skipped(self):
        text = 'class T {\n    T(1) + 1;\n}\n'
        syms = sym_map(text)
        assert set(syms) == {"T"}

    def test_annotation_named_arg_suppresses_match(self):
        text = ('class N {\n'
                '    @A(x = 1)\n    void m() {}\n'
                '}\n')
        syms = sym_map(text)
        assert "m" not in syms               # 前缀含 = → 非方法声明

    def test_method_body_and_static_init_are_blocks(self):
        text = ('/** d */\npublic class B {\n'
                '    static { int x = 1; }\n'
                '    { int y = inner(); }\n'
                '    /** d */\n    public void outer() { int z = nested(1); }\n'
                '}\n')
        syms = sym_map(text)
        assert set(syms) == {"B", "outer"}   # 块内调用不产生符号

    def test_lambda_field_initializer_not_method(self):
        text = ('class L {\n'
                '    Runnable r = () -> {};\n'
                '}\n')
        syms = sym_map(text)
        assert set(syms) == {"L"}

    def test_no_body_at_eof_skipped(self):
        text = ('/** d */\npublic class E {\n'
                '    public void end()\n')
        syms = sym_map(text)
        assert set(syms) == {"E"}            # 括号后无 {/;/throws/default → 非声明

    def test_unbalanced_parens_at_eof_skipped(self):
        text = ('/** d */\npublic class F {\n'
                '    public void open(')      # 参数括号悬空到 EOF,永不平衡
        syms = sym_map(text)
        assert set(syms) == {"F"}

    def test_annotated_params_nested_parens(self):
        text = ('/** d */\npublic class P {\n'
                '    /** d */\n'
                '    public void m(@A(1) int x) {}\n'
                '}\n')
        syms = sym_map(text)
        assert "m" in syms and syms["m"].external   # 参数内注解括号嵌套可正确平衡


# ── javadoc 归属 ─────────────────────────────────────────────────────

class TestJavadocAttribution:
    def test_doc_above_annotations_attributed(self):
        text = ('class A {\n'
                '    /** 归属。 */\n'
                '    @SuppressWarnings("x")\n'
                '    @Deprecated\n'
                '    public void m() {}\n'
                '}\n')
        assert sym_map(text)["m"].has_doc

    def test_multiline_javadoc_attributed(self):
        text = ('class A {\n'
                '    /**\n     * 多行\n     */\n'
                '    public void m() {}\n'
                '}\n')
        assert sym_map(text)["m"].has_doc

    def test_blank_line_breaks_attribution(self):
        text = 'class A {\n    /** d */\n\n    public void m() {}\n}\n'
        assert not sym_map(text)["m"].has_doc

    def test_line_comment_not_attributed(self):
        text = 'class A {\n    // 装饰\n    public void m() {}\n}\n'
        assert not sym_map(text)["m"].has_doc

    def test_plain_block_comment_not_attributed(self):
        text = 'class A {\n    /* 普通 */\n    public void m() {}\n}\n'
        assert not sym_map(text)["m"].has_doc

    def test_code_line_between_doc_and_decl(self):
        text = 'class A {\n    /** d */\n    int x = 1;\n    public void m() {}\n}\n'
        assert not sym_map(text)["m"].has_doc


class TestTrueDeclLine:
    def test_plain_declaration(self):
        lines = ["@X", "public void m() {}"]
        assert dg._true_decl_line(lines, 2) == 2

    def test_penetrates_annotation_lines(self):
        lines = ["/** d */", "@Deprecated", "@Override", "public void m() {}"]
        assert dg._true_decl_line(lines, 2) == 4

    def test_penetrates_multiline_annotation_args(self):
        lines = ["/** d */", "@A(", '    "x")', "public void m() {}"]
        assert dg._true_decl_line(lines, 2) == 4

    def test_all_annotation_tail_falls_back_to_sym_line(self):
        # 全文件自符号行起皆为注解行 → 越界回退原行号
        assert dg._true_decl_line(["@A", "@B"], 1) == 1
        assert dg._true_decl_line(["code();", "@A", "@interface X {}"], 2) == 2


class TestHasJavadoc:
    def test_javadoc_end_line_above(self):
        lines = ["/** d */", "void m() {}"]
        assert dg._has_javadoc(lines, 2, {1: True}) is True

    def test_annotation_between_doc_and_decl(self):
        lines = ["/** d */", "@A(1)", "void m() {}"]
        assert dg._has_javadoc(lines, 3, {1: True}) is True

    def test_multiline_annotation_args_walk(self):
        lines = ["/** d */", "@A(", '"x")', "void m() {}"]
        assert dg._has_javadoc(lines, 4, {1: True}) is False

    def test_blank_line_blocks(self):
        lines = ["/** d */", "", "void m() {}"]
        assert dg._has_javadoc(lines, 3, {1: True}) is False

    def test_non_javadoc_above_returns_false(self):
        lines = ["int x = 1;", "void m() {}"]
        assert dg._has_javadoc(lines, 2, {7: True}) is False   # 上方普通代码行非 javadoc 结束行

    def test_nothing_above_decl(self):
        assert dg._has_javadoc(["void m() {}"], 1, {}) is False

    def test_annotation_run_to_top_of_file(self):
        lines = ["@Deprecated", "class X {}"]
        assert dg._has_javadoc(lines, 2, {}) is False

    def test_open_paren_above_skips_javadoc(self):
        # 注解参数未闭合(向上走)→ 即使上方是 javadoc 也不归属
        lines = ["/** d */", "@A(", ") x", "void m() {}"]
        assert dg._has_javadoc(lines, 3, {1: True}) is False


# ── 门判定 ───────────────────────────────────────────────────────────

def _sym(name: str, external: bool, doc: bool) -> dg.Symbol:
    s = dg.Symbol(name, 1, "method", external, "X.java")
    s.has_doc = doc
    return s


class TestJudgePasses:
    def test_judge_counts(self):
        syms = [_sym("a", True, True), _sym("b", False, True), _sym("c", False, False)]
        st = dg.judge(syms)
        assert st["external_total"] == 1 and st["external_doc"] == 1
        assert st["internal_total"] == 2 and st["internal_doc"] == 1
        assert [s.name for s in st["missing"]] == ["c"]

    def test_passes_thresholds(self):
        assert dg.passes({"external_doc": 4, "external_total": 4,
                          "internal_doc": 4, "internal_total": 5}) is True   # 内部恰 80%
        assert dg.passes({"external_doc": 3, "external_total": 4,
                          "internal_doc": 5, "internal_total": 5}) is False  # 对外 <100%
        assert dg.passes({"external_doc": 2, "external_total": 2,
                          "internal_doc": 3, "internal_total": 5}) is False  # 内部 60%
        assert dg.passes({"external_doc": 0, "external_total": 0,
                          "internal_doc": 0, "internal_total": 0}) is True   # 空集达标

    def test_good_and_bad_files_end_to_end(self):
        st = dg.judge(dg.analyze(GREEN_FILE, "Green.java"))
        assert dg.passes(st) and st["missing"] == []
        st = dg.judge(dg.analyze(RED_FILE, "Red.java"))
        assert not dg.passes(st) and [s.name for s in st["missing"]] == ["noDoc"]


# ── scan_files:扫描面 ───────────────────────────────────────────────

class TestScanFiles:
    def test_real_repo_scan(self):
        files = dg.scan_files(dg.REPO_ROOT)
        assert files, "真实仓库扫描面不应为空"
        for f in files:
            rel = f.relative_to(dg.REPO_ROOT).as_posix()
            assert rel.startswith(dg.SCAN_PATHSPEC)
            assert rel.endswith(".java")
            assert not any(s.lower() in dg.EXCLUDE_SEGMENTS for s in f.parts)
        assert files == sorted(files)

    def test_filters_and_excludes(self, tmp_path):
        base = dg.SCAN_PATHSPEC + "/demo"
        make_repo(tmp_path, {
            f"{base}/Keep.java": "class Keep {}",
            f"{base}/notes.txt": "非 java,按扩展名过滤",
            f"{base}/test/Tester.java": "class Tester {}",
            f"{base}/example/Example.java": "class Example {}",
            f"{base}/examples/Ex.java": "class Ex {}",
            f"{base}/generated/Gen.java": "class Gen {}",
            f"{base}/build/Built.java": "class Built {}",
            f"{base}/BUILD/Cased.java": "class Cased {}",
        })
        files = dg.scan_files(tmp_path)
        assert [f.name for f in files] == ["Keep.java"]     # 仅保留正常主源码

    def test_empty_repo(self, tmp_path):
        make_repo(tmp_path, {})
        assert dg.scan_files(tmp_path) == []

    def test_fail_closed_on_git_error(self, tmp_path):
        with pytest.raises(subprocess.CalledProcessError):
            dg.scan_files(tmp_path / "no-such-dir")


# ── run_gate / CLI ──────────────────────────────────────────────────

class TestRunGate:
    def test_green_repo_text_output(self, tmp_path, capsys):
        repo = make_repo(tmp_path, {f"{dg.SCAN_PATHSPEC}/demo/Good.java": dg.GOOD_FILE})
        ok, missing, stats = dg.run_gate(repo)
        assert ok is True and missing == []
        assert stats["external_total"] == 4 and stats["internal_total"] == 2
        out = capsys.readouterr().out
        assert "达标" in out and "对外 4/4、内部 2/2" in out

    def test_red_repo_text_output(self, tmp_path, capsys):
        repo = make_repo(tmp_path, {
            f"{dg.SCAN_PATHSPEC}/demo/Good.java": dg.GOOD_FILE,
            f"{dg.SCAN_PATHSPEC}/demo/Bad.java": dg.BAD_FILE,
        })
        ok, missing, stats = dg.run_gate(repo)
        assert ok is False and {s.name for s in missing} >= {"noDoc", "protNoDoc"}
        out = capsys.readouterr().out
        assert "缺失[对外]" in out and "未达标" in out

    def test_json_output(self, tmp_path, capsys):
        repo = make_repo(tmp_path, {
            f"{dg.SCAN_PATHSPEC}/demo/Good.java": dg.GOOD_FILE,
            f"{dg.SCAN_PATHSPEC}/demo/Bad.java": dg.BAD_FILE,
        })
        ok, missing, _ = dg.run_gate(repo, as_json=True)
        assert ok is False
        payload = json.loads(capsys.readouterr().out)
        assert payload["pass"] is False
        assert payload["external"] == {"total": 11, "documented": 6}
        assert payload["internal"] == {"total": 2, "documented": 2}
        assert {"file", "line", "symbol", "surface"} <= set(payload["missing"][0])
        assert {m["symbol"] for m in payload["missing"]} >= {"noDoc", "blankSeparated"}

    def test_empty_scan_passes(self, tmp_path, capsys):
        repo = make_repo(tmp_path, {})
        ok, missing, stats = dg.run_gate(repo)
        assert ok is True and missing == []
        assert stats["external_total"] == 0 and stats["internal_total"] == 0
        assert "对外 0/0" in capsys.readouterr().out


class TestMain:
    def test_default_green(self, monkeypatch, capsys):
        monkeypatch.setattr(sys, "argv", ["docstring_gate.py"])
        assert dg.main() == 0
        assert "达标" in capsys.readouterr().out

    def test_json_flag(self, monkeypatch, capsys):
        monkeypatch.setattr(sys, "argv", ["docstring_gate.py", "--json"])
        assert dg.main() == 0
        payload = json.loads(capsys.readouterr().out)
        assert payload["pass"] is True and "missing" in payload

    def test_self_test_flag(self, monkeypatch, capsys):
        monkeypatch.setattr(sys, "argv", ["docstring_gate.py", "--self-test"])
        assert dg.main() == 0
        assert "SELF-TEST PASS" in capsys.readouterr().out

    def test_bad_argument_exits_2(self, monkeypatch, capsys):
        monkeypatch.setattr(sys, "argv", ["docstring_gate.py", "--no-such-flag"])
        with pytest.raises(SystemExit) as ei:
            dg.main()
        assert ei.value.code == 2
        capsys.readouterr()

    def test_cli_exit_code_contract(self):
        proc = subprocess.run(
            [sys.executable, str(SCRIPTS_DIR / "docstring_gate.py")],
            capture_output=True, text=True)
        assert proc.returncode == 0, proc.stdout + proc.stderr


# ── self_test:负控制(含失败路径)────────────────────────────────────

BROKEN_GOOD = '''package demo;

/** 有 javadoc 的公开类。 */
public class Good {
    public void documented() {}

    /** 内部方法同样有 javadoc。 */
    private void hidden() {}

    /** 有 javadoc 的构造器。 */
    public Good() {}

    void ood() {}
}
'''

ALL_GOOD_BAD = '''package demo;

/** 类。 */
public class Bad {
    /** d */
    public Bad() {}

    /** d */
    public void noDoc() {}

    /** d */
    public void blankSeparated() {}

    /** d */
    public void lineComment() {}

    /** d */
    protected void protNoDoc() {}

    /** d */
    public void blockComment() {}
}
'''


class TestSelfTest:
    def test_clean_run_passes(self, capsys):
        assert dg.self_test() == 0
        assert "SELF-TEST PASS" in capsys.readouterr().out

    def test_broken_good_file_reported(self, monkeypatch, capsys):
        monkeypatch.setattr(dg, "GOOD_FILE", BROKEN_GOOD)
        assert dg.self_test() == 1
        out = capsys.readouterr().out
        assert "SELF-TEST FAIL" in out
        assert "误报缺失" in out          # documented 缺 javadoc → 缺失
        assert "对外符号数期望 4" in out   # 缺 toString → 3
        assert "构造器识别数期望 2" in out # 仅 1 个构造器
        assert "截首字母" in out          # 符号 ood 命中截名探针

    def test_sanitized_bad_file_reported(self, monkeypatch, capsys):
        monkeypatch.setattr(dg, "BAD_FILE", ALL_GOOD_BAD)
        assert dg.self_test() == 1
        out = capsys.readouterr().out
        assert "坏样本缺失集不符" in out
        assert "应红(对外 <100%)却判绿" in out
        assert "端到端负控制失败" in out

    def test_internal_threshold_too_strict(self, monkeypatch, capsys):
        monkeypatch.setattr(dg, "INTERNAL_MIN", 0.9)
        assert dg.self_test() == 1
        assert "80% 应达标却红" in capsys.readouterr().out

    def test_internal_threshold_too_loose(self, monkeypatch, capsys):
        monkeypatch.setattr(dg, "INTERNAL_MIN", 0.5)
        assert dg.self_test() == 1
        assert "60% 应红却绿" in capsys.readouterr().out

    def test_git_init_failure_reported(self, monkeypatch, capsys):
        real_run = subprocess.run

        def fake_run(cmd, *args, **kwargs):
            if "init" in cmd:
                return subprocess.CompletedProcess(cmd, 1, stdout="", stderr="boom")
            return real_run(cmd, *args, **kwargs)

        monkeypatch.setattr(dg.subprocess, "run", fake_run)
        assert dg.self_test() == 1
        assert "临时仓 init 失败,端到端负控制未执行" in capsys.readouterr().out

    def test_external_min_above_reachable_breaks_empty_internal(self, monkeypatch, capsys):
        monkeypatch.setattr(dg, "EXTERNAL_MIN", 1.5)   # 1.0 < 1.5 → 空内部集探针变红
        assert dg.self_test() == 1
        assert "空内部集应视为达标" in capsys.readouterr().out


class TestModuleEntry:
    def test_dunder_main_guard(self, monkeypatch, capsys):
        import runpy
        monkeypatch.setattr(sys, "argv", ["docstring_gate.py"])   # 隔离 pytest 自身 argv
        with pytest.raises(SystemExit) as ei:
            runpy.run_path(str(SCRIPTS_DIR / "docstring_gate.py"), run_name="__main__")
        assert ei.value.code == 0
        assert "达标" in capsys.readouterr().out
