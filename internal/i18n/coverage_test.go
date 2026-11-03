package i18n_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"unicode"
)

// moduleRoot はリポジトリのルート（go.mod のあるディレクトリ）を返す。
func moduleRoot(t *testing.T) string {
	t.Helper()
	dir, _ := filepath.Abs(".")
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("go.mod が見つからない")
		}
		dir = parent
	}
}

func hasJA(s string) bool {
	for _, r := range s {
		if unicode.In(r, unicode.Han, unicode.Hiragana, unicode.Katakana) {
			return true
		}
	}
	return false
}

var verbRE = regexp.MustCompile(`%[-+# 0]*(\*|[0-9]+)?(\.(\*|[0-9]+))?[a-zA-Z%]`)

// verbs は書式指定（%s・%v・%w など）の並びを返す（%% は除く）。
func verbs(s string) []string {
	var out []string
	for _, v := range verbRE.FindAllString(s, -1) {
		if v != "%%" {
			out = append(out, v)
		}
	}
	return out
}

// 利用者に見せる日本語の文字列は、すべて i18n.T（日本語, 英語）で英語と並べて書く。
// 英語の側には日本語を含めず、書式指定（%s など）の並びを日本語の側とそろえる。
// examples/ は利用者が写して使うサンプルなので対象外（internal のパッケージを使えないため）。
// internal/i18n 自身も対象外。
func TestMessagesAreTranslated(t *testing.T) {
	root := moduleRoot(t)
	fset := token.NewFileSet()
	pairs := 0
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "examples", "testdata":
				return filepath.SkipDir
			}
			if rel, _ := filepath.Rel(root, p); rel == filepath.Join("internal", "i18n") {
				return filepath.SkipDir // 起動時の警告だけは、意図して日本語と英語を 1 行に並べている
			}
			return nil
		}
		if !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
			return nil
		}
		rel, _ := filepath.Rel(root, p)
		f, err := parser.ParseFile(fset, p, nil, 0)
		if err != nil {
			return err
		}
		inT := map[*ast.BasicLit]bool{}
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || (sel.Sel.Name != "T" && sel.Sel.Name != "Error") {
				return true
			}
			if id, ok := sel.X.(*ast.Ident); !ok || id.Name != "i18n" {
				return true
			}
			pos := fset.Position(call.Pos())
			if len(call.Args) != 2 {
				t.Errorf("%s:%d: i18n.%s の引数は 2 つ（日本語, 英語）", rel, pos.Line, sel.Sel.Name)
				return true
			}
			ja, ok1 := call.Args[0].(*ast.BasicLit)
			en, ok2 := call.Args[1].(*ast.BasicLit)
			if !ok1 || !ok2 || ja.Kind != token.STRING || en.Kind != token.STRING {
				t.Errorf("%s:%d: i18n.T には文字列リテラルを渡す（訳し漏れと書式指定を確かめるため）", rel, pos.Line)
				return true
			}
			inT[ja], inT[en] = true, true
			js, _ := strconv.Unquote(ja.Value)
			es, _ := strconv.Unquote(en.Value)
			pairs++
			if strings.TrimSpace(es) == "" {
				t.Errorf("%s:%d: 英語の文言が空", rel, pos.Line)
			}
			if hasJA(es) {
				t.Errorf("%s:%d: 英語の文言に日本語がある: %q", rel, pos.Line, es)
			}
			if a, b := strings.Join(verbs(js), " "), strings.Join(verbs(es), " "); a != b {
				t.Errorf("%s:%d: 書式指定の並びが違う（日本語 %q / 英語 %q）", rel, pos.Line, a, b)
			}
			return true
		})
		// パッケージの変数の初期化で i18n.T を呼ばない（初期化のときの言語で固定される。番兵のエラーは i18n.Error を使う）。
		for _, d := range f.Decls {
			g, ok := d.(*ast.GenDecl)
			if !ok || g.Tok != token.VAR {
				continue
			}
			ast.Inspect(g, func(n ast.Node) bool {
				if _, ok := n.(*ast.FuncLit); ok {
					return false // 関数の中は呼び出しのたびに評価される
				}
				if call, ok := n.(*ast.CallExpr); ok {
					if sel, ok := call.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "T" {
						if id, ok := sel.X.(*ast.Ident); ok && id.Name == "i18n" {
							t.Errorf("%s:%d: パッケージの変数の初期化で i18n.T を呼んでいる（言語を変えても追従しない）", rel, fset.Position(call.Pos()).Line)
						}
					}
				}
				return true
			})
		}
		ast.Inspect(f, func(n ast.Node) bool {
			bl, ok := n.(*ast.BasicLit)
			if !ok || bl.Kind != token.STRING || inT[bl] {
				return true
			}
			if s, _ := strconv.Unquote(bl.Value); hasJA(s) {
				t.Errorf("%s:%d: 日本語の文字列が i18n.T を通っていない: %.60s", rel, fset.Position(bl.Pos()).Line, bl.Value)
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if pairs < 100 {
		t.Fatalf("i18n.T の呼び出しが %d 件しか見つからない（探し方を確かめる）", pairs)
	}
}

var (
	tmplActionRE = regexp.MustCompile(`(?s)\{\{.*?\}\}`)
	tmplPairRE   = regexp.MustCompile(`\bt\s+"((?:[^"\\]|\\.)*)"\s+"((?:[^"\\]|\\.)*)"`)
)

// 管理画面のテンプレートの日本語も、すべて {{t "日本語" "English"}} で英語と並べる。
func TestTemplatesAreTranslated(t *testing.T) {
	dir := filepath.Join(moduleRoot(t), "internal", "admin", "templates")
	files, err := filepath.Glob(filepath.Join(dir, "*.html"))
	if err != nil || len(files) == 0 {
		t.Fatalf("テンプレートが見つからない: %v", err)
	}
	pairs := 0
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		name := filepath.Base(f)
		src := string(b)
		for _, m := range tmplPairRE.FindAllStringSubmatch(src, -1) {
			pairs++
			ja, _ := strconv.Unquote(`"` + m[1] + `"`)
			en, _ := strconv.Unquote(`"` + m[2] + `"`)
			if strings.TrimSpace(en) == "" || hasJA(en) {
				t.Errorf("%s: 英語の文言が空か、日本語がある: %q", name, en)
			}
			if a, b := strings.Join(verbs(ja), " "), strings.Join(verbs(en), " "); a != b {
				t.Errorf("%s: 書式指定の並びが違う（日本語 %q / 英語 %q）: %s", name, a, b, ja)
			}
		}
		// {{ }} の外（HTML の地の文・属性）に日本語を書かない。{{ }} の中の日本語は t の第 1 引数だけにする。
		rest := tmplActionRE.ReplaceAllStringFunc(src, func(a string) string {
			return tmplPairRE.ReplaceAllString(a, "")
		})
		for i, line := range strings.Split(rest, "\n") {
			if hasJA(line) {
				t.Errorf("%s:%d: 日本語が {{t ...}} を通っていない: %.80s", name, i+1, strings.TrimSpace(line))
			}
		}
	}
	if pairs < 50 {
		t.Fatalf("{{t ...}} が %d 件しか見つからない（探し方を確かめる）", pairs)
	}
}
