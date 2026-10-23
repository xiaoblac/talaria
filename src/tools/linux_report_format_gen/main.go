// Copyright 2026 reFuzz project authors. All rights reserved.
// Use of this source code is governed by Apache License 2.0.
//
// linux_report_format_gen extracts the data portion of syzkaller's Linux
// report parser (commonOopses/linuxOopses) into a small C++ initializer.  The
// parser algorithm remains in C++; this tool keeps the large, versioned oops
// format table mechanically tied to the syzkaller checkout used by a build.
package main

import (
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

const (
	linuxRipMarker   = "@@LINUX_RIP_FRAME@@"
	linuxCallMarker  = "@@LINUX_CALL_TRACE@@"
	warningRipMarker = "@@WARNING_RIP_FRAME@@"
	stackTraceMarker = "@@PARSE_STACK_TRACE@@"
)

type pattern struct {
	source string
	icase  bool
}

type part struct {
	stackTrace bool
	pattern    pattern
}

type stackSpec struct {
	parts     []part
	parts2    []part
	skip      []string
	extractor string
}

type formatSpec struct {
	title        pattern
	hasTitle     bool
	report       pattern
	hasReport    bool
	fmt          string
	alt          []string
	stack        *stackSpec
	noStackTrace bool
	corrupted    bool
}

type oopsSpec struct {
	header       string
	formats      []formatSpec
	suppressions []pattern
}

type globalStackSpec struct {
	stackStarts    []pattern
	frames         []pattern
	skip           []string
	corruptedLines []pattern
	stripPrefixes  []string
}

type titleTypeRule struct {
	prefixes   []string
	reportType string
}

type sourceIndex struct {
	values map[string]ast.Expr
}

func main() {
	root := flag.String("syzkaller-root", findRoot(), "syzkaller checkout root")
	out := flag.String("out", filepath.Join("crash", "components", "src", "symbolizer", "linux_report_formats.gen.inc"), "generated C++ include")
	flag.Parse()
	if *root == "" {
		log.Fatal("syzkaller root not found; pass -syzkaller-root")
	}
	idx := &sourceIndex{values: make(map[string]ast.Expr)}
	for _, rel := range []string{
		"pkg/report/report.go",
		"pkg/report/linux.go",
		"pkg/report/crash/types.go",
		"pkg/report/crash/title_to_type.go",
	} {
		if err := idx.read(filepath.Join(*root, rel)); err != nil {
			log.Fatalf("read %s: %v", rel, err)
		}
	}
	linux, err := idx.parseOopsVar("linuxOopses")
	if err != nil {
		log.Fatalf("linuxOopses: %v", err)
	}
	common, err := idx.parseOopsVar("commonOopses")
	if err != nil {
		log.Fatalf("commonOopses: %v", err)
	}
	linux = append(linux, common...)
	if len(linux) == 0 {
		log.Fatal("no oops formats found")
	}
	stackParams, err := idx.parseGlobalStackParams()
	if err != nil {
		log.Fatalf("linuxStackParams: %v", err)
	}
	anchorsExpr, ok := idx.values["linuxStallAnchorFrames"]
	if !ok {
		log.Fatal("linuxStallAnchorFrames not found")
	}
	anchors, err := idx.parsePatterns(anchorsExpr)
	if err != nil {
		log.Fatalf("linuxStallAnchorFrames: %v", err)
	}
	typeRules, err := idx.parseTitleTypeRules()
	if err != nil {
		log.Fatalf("titleToType: %v", err)
	}
	if err := writeOutput(*out, linux, stackParams, anchors, typeRules); err != nil {
		log.Fatalf("write output: %v", err)
	}
	fmt.Fprintf(os.Stderr,
		"linux_report_format_gen: emitted %d oops groups and %d type rules\n",
		len(linux), len(typeRules))
}

func findRoot() string {
	cwd, err := os.Getwd()
	if err != nil {
		return ""
	}
	for dir := cwd; dir != filepath.Dir(dir); dir = filepath.Dir(dir) {
		if _, err := os.Stat(filepath.Join(dir, "pkg", "report", "linux.go")); err == nil {
			return dir
		}
	}
	return ""
}

func (idx *sourceIndex) read(path string) error {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		return err
	}
	for _, decl := range file.Decls {
		gen, ok := decl.(*ast.GenDecl)
		if !ok || (gen.Tok != token.VAR && gen.Tok != token.CONST) {
			continue
		}
		for _, spec := range gen.Specs {
			vs := spec.(*ast.ValueSpec)
			for i, name := range vs.Names {
				if i < len(vs.Values) {
					idx.values[name.Name] = vs.Values[i]
				}
			}
		}
	}
	return nil
}

func (idx *sourceIndex) parseTitleTypeRules() ([]titleTypeRule, error) {
	expr, ok := idx.values["titleToType"]
	if !ok {
		return nil, fmt.Errorf("variable not found")
	}
	lit, ok := unwrap(expr).(*ast.CompositeLit)
	if !ok {
		return nil, fmt.Errorf("expected titleToType composite")
	}
	var result []titleTypeRule
	for _, elt := range lit.Elts {
		entry, ok := unwrap(elt).(*ast.CompositeLit)
		if !ok {
			return nil, fmt.Errorf("expected titleToType entry")
		}
		fields := make(map[string]ast.Expr)
		for _, field := range entry.Elts {
			kv, ok := field.(*ast.KeyValueExpr)
			if !ok {
				return nil, fmt.Errorf("titleToType entry contains positional field")
			}
			fields[identName(kv.Key)] = kv.Value
		}
		prefixes, err := evalStrings(fields["includePrefixes"])
		if err != nil {
			return nil, fmt.Errorf("includePrefixes: %w", err)
		}
		typeName := identName(fields["crashType"])
		typeExpr, ok := idx.values[typeName]
		if !ok {
			return nil, fmt.Errorf("crash type %q not found", typeName)
		}
		call, ok := unwrap(typeExpr).(*ast.CallExpr)
		if !ok || identName(call.Fun) != "Type" || len(call.Args) != 1 {
			return nil, fmt.Errorf("crash type %q has unsupported value", typeName)
		}
		reportType, err := evalString(call.Args[0])
		if err != nil {
			return nil, fmt.Errorf("crash type %q: %w", typeName, err)
		}
		if reportType == "" {
			reportType = "UNKNOWN"
		}
		result = append(result, titleTypeRule{
			prefixes: prefixes, reportType: reportType,
		})
	}
	return result, nil
}

func (idx *sourceIndex) parseOopsVar(name string) ([]oopsSpec, error) {
	expr, ok := idx.values[name]
	if !ok {
		return nil, fmt.Errorf("variable not found")
	}
	if call, ok := expr.(*ast.CallExpr); ok && identName(call.Fun) == "append" {
		if len(call.Args) == 0 {
			return nil, fmt.Errorf("append has no arguments")
		}
		// linuxOopses appends commonOopses. The caller emits that table
		// separately so the two upstream declarations remain independently
		// auditable.
		return idx.parseOopsList(call.Args[0])
	}
	return idx.parseOopsList(expr)
}

func (idx *sourceIndex) parseOopsList(expr ast.Expr) ([]oopsSpec, error) {
	lit, ok := unwrap(expr).(*ast.CompositeLit)
	if !ok {
		return nil, fmt.Errorf("expected oops list, got %T", expr)
	}
	var out []oopsSpec
	for _, elt := range lit.Elts {
		one, err := idx.parseOopsExpr(elt)
		if err != nil {
			return nil, err
		}
		out = append(out, one)
	}
	return out, nil
}

func (idx *sourceIndex) parseOopsExpr(expr ast.Expr) (oopsSpec, error) {
	expr = unwrap(expr)
	if id := identName(expr); id != "" {
		value, ok := idx.values[id]
		if !ok {
			return oopsSpec{}, fmt.Errorf("oops variable %q not found", id)
		}
		return idx.parseOopsExpr(value)
	}
	lit, ok := unwrap(expr).(*ast.CompositeLit)
	if !ok || len(lit.Elts) < 2 {
		return oopsSpec{}, fmt.Errorf("expected oops composite, got %T", expr)
	}
	var result oopsSpec
	var err error
	result.header, err = evalString(lit.Elts[0])
	if err != nil {
		return result, fmt.Errorf("header: %w", err)
	}
	result.formats, err = idx.parseFormats(lit.Elts[1])
	if err != nil {
		return result, fmt.Errorf("%s formats: %w", result.header, err)
	}
	if len(lit.Elts) > 2 {
		result.suppressions, err = idx.parsePatterns(lit.Elts[2])
		if err != nil {
			return result, fmt.Errorf("%s suppressions: %w", result.header, err)
		}
	}
	return result, nil
}

func (idx *sourceIndex) parseFormats(expr ast.Expr) ([]formatSpec, error) {
	lit, ok := unwrap(expr).(*ast.CompositeLit)
	if !ok {
		return nil, fmt.Errorf("expected format list")
	}
	var out []formatSpec
	for _, elt := range lit.Elts {
		one, err := idx.parseFormat(elt)
		if err != nil {
			return nil, err
		}
		out = append(out, one)
	}
	return out, nil
}

func (idx *sourceIndex) parseFormat(expr ast.Expr) (formatSpec, error) {
	lit, ok := unwrap(expr).(*ast.CompositeLit)
	if !ok {
		return formatSpec{}, fmt.Errorf("expected format composite")
	}
	fields := make(map[string]ast.Expr)
	for _, elt := range lit.Elts {
		kv, ok := elt.(*ast.KeyValueExpr)
		if !ok {
			return formatSpec{}, fmt.Errorf("format contains positional field")
		}
		fields[identName(kv.Key)] = kv.Value
	}
	var out formatSpec
	var err error
	if e, ok := fields["title"]; ok {
		out.title, err = idx.evalPattern(e)
		if err != nil {
			return out, fmt.Errorf("title: %w", err)
		}
		out.hasTitle = true
	}
	if e, ok := fields["report"]; ok {
		out.report, err = idx.evalPattern(e)
		if err != nil {
			return out, fmt.Errorf("report: %w", err)
		}
		out.hasReport = true
	}
	if e, ok := fields["fmt"]; ok {
		out.fmt, err = evalString(e)
		if err != nil {
			return out, fmt.Errorf("fmt: %w", err)
		}
	}
	if e, ok := fields["alt"]; ok {
		out.alt, err = evalStrings(e)
		if err != nil {
			return out, fmt.Errorf("alt: %w", err)
		}
	}
	if e, ok := fields["stack"]; ok {
		out.stack, err = idx.parseStack(e)
		if err != nil {
			return out, fmt.Errorf("stack: %w", err)
		}
	}
	if e, ok := fields["noStackTrace"]; ok {
		out.noStackTrace, err = evalBool(e)
		if err != nil {
			return out, fmt.Errorf("noStackTrace: %w", err)
		}
	}
	if e, ok := fields["corrupted"]; ok {
		out.corrupted, err = evalBool(e)
		if err != nil {
			return out, fmt.Errorf("corrupted: %w", err)
		}
	}
	if !out.hasTitle || out.fmt == "" {
		return out, fmt.Errorf("format lacks title or fmt")
	}
	return out, nil
}

func (idx *sourceIndex) parseStack(expr ast.Expr) (*stackSpec, error) {
	call, ok := unwrap(expr).(*ast.CallExpr)
	if ok && identName(call.Fun) == "warningStackFmt" {
		stack := &stackSpec{
			parts:  []part{{pattern: pattern{source: warningRipMarker}}, {stackTrace: true}},
			parts2: []part{{pattern: pattern{source: linuxCallMarker}}, {stackTrace: true}},
		}
		for _, arg := range call.Args {
			value, err := evalString(arg)
			if err != nil {
				return nil, err
			}
			stack.skip = append(stack.skip, value)
		}
		return stack, nil
	}
	lit, ok := unwrap(expr).(*ast.CompositeLit)
	if !ok {
		return nil, fmt.Errorf("expected stackFmt")
	}
	fields := make(map[string]ast.Expr)
	for _, elt := range lit.Elts {
		kv, ok := elt.(*ast.KeyValueExpr)
		if !ok {
			return nil, fmt.Errorf("stackFmt contains positional field")
		}
		fields[identName(kv.Key)] = kv.Value
	}
	stack := &stackSpec{}
	var err error
	if e, ok := fields["parts"]; ok {
		stack.parts, err = idx.parseParts(e)
		if err != nil {
			return nil, err
		}
	}
	if e, ok := fields["parts2"]; ok {
		stack.parts2, err = idx.parseParts(e)
		if err != nil {
			return nil, err
		}
	}
	if e, ok := fields["skip"]; ok {
		stack.skip, err = evalStrings(e)
		if err != nil {
			return nil, err
		}
	}
	if e, ok := fields["extractor"]; ok {
		stack.extractor = identName(e)
	}
	return stack, nil
}

func (idx *sourceIndex) parseParts(expr ast.Expr) ([]part, error) {
	lit, ok := unwrap(expr).(*ast.CompositeLit)
	if !ok {
		return nil, fmt.Errorf("expected stack parts")
	}
	var out []part
	for _, elt := range lit.Elts {
		if identName(elt) == "parseStackTrace" {
			out = append(out, part{stackTrace: true})
			continue
		}
		p, err := idx.evalPattern(elt)
		if err != nil {
			return nil, err
		}
		out = append(out, part{pattern: p})
	}
	return out, nil
}

func (idx *sourceIndex) parsePatterns(expr ast.Expr) ([]pattern, error) {
	values, err := evalExprList(expr)
	if err != nil {
		return nil, err
	}
	var out []pattern
	for _, value := range values {
		p, err := idx.evalPattern(value)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, nil
}

func (idx *sourceIndex) evalPattern(expr ast.Expr) (pattern, error) {
	if call, ok := unwrap(expr).(*ast.CallExpr); ok {
		name := identName(call.Fun)
		if name == "compile" || name == "MustCompile" {
			if len(call.Args) != 1 {
				return pattern{}, fmt.Errorf("pattern call has %d args", len(call.Args))
			}
			return evalPatternExpr(call.Args[0])
		}
		if name == "QuoteMeta" {
			value, err := evalString(call.Args[0])
			return pattern{source: quoteMeta(value)}, err
		}
	}
	if id := identName(expr); id != "" {
		switch id {
		case "linuxRipFrame":
			return pattern{source: linuxRipMarker}, nil
		case "linuxCallTrace":
			return pattern{source: linuxCallMarker}, nil
		}
		if value, ok := idx.values[id]; ok {
			return idx.evalPattern(value)
		}
	}
	return evalPatternExpr(expr)
}

func (idx *sourceIndex) parseGlobalStackParams() (globalStackSpec, error) {
	expr, ok := idx.values["linuxStackParams"]
	if !ok {
		return globalStackSpec{}, fmt.Errorf("variable not found")
	}
	lit, ok := unwrap(expr).(*ast.CompositeLit)
	if !ok {
		return globalStackSpec{}, fmt.Errorf("expected stackParams composite")
	}
	fields := make(map[string]ast.Expr)
	for _, elt := range lit.Elts {
		kv, ok := elt.(*ast.KeyValueExpr)
		if !ok {
			return globalStackSpec{}, fmt.Errorf("positional stackParams field")
		}
		fields[identName(kv.Key)] = kv.Value
	}
	var out globalStackSpec
	var err error
	if out.stackStarts, err = idx.parsePatterns(fields["stackStartRes"]); err != nil {
		return out, err
	}
	if out.frames, err = idx.parsePatterns(fields["frameRes"]); err != nil {
		return out, err
	}
	if out.skip, err = evalStrings(fields["skipPatterns"]); err != nil {
		return out, err
	}
	if out.corruptedLines, err = idx.parsePatterns(fields["corruptedLines"]); err != nil {
		return out, err
	}
	if out.stripPrefixes, err = evalStrings(fields["stripFramePrefixes"]); err != nil {
		return out, err
	}
	return out, nil
}

func evalPatternExpr(expr ast.Expr) (pattern, error) {
	value, err := evalString(expr)
	if err != nil {
		return pattern{}, err
	}
	p := pattern{source: value}
	if strings.HasPrefix(p.source, "(?i)") {
		p.source = strings.TrimPrefix(p.source, "(?i)")
		p.icase = true
	}
	return p, nil
}

func evalStrings(expr ast.Expr) ([]string, error) {
	values, err := evalExprList(expr)
	if err != nil {
		return nil, err
	}
	result := make([]string, 0, len(values))
	for _, value := range values {
		text, err := evalString(value)
		if err != nil {
			return nil, err
		}
		result = append(result, text)
	}
	return result, nil
}

func evalExprList(expr ast.Expr) ([]ast.Expr, error) {
	lit, ok := unwrap(expr).(*ast.CompositeLit)
	if !ok {
		return nil, fmt.Errorf("expected expression list")
	}
	return lit.Elts, nil
}

func evalBool(expr ast.Expr) (bool, error) {
	lit, ok := unwrap(expr).(*ast.Ident)
	if !ok || (lit.Name != "true" && lit.Name != "false") {
		return false, fmt.Errorf("expected boolean")
	}
	return lit.Name == "true", nil
}

func evalString(expr ast.Expr) (string, error) {
	expr = unwrap(expr)
	switch value := expr.(type) {
	case *ast.BasicLit:
		if value.Kind != token.STRING {
			return "", fmt.Errorf("expected string literal")
		}
		return strconv.Unquote(value.Value)
	case *ast.BinaryExpr:
		if value.Op != token.ADD {
			return "", fmt.Errorf("unsupported string operator %s", value.Op)
		}
		left, err := evalString(value.X)
		if err != nil {
			return "", err
		}
		right, err := evalString(value.Y)
		return left + right, err
	case *ast.CallExpr:
		name := identName(value.Fun)
		if _, ok := value.Fun.(*ast.ArrayType); ok && len(value.Args) == 1 {
			return evalString(value.Args[0])
		}
		if name == "QuoteMeta" {
			arg, err := evalString(value.Args[0])
			return quoteMeta(arg), err
		}
		if name == "String" && len(value.Args) == 0 {
			if sel, ok := value.Fun.(*ast.SelectorExpr); ok && identName(sel.X) == "linuxRipFrame" {
				return linuxRipMarker, nil
			}
		}
		return "", fmt.Errorf("unsupported string call %s", name)
	case *ast.SelectorExpr:
		if value.Sel.Name == "String" && identName(value.X) == "linuxRipFrame" {
			return linuxRipMarker, nil
		}
		return "", fmt.Errorf("unsupported selector")
	default:
		return "", fmt.Errorf("unsupported string expression %T", expr)
	}
}

func unwrap(expr ast.Expr) ast.Expr {
	if paren, ok := expr.(*ast.ParenExpr); ok {
		return unwrap(paren.X)
	}
	if unary, ok := expr.(*ast.UnaryExpr); ok && unary.Op == token.AND {
		return unwrap(unary.X)
	}
	return expr
}

func identName(expr ast.Expr) string {
	switch value := expr.(type) {
	case *ast.Ident:
		return value.Name
	case *ast.SelectorExpr:
		return value.Sel.Name
	}
	return ""
}

func quoteMeta(value string) string {
	const meta = `\\.+*?()|[]{}^$`
	var out strings.Builder
	for _, ch := range value {
		if strings.ContainsRune(meta, ch) {
			out.WriteByte('\\')
		}
		out.WriteRune(ch)
	}
	return out.String()
}

func writeOutput(path string, specs []oopsSpec, stack globalStackSpec,
	anchors []pattern, typeRules []titleTypeRule) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	var b strings.Builder
	b.WriteString("// Code generated by tools/linux_report_format_gen; DO NOT EDIT.\n")
	b.WriteString("static std::vector<OopsSpec> BuildGeneratedOopsSpecs()\n{\n")
	b.WriteString("    std::vector<OopsSpec> specs;\n")
	b.WriteString(fmt.Sprintf("    specs.reserve(%d);\n", len(specs)))
	for _, spec := range specs {
		b.WriteString("    specs.push_back(MakeOops(")
		b.WriteString(cppQuote(spec.header))
		b.WriteString(", {\n")
		for _, format := range spec.formats {
			b.WriteString("        MakeFormat(")
			if format.hasTitle {
				b.WriteString("MakePattern(")
				b.WriteString(cppQuote(format.title.source))
				b.WriteString(fmt.Sprintf(", %t)", format.title.icase))
			} else {
				b.WriteString("NoPattern()")
			}
			b.WriteString(", ")
			if format.hasReport {
				b.WriteString("MakePattern(")
				b.WriteString(cppQuote(format.report.source))
				b.WriteString(fmt.Sprintf(", %t)", format.report.icase))
			} else {
				b.WriteString("NoPattern()")
			}
			b.WriteString(", ")
			b.WriteString(cppQuote(format.fmt))
			b.WriteString(", {")
			for i, alt := range format.alt {
				if i > 0 {
					b.WriteString(", ")
				}
				b.WriteString(cppQuote(alt))
			}
			b.WriteString("}, ")
			if format.stack == nil {
				b.WriteString("NoStack()")
			} else {
				b.WriteString("MakeStack({")
				writeParts(&b, format.stack.parts)
				b.WriteString("}, {")
				writeParts(&b, format.stack.parts2)
				b.WriteString("}, {")
				for i, skip := range format.stack.skip {
					if i > 0 {
						b.WriteString(", ")
					}
					b.WriteString(cppQuote(skip))
				}
				b.WriteString("}, ")
				b.WriteString(cppQuote(format.stack.extractor))
				b.WriteString(")")
			}
			b.WriteString(fmt.Sprintf(", %t, %t),\n", format.noStackTrace, format.corrupted))
		}
		b.WriteString("    }, {")
		for i, suppression := range spec.suppressions {
			if i > 0 {
				b.WriteString(", ")
			}
			b.WriteString("MakePattern(")
			b.WriteString(cppQuote(suppression.source))
			b.WriteString(fmt.Sprintf(", %t)", suppression.icase))
		}
		b.WriteString("}));\n")
	}
	b.WriteString("    return specs;\n}\n")
	b.WriteString("\nstatic StackParamsSpec BuildGeneratedStackParamsSpec()\n{\n")
	b.WriteString("    return MakeStackParams({")
	writePatterns(&b, stack.stackStarts)
	b.WriteString("}, {")
	writePatterns(&b, stack.frames)
	b.WriteString("}, {")
	writeStrings(&b, stack.skip)
	b.WriteString("}, {")
	writePatterns(&b, stack.corruptedLines)
	b.WriteString("}, {")
	writeStrings(&b, stack.stripPrefixes)
	b.WriteString("});\n}\n")
	b.WriteString("\nstatic std::vector<PatternSpec> BuildGeneratedStallAnchorPatterns()\n{\n")
	b.WriteString("    return {")
	writePatterns(&b, anchors)
	b.WriteString("};\n}\n")
	b.WriteString("\nstatic std::vector<TitleTypeRule> BuildGeneratedTitleTypeRules()\n{\n")
	b.WriteString("    return {\n")
	for _, rule := range typeRules {
		b.WriteString("        MakeTitleTypeRule({")
		writeStrings(&b, rule.prefixes)
		b.WriteString("}, ")
		b.WriteString(cppQuote(rule.reportType))
		b.WriteString("),\n")
	}
	b.WriteString("    };\n}\n")
	return os.WriteFile(path, []byte(b.String()), 0o644)
}

func writePatterns(b *strings.Builder, patterns []pattern) {
	for i, item := range patterns {
		if i > 0 {
			b.WriteString(", ")
		}
		b.WriteString("MakePattern(")
		b.WriteString(cppQuote(item.source))
		b.WriteString(fmt.Sprintf(", %t)", item.icase))
	}
}

func writeStrings(b *strings.Builder, values []string) {
	for i, item := range values {
		if i > 0 {
			b.WriteString(", ")
		}
		b.WriteString(cppQuote(item))
	}
}

func writeParts(b *strings.Builder, parts []part) {
	for i, item := range parts {
		if i > 0 {
			b.WriteString(", ")
		}
		if item.stackTrace {
			b.WriteString("StackTracePart()")
		} else {
			b.WriteString("RegexPart(MakePattern(")
			b.WriteString(cppQuote(item.pattern.source))
			b.WriteString(fmt.Sprintf(", %t))", item.pattern.icase))
		}
	}
}

func cppQuote(value string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, ch := range []byte(value) {
		switch ch {
		case '\\':
			b.WriteString("\\\\")
		case '"':
			b.WriteString("\\\"")
		case '\n':
			b.WriteString("\\n")
		case '\r':
			b.WriteString("\\r")
		case '\t':
			b.WriteString("\\t")
		default:
			if ch < 0x20 || ch >= 0x7f {
				b.WriteString(fmt.Sprintf("\\x%02x", ch))
			} else {
				b.WriteByte(ch)
			}
		}
	}
	b.WriteByte('"')
	return b.String()
}
