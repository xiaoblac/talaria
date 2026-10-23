// syz_usbgen_emit — port of upstream sys/linux/init_vusb_ids.go data
// to a C++ source file consumable by reFuzz's program/syz/linux/
// SpecialType bodies for usb_device_descriptor / *_printer / *_hid.
//
// Path: upstream Linux kernel USB driver match tables → syzkaller's
// own syz-usbgen tool → init_vusb_ids.go (Go source). reFuzz does NOT
// re-extract from kernel sources; this tool only takes the Go file
// produced by upstream syz-usbgen and dumps the same data into C++.
//
// We use go/parser + go/ast because both `usbIds` / `usbIdsAll` /
// `hidIds` / `hidIdsAll` are unexported package-level vars in
// sys/linux. No external Go package can import them, so reflection
// from a sibling tool cannot reach the values. AST evaluation of the
// declarations themselves is the supported path.
//
// Output is two files (paths relative to repo root):
//   program/include/refuzz/program/syz/linux/generated/usb_ids.gen.hpp
//   program/src/syz/linux/generated/usb_ids.gen.cpp
//
// Emitted symbols (namespace refuzz::program::syz::linux_usb_ids):
//   extern const std::unordered_map<std::string, std::string> kUsbIds
//   extern const std::unordered_map<std::string, std::string> kHidIds
//   extern const std::string                                  kUsbIdsAll
//   extern const std::string                                  kHidIdsAll
//
// The .cpp file size is approximately 4× the input file (~2.5MB) due
// to byte-by-byte \xNN encoding. This is intentional: it sidesteps
// the C++ \xNN greedy-consume rule and keeps the emitter trivial.
// Compile cost on a normal host is < 60s — well within the plan §8
// stop-condition bound.

package main

import (
	"bufio"
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strconv"
)

func main() {
	defaultIn := relativeFromExecutable("../../../sys/linux/init_vusb_ids.go")
	defaultHpp := relativeFromExecutable(
		"../../program/include/refuzz/program/syz/linux/generated/usb_ids.gen.hpp")
	defaultCpp := relativeFromExecutable(
		"../../program/src/syz/linux/generated/usb_ids.gen.cpp")

	inFlag := flag.String("in", defaultIn, "path to upstream init_vusb_ids.go")
	outHpp := flag.String("hpp", defaultHpp, "path to output .gen.hpp")
	outCpp := flag.String("cpp", defaultCpp, "path to output .gen.cpp")
	flag.Parse()

	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, *inFlag, nil, 0)
	if err != nil {
		log.Fatalf("parse %s: %v", *inFlag, err)
	}

	usbIds, err := evalMap(file, "usbIds")
	if err != nil {
		log.Fatalf("eval usbIds: %v", err)
	}
	hidIds, err := evalMap(file, "hidIds")
	if err != nil {
		log.Fatalf("eval hidIds: %v", err)
	}
	usbIdsAll, err := evalConcat(file, "usbIdsAll", map[string]map[string]string{
		"usbIds": usbIds,
	})
	if err != nil {
		log.Fatalf("eval usbIdsAll: %v", err)
	}
	hidIdsAll, err := evalConcat(file, "hidIdsAll", map[string]map[string]string{
		"hidIds": hidIds,
	})
	if err != nil {
		log.Fatalf("eval hidIdsAll: %v", err)
	}

	if err := writeHeader(*outHpp); err != nil {
		log.Fatalf("write header: %v", err)
	}
	if err := writeSource(*outCpp, *inFlag, usbIds, hidIds, usbIdsAll, hidIdsAll); err != nil {
		log.Fatalf("write source: %v", err)
	}

	fmt.Fprintf(os.Stderr,
		"syz_usbgen_emit: usbIds=%d entries, hidIds=%d entries, "+
			"usbIdsAll=%d bytes, hidIdsAll=%d bytes\n",
		len(usbIds), len(hidIds), len(usbIdsAll), len(hidIdsAll))
}

// relativeFromExecutable resolves rel against the directory holding
// the running binary. Falls back to rel itself if Executable() fails.
func relativeFromExecutable(rel string) string {
	exe, err := os.Executable()
	if err != nil {
		return rel
	}
	return filepath.Join(filepath.Dir(exe), rel)
}

// findVar returns the *ast.ValueSpec for the named top-level var, or
// nil if absent.
func findVar(file *ast.File, name string) *ast.ValueSpec {
	for _, d := range file.Decls {
		gd, ok := d.(*ast.GenDecl)
		if !ok || gd.Tok != token.VAR {
			continue
		}
		for _, spec := range gd.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			for _, ident := range vs.Names {
				if ident.Name == name {
					return vs
				}
			}
		}
	}
	return nil
}

// evalStringLit unquotes a Go string literal.
func evalStringLit(b *ast.BasicLit) (string, error) {
	if b.Kind != token.STRING {
		return "", fmt.Errorf("not a string literal: kind=%v", b.Kind)
	}
	return strconv.Unquote(b.Value)
}

// evalStringExpr evaluates a Go expression that resolves to a string.
// Supported shapes:
//   - *ast.BasicLit with kind STRING (single quoted literal)
//   - *ast.BinaryExpr with Op==ADD, both sides recursively string-valued
//   - *ast.IndexExpr with X=*ast.Ident, Index=*ast.BasicLit STRING:
//     looked up in lookup[X.Name][Index.Value-unquoted].
//
// Anything else returns an error so the emitter fails loud rather than
// silently producing wrong data.
func evalStringExpr(expr ast.Expr, lookup map[string]map[string]string) (string, error) {
	switch e := expr.(type) {
	case *ast.BasicLit:
		return evalStringLit(e)
	case *ast.BinaryExpr:
		if e.Op != token.ADD {
			return "", fmt.Errorf("unsupported binary op: %v", e.Op)
		}
		left, err := evalStringExpr(e.X, lookup)
		if err != nil {
			return "", err
		}
		right, err := evalStringExpr(e.Y, lookup)
		if err != nil {
			return "", err
		}
		return left + right, nil
	case *ast.IndexExpr:
		ident, ok := e.X.(*ast.Ident)
		if !ok {
			return "", fmt.Errorf("index expr X is not an identifier")
		}
		mp, ok := lookup[ident.Name]
		if !ok {
			return "", fmt.Errorf("unknown source map: %s", ident.Name)
		}
		idx, ok := e.Index.(*ast.BasicLit)
		if !ok {
			return "", fmt.Errorf("index is not a literal")
		}
		key, err := evalStringLit(idx)
		if err != nil {
			return "", err
		}
		v, ok := mp[key]
		if !ok {
			return "", fmt.Errorf("%s[%q] not found", ident.Name, key)
		}
		return v, nil
	case *ast.ParenExpr:
		return evalStringExpr(e.X, lookup)
	}
	return "", fmt.Errorf("unsupported expr type: %T", expr)
}

// evalMap evaluates `var <name> = map[string]string{ "k": "v", ... }`.
func evalMap(file *ast.File, name string) (map[string]string, error) {
	vs := findVar(file, name)
	if vs == nil {
		return nil, fmt.Errorf("var %s not found", name)
	}
	if len(vs.Values) != 1 {
		return nil, fmt.Errorf("var %s expected single value, got %d",
			name, len(vs.Values))
	}
	cl, ok := vs.Values[0].(*ast.CompositeLit)
	if !ok {
		return nil, fmt.Errorf("var %s value is not a composite literal", name)
	}
	out := make(map[string]string, len(cl.Elts))
	for i, elt := range cl.Elts {
		kv, ok := elt.(*ast.KeyValueExpr)
		if !ok {
			return nil, fmt.Errorf("var %s: elt %d is not key-value", name, i)
		}
		keyLit, ok := kv.Key.(*ast.BasicLit)
		if !ok {
			return nil, fmt.Errorf("var %s: elt %d key not a literal", name, i)
		}
		key, err := evalStringLit(keyLit)
		if err != nil {
			return nil, fmt.Errorf("var %s: elt %d key: %v", name, i, err)
		}
		val, err := evalStringExpr(kv.Value, nil)
		if err != nil {
			return nil, fmt.Errorf("var %s: elt %d (%q) value: %v",
				name, i, key, err)
		}
		if _, dup := out[key]; dup {
			return nil, fmt.Errorf("var %s: duplicate key %q", name, key)
		}
		out[key] = val
	}
	return out, nil
}

// evalConcat evaluates `var <name> = <map>["k1"] + <map>["k2"] + ...`
// resolving IndexExprs against the supplied source map(s).
func evalConcat(file *ast.File, name string,
	lookup map[string]map[string]string) (string, error) {
	vs := findVar(file, name)
	if vs == nil {
		return "", fmt.Errorf("var %s not found", name)
	}
	if len(vs.Values) != 1 {
		return "", fmt.Errorf("var %s expected single value, got %d",
			name, len(vs.Values))
	}
	return evalStringExpr(vs.Values[0], lookup)
}

// =========================================================================
// Emission
// =========================================================================

const headerTemplate = `// AUTOGENERATED by tools/syz_usbgen_emit. DO NOT EDIT.
// Source: sys/linux/init_vusb_ids.go (in turn produced by
// syzkaller's tools/syz-usbgen from Linux kernel USB driver match
// tables). Regenerate with ` + "`make syz_regen_usb`" + `.

#pragma once

#include <string>
#include <unordered_map>

namespace refuzz::program::syz::linux_usb_ids {

// Per-driver map of USB device IDs. Each value is a binary blob of
// concatenated 17-byte UsbDeviceID records (matchFlags|idVendor|
// idProduct|bcdDeviceLo|bcdDeviceHi|bDeviceClass|bDeviceSubClass|
// bDeviceProtocol|bInterfaceClass|bInterfaceSubClass|bInterfaceProtocol|
// bInterfaceNumber, little-endian as defined by include/linux/mod_devicetable.h
// USB_DEVICE_ID).
extern const std::unordered_map<std::string, std::string> kUsbIds;

// Per-driver map of HID device IDs. Each value is a binary blob of
// concatenated 12-byte HidDeviceID records (bus|group|vendor|product,
// little-endian).
extern const std::unordered_map<std::string, std::string> kHidIds;

// Concatenation of selected kUsbIds entries in the upstream-defined
// order. Indexed by random offset / 17 in randUsbDeviceID.
extern const std::string kUsbIdsAll;

// Concatenation of selected kHidIds entries in the upstream-defined
// order. Indexed by random offset / 12 in the HID descriptor body.
extern const std::string kHidIdsAll;

} // namespace refuzz::program::syz::linux_usb_ids
`

func writeHeader(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(headerTemplate), 0o644)
}

// writeSource emits the .gen.cpp.
//
// Layout:
//   - kUsbIds: unordered_map initializer with entries sorted by key
//     (alphabetical). Sorting makes the .gen.cpp byte-stable across
//     runs without affecting runtime hash bucket order.
//   - kHidIds: same.
//   - kUsbIdsAll / kHidIdsAll: single string per blob.
//
// All values use std::string(byteLitChunks..., totalLen). byteLitChunks
// are series of adjacent C++ string literals, each up to chunkChars
// source characters. Adjacent literals concatenate at compile time.
func writeSource(path, inputPath string,
	usbIds, hidIds map[string]string,
	usbIdsAll, hidIdsAll string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	w := bufio.NewWriter(f)
	defer w.Flush()

	fmt.Fprintln(w, "// AUTOGENERATED by tools/syz_usbgen_emit. DO NOT EDIT.")
	fmt.Fprintf(w, "// Source: %s\n", filepath.ToSlash(inputPath))
	fmt.Fprintln(w, "// Regenerate with `make syz_regen_usb`.")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "#include \"refuzz/program/syz/linux/generated/usb_ids.gen.hpp\"")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "namespace refuzz::program::syz::linux_usb_ids {")
	fmt.Fprintln(w, "")

	// kUsbIds
	fmt.Fprintln(w, "const std::unordered_map<std::string, std::string> kUsbIds = {")
	emitMap(w, usbIds)
	fmt.Fprintln(w, "};")
	fmt.Fprintln(w, "")

	// kHidIds
	fmt.Fprintln(w, "const std::unordered_map<std::string, std::string> kHidIds = {")
	emitMap(w, hidIds)
	fmt.Fprintln(w, "};")
	fmt.Fprintln(w, "")

	// kUsbIdsAll
	fmt.Fprintln(w, "const std::string kUsbIdsAll = std::string(")
	emitStringChunks(w, usbIdsAll, "    ")
	fmt.Fprintf(w, ", %d);\n", len(usbIdsAll))
	fmt.Fprintln(w, "")

	// kHidIdsAll
	fmt.Fprintln(w, "const std::string kHidIdsAll = std::string(")
	emitStringChunks(w, hidIdsAll, "    ")
	fmt.Fprintf(w, ", %d);\n", len(hidIdsAll))
	fmt.Fprintln(w, "")

	fmt.Fprintln(w, "} // namespace refuzz::program::syz::linux_usb_ids")
	return nil
}

// emitMap emits map entries as a sorted (by key) initializer list,
// each on its own line: {"<key>", std::string(<bytes>, <len>)},
func emitMap(w *bufio.Writer, m map[string]string) {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		v := m[k]
		fmt.Fprintf(w, "    {%s, std::string(", cppKeyLiteral(k))
		// Inline single-line literal for short values; chunked otherwise.
		if len(v) <= 64 {
			fmt.Fprintf(w, "\"%s\", %d)},\n", cppByteLiteral(v), len(v))
		} else {
			fmt.Fprintln(w)
			emitStringChunks(w, v, "        ")
			fmt.Fprintf(w, ", %d)},\n", len(v))
		}
	}
}

// cppKeyLiteral returns a C++ string literal for a map key. Map keys
// are human-readable driver names — they're plain ASCII in upstream,
// but a few entries contain spaces / hyphens / other punctuation.
// We keep printable ASCII characters as-is (escaping " and \) and
// fall back to \xNN for anything outside that range.
func cppKeyLiteral(s string) string {
	out := make([]byte, 0, len(s)+2)
	out = append(out, '"')
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '\\' || c == '"':
			out = append(out, '\\', c)
		case c >= 0x20 && c < 0x7f:
			out = append(out, c)
		default:
			out = append(out, '\\', 'x')
			out = append(out, hexDigit(c>>4), hexDigit(c&0x0f))
			// Defensive: terminate the literal and start a new one
			// to prevent the next char from being absorbed by the
			// hex escape's greedy lexing.
			if i+1 < len(s) && isHexDigit(s[i+1]) {
				out = append(out, '"', '"')
			}
		}
	}
	out = append(out, '"')
	return string(out)
}

// emitStringChunks writes the bytes of `s` as a series of adjacent
// C++ string literals, each ≤ chunkChars source characters and each
// indented with `indent`. The result is suitable as the first argument
// of std::string(<chunks>, <len>).
//
// Every byte is emitted as `\xNN` (uppercase hex, 2 digits). This is
// 4× the raw byte count in source size but eliminates the C++ greedy
// hex-escape rule (\x reads as many hex digits as follow). Each chunk
// ends with `"` and a newline; the next chunk starts with `<indent>"`,
// giving compile-time literal concatenation.
func emitStringChunks(w *bufio.Writer, s, indent string) {
	const chunkBytes = 256 // 256 raw bytes → ~1024 source chars per chunk
	if len(s) == 0 {
		fmt.Fprintf(w, "%s\"\"", indent)
		return
	}
	for i := 0; i < len(s); i += chunkBytes {
		end := i + chunkBytes
		if end > len(s) {
			end = len(s)
		}
		fmt.Fprintf(w, "%s\"%s\"", indent, cppByteLiteral(s[i:end]))
		if end < len(s) {
			fmt.Fprintln(w)
		}
	}
}

// cppByteLiteral encodes every byte as \xNN (no printable shortcuts).
// This is unambiguous regardless of surrounding context.
func cppByteLiteral(s string) string {
	out := make([]byte, 0, len(s)*4)
	for i := 0; i < len(s); i++ {
		c := s[i]
		out = append(out, '\\', 'x')
		out = append(out, hexDigit(c>>4), hexDigit(c&0x0f))
	}
	return string(out)
}

func hexDigit(n byte) byte {
	if n < 10 {
		return '0' + n
	}
	return 'A' + n - 10
}

func isHexDigit(c byte) bool {
	return (c >= '0' && c <= '9') ||
		(c >= 'a' && c <= 'f') ||
		(c >= 'A' && c <= 'F')
}
