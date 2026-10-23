// Copyright 2026 reFuzz project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE.
//
// csource_header_emit — Build-time tool that bundles the syzkaller
// executor common headers (../executor/common*.h, kvm*.h, android/*.h)
// into a single self-contained C++ string constant the csource module
// splices through cpp at Write() time.
//
// Behavior is the reFuzz-side equivalent of upstream
// executor.CommonHeader (executor/embed.go): start from common.h,
// iteratively replace `#include "<file>"` and `#include
// "android/<file>"` directives with the referenced file's contents
// until no more replacements happen, then assert every embedded file
// got transitively included, then strip line comments.
//
// reFuzz reimplements this in its own build-time tool — it does NOT
// import github.com/google/syzkaller/executor — so the C++ csource
// module sees only a generated std::string and has zero syzkaller
// runtime dependency. Per Epic 4 plan §3 binding (Common header).
//
// Output: crash/repro/csource/src/csource_common_source.gen.cpp
// emitting `extern const std::string kCsourceCommonSource`. Encoding
// mirrors tools/syz_usbgen_emit (every byte as \xNN).
//
// CI golden test (main_test.go) re-emits in-memory and asserts
// byte-equal vs the checked-in .gen.cpp.

package main

import (
	"bufio"
	"bytes"
	"flag"
	"fmt"
	"log"
	"maps"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
)

// Files excluded from transitive expansion (mirror executor/embed.go
// rule: skip the entry point itself and the placeholder ext example).
var excludedFromExpansion = map[string]bool{
	"common.h":              true,
	"common_ext_example.h":  true,
}

func main() {
	defaultRoot := relativeFromExecutable("../../..")
	defaultOut := relativeFromExecutable(
		"../../crash/repro/csource/src/csource_common_source.gen.cpp")

	syzRoot := flag.String("syzkaller-root", defaultRoot,
		"path to syzkaller repo root (containing executor/)")
	outPath := flag.String("out", defaultOut,
		"path to output .gen.cpp")
	flag.Parse()

	if *syzRoot == "" || !isDir(*syzRoot) {
		// Fall back to walking up from the source file's location:
		// useful when the binary path is unstable (e.g., go run).
		root, ok := findSyzkallerRoot()
		if !ok {
			log.Fatalf("syzkaller-root not found; pass -syzkaller-root explicitly")
		}
		*syzRoot = root
	}

	bundled, err := buildCommonHeader(filepath.Join(*syzRoot, "executor"))
	if err != nil {
		log.Fatalf("buildCommonHeader: %v", err)
	}
	if err := writeSource(*outPath, bundled); err != nil {
		log.Fatalf("write: %v", err)
	}
	fmt.Fprintf(os.Stderr,
		"csource_header_emit: bundled common header is %d bytes\n",
		len(bundled))
}

func isDir(p string) bool {
	st, err := os.Stat(p)
	return err == nil && st.IsDir()
}

func relativeFromExecutable(rel string) string {
	exe, err := os.Executable()
	if err != nil {
		return rel
	}
	return filepath.Join(filepath.Dir(exe), rel)
}

// findSyzkallerRoot walks up from CWD looking for a directory that
// contains both `executor/common.h` and `prog/`.
func findSyzkallerRoot() (string, bool) {
	cwd, err := os.Getwd()
	if err != nil {
		return "", false
	}
	for d := cwd; d != "/" && d != "."; d = filepath.Dir(d) {
		if _, err := os.Stat(filepath.Join(d, "executor", "common.h")); err == nil {
			if _, err := os.Stat(filepath.Join(d, "prog")); err == nil {
				return d, true
			}
		}
	}
	return "", false
}

// buildCommonHeader is the reFuzz-side port of upstream
// executor.CommonHeader (executor/embed.go). Reads `common.h` plus
// every `common*.h`, `kvm*.h`, and `android/*.h` under execDir, then
// iteratively expands quoted includes until none remain in the data
// or in the candidate set. Strips line comments at the end (keeps
// `//%` directives).
func buildCommonHeader(execDir string) ([]byte, error) {
	data, err := os.ReadFile(filepath.Join(execDir, "common.h"))
	if err != nil {
		return nil, fmt.Errorf("read common.h: %w", err)
	}

	// Discover all embedded headers — same globs as embed.go's
	// `//go:embed common*.h kvm*.h android/*.h` directive.
	headers := make(map[string][]byte)
	for _, glob := range []string{
		"common*.h",
		"kvm*.h",
		filepath.Join("android", "*.h"),
	} {
		matches, err := filepath.Glob(filepath.Join(execDir, glob))
		if err != nil {
			return nil, fmt.Errorf("glob %s: %w", glob, err)
		}
		for _, full := range matches {
			rel, err := filepath.Rel(execDir, full)
			if err != nil {
				return nil, err
			}
			rel = filepath.ToSlash(rel)
			base := path.Base(rel)
			if excludedFromExpansion[base] {
				continue
			}
			body, err := os.ReadFile(full)
			if err != nil {
				return nil, fmt.Errorf("read %s: %w", rel, err)
			}
			headers[rel] = body
		}
	}

	unused := maps.Clone(headers)
	for {
		replaced := false
		for relPath, contents := range headers {
			base := path.Base(relPath)
			needle := []byte("#include \"" + base + "\"")
			if !bytes.Contains(data, needle) {
				androidNeedle := []byte("#include \"android/" + base + "\"")
				if !bytes.Contains(data, androidNeedle) {
					continue
				}
				needle = androidNeedle
			}
			data = bytes.ReplaceAll(data, needle, contents)
			delete(unused, relPath)
			replaced = true
		}
		if !replaced {
			break
		}
	}
	if len(unused) != 0 {
		names := make([]string, 0, len(unused))
		for k := range unused {
			names = append(names, k)
		}
		return nil, fmt.Errorf("transitive expansion incomplete; %d header(s) "+
			"never referenced: %v", len(names), names)
	}

	// Strip line comments — same patterns as executor.CommonHeader
	// (executor/embed.go:67-74). Keep `//%` directives.
	for _, pattern := range []string{
		"(\n|^)\\s*//$",
		"(\n|^)\\s*//[^%].*",
		"\\s*//$",
		"\\s*//[^%].*",
	} {
		data = regexp.MustCompile(pattern).ReplaceAll(data, nil)
	}

	return data, nil
}

const headerTemplate = `// AUTOGENERATED by tools/csource_header_emit. DO NOT EDIT.
// Source: syzkaller executor/common.h with all transitive
// quoted includes inlined (mirror of executor.CommonHeader in
// executor/embed.go). Regenerate with ` + "`make syz_regen_csource_common`" + `.
//
// At csource::Write() time this string is fed to ` + "`cpp -nostdinc -undef`" + `
// with per-program SYZ_* defines so the preprocessor prunes
// non-applicable #if blocks. See common.go::createCommonHeader.

#include <string>

namespace refuzz::crash::repro::csource {

extern const std::string kCsourceCommonSource;

const std::string kCsourceCommonSource = std::string(
`

func writeSource(path string, bundled []byte) error {
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

	fmt.Fprint(w, headerTemplate)
	emitStringChunks(w, bundled, "    ")
	fmt.Fprintf(w, ", %d);\n\n", len(bundled))
	fmt.Fprintln(w, "} // namespace refuzz::crash::repro::csource")
	return nil
}

// emitStringChunks writes bytes of `s` as adjacent C++ string
// literals (each up to chunkBytes raw bytes → ~1024 source chars per
// chunk). \xNN encoding throughout — no printable shortcuts so the
// greedy hex-escape rule never bites.
func emitStringChunks(w *bufio.Writer, s []byte, indent string) {
	const chunkBytes = 256
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

func cppByteLiteral(s []byte) string {
	var b strings.Builder
	b.Grow(len(s) * 4)
	for _, c := range s {
		b.WriteByte('\\')
		b.WriteByte('x')
		b.WriteByte(hexDigit(c >> 4))
		b.WriteByte(hexDigit(c & 0x0f))
	}
	return b.String()
}

func hexDigit(n byte) byte {
	if n < 10 {
		return '0' + n
	}
	return 'A' + n - 10
}
