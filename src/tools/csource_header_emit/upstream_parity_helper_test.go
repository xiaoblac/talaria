// Copyright 2026 reFuzz project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE.
//
// Test-only helper exposing upstream `executor.CommonHeader` bytes
// for the parity check. Build-time-only — the `_test.go` suffix
// keeps this file out of production builds, so `go run
// ./tools/csource_header_emit` does not pull
// `github.com/google/syzkaller/executor`. The C++ csource runtime
// sees only the generated kCsourceCommonSource std::string.

package main

import (
	"testing"

	"github.com/google/syzkaller/executor"
)

func loadUpstreamCommonHeader(t *testing.T) []byte {
	t.Helper()
	out := executor.CommonHeader
	if len(out) == 0 {
		t.Skip("upstream executor.CommonHeader is empty")
		return nil
	}
	cp := make([]byte, len(out))
	copy(cp, out)
	return cp
}
