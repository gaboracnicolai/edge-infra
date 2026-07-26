// Package ciguard holds meta-tests about the CI configuration itself.
//
// ── WHY THIS EXISTS ──────────────────────────────────────────────────────────
//
// Build-tagged tests are invisible to `go test ./...`. CI therefore opts each one
// in by hand, per package, with a `-run` filter:
//
//	go test -tags integration ./cmd/server/    -run TestXDS
//	go test -tags integration ./internal/store/ -run TestLoadSnapshot_OSB
//
// That is opt-in BY NAME. A new integration test whose name does not happen to
// match an existing prefix — or that lives in a package no invocation names —
// compiles, is committed, is reviewed, and then silently never runs. Nothing
// reports it. It reads as coverage and is not.
//
// This repo has already lost that bet twice: internal/migrate's four
// schema-baseline tests were never executed by any workflow, and
// TestVerifyColocation was never matched by either of the two `-run` filters
// aimed at its package — the same invariant cmd/server/admin.go cites as the
// reason the Admin API may share this process.
//
// This test closes the MECHANISM rather than those two instances: it enumerates
// every integration-tagged test function in the tree, enumerates every
// integration invocation in .github/workflows, and fails if any test is not
// reachable by at least one invocation. It is deliberately NOT build-tagged, so
// it runs in the plain `go test ./...` gate that every push already executes.
//
// It cannot prove a wired test actually EXECUTES (several skip themselves when a
// required DSN is unset). The workflow steps assert that separately by rejecting
// SKIP output; see .github/workflows/osb-test.yaml.
package ciguard

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// integrationInvocation is one `go test -tags integration` command found in a
// workflow: the package it targets and the -run filter it applies (empty = all).
type integrationInvocation struct {
	workflow string
	pkg      string // normalised, e.g. "cmd/server"
	run      string // -run value, "" when absent
}

// taggedTest is one Test function inside a file carrying //go:build integration.
type taggedTest struct {
	pkg  string // normalised dir, e.g. "internal/migrate"
	name string
	file string
}

var (
	buildTagRE = regexp.MustCompile(`(?m)^//go:build\s+integration\b`)
	testFuncRE = regexp.MustCompile(`(?m)^func\s+(Test[A-Za-z0-9_]*)\s*\(`)
	runFlagRE  = regexp.MustCompile(`-run[= ]+([^\s]+)`)
	pkgArgRE   = regexp.MustCompile(`(^|\s)(\./[^\s]*)`)
)

// repoRoot walks up from the test's working directory to the module root.
func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("go.mod not found walking up from the test directory")
		}
		dir = parent
	}
}

// unquote removes one layer of surrounding shell quoting from a token.
func unquote(s string) string {
	if len(s) >= 2 {
		if (s[0] == '\'' && s[len(s)-1] == '\'') || (s[0] == '"' && s[len(s)-1] == '"') {
			return s[1 : len(s)-1]
		}
	}
	return s
}

// normalisePkg turns a `go test` package argument ("./internal/store/") or a
// filesystem dir into a comparable form ("internal/store").
func normalisePkg(p string) string {
	p = strings.TrimPrefix(p, "./")
	p = strings.TrimSuffix(p, "/")
	if p == "" || p == "." {
		return "."
	}
	return p
}

// collectTaggedTests finds every Test function in a file whose build constraint
// is `integration`.
func collectTaggedTests(t *testing.T, root string) []taggedTest {
	t.Helper()
	var out []taggedTest
	skipDirs := map[string]bool{".git": true, "node_modules": true, "vendor": true, ".venv-integration": true}

	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if skipDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, "_test.go") {
			return nil
		}
		b, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		src := string(b)
		// Only the build-constraint region matters; constraints must precede the
		// package clause, so bound the search there to avoid matching a comment.
		head := src
		if i := strings.Index(src, "\npackage "); i > 0 {
			head = src[:i]
		}
		if !buildTagRE.MatchString(head) {
			return nil
		}
		rel, relErr := filepath.Rel(root, filepath.Dir(path))
		if relErr != nil {
			return relErr
		}
		for _, m := range testFuncRE.FindAllStringSubmatch(src, -1) {
			out = append(out, taggedTest{
				pkg:  normalisePkg(filepath.ToSlash(rel)),
				name: m[1],
				file: filepath.ToSlash(strings.TrimPrefix(path, root+string(filepath.Separator))),
			})
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk repo: %v", err)
	}
	return out
}

// collectInvocations parses .github/workflows for `go test … -tags integration …`
// command lines.
func collectInvocations(t *testing.T, root string) []integrationInvocation {
	t.Helper()
	dir := filepath.Join(root, ".github", "workflows")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read workflows: %v", err)
	}
	var out []integrationInvocation
	for _, e := range entries {
		if e.IsDir() || !(strings.HasSuffix(e.Name(), ".yaml") || strings.HasSuffix(e.Name(), ".yml")) {
			continue
		}
		b, readErr := os.ReadFile(filepath.Join(dir, e.Name()))
		if readErr != nil {
			t.Fatal(readErr)
		}
		for _, line := range strings.Split(string(b), "\n") {
			trimmed := strings.TrimSpace(line)
			// Skip YAML comments so a commented-out invocation never counts as coverage.
			if strings.HasPrefix(trimmed, "#") {
				continue
			}
			if !strings.Contains(trimmed, "go test") {
				continue
			}
			if !strings.Contains(trimmed, "-tags integration") && !strings.Contains(trimmed, "-tags=integration") {
				continue
			}
			inv := integrationInvocation{workflow: e.Name()}
			if m := runFlagRE.FindStringSubmatch(trimmed); m != nil {
				inv.run = m[1]
			}
			for _, m := range pkgArgRE.FindAllStringSubmatch(trimmed, -1) {
				out = append(out, integrationInvocation{
					workflow: inv.workflow,
					pkg:      normalisePkg(m[2]),
					run:      inv.run,
				})
			}
		}
	}
	return out
}

// covers reports whether an invocation would execute the given test. It mirrors
// `go test -run` semantics: the pattern is split on '/' for subtests, and the
// first element is an UNANCHORED regexp match against the top-level test name.
func (inv integrationInvocation) covers(tt taggedTest, t *testing.T) bool {
	t.Helper()
	if inv.pkg != tt.pkg && inv.pkg != "..." && !(strings.HasSuffix(inv.pkg, "...") &&
		strings.HasPrefix(tt.pkg, strings.TrimSuffix(inv.pkg, "..."))) {
		return false
	}
	if inv.run == "" {
		return true // whole package
	}
	// The workflow line is shell source, so a pattern containing '|' is quoted
	// ('TestApply|TestBaseline'). The shell strips those quotes before go test
	// sees them; strip them here too, or the compiled regexp contains literal
	// quote characters and matches nothing. (The inverse guard below caught
	// exactly this defect in this parser when the first wiring landed.)
	top := strings.SplitN(unquote(inv.run), "/", 2)[0]
	re, err := regexp.Compile(top)
	if err != nil {
		t.Fatalf("workflow %s has an uncompilable -run pattern %q: %v", inv.workflow, inv.run, err)
	}
	return re.MatchString(tt.name)
}

// TestEveryIntegrationTestIsWiredIntoCI is the guard. Every integration-tagged
// test function must be reachable by at least one workflow invocation.
func TestEveryIntegrationTestIsWiredIntoCI(t *testing.T) {
	root := repoRoot(t)
	tests := collectTaggedTests(t, root)
	invs := collectInvocations(t, root)

	if len(tests) == 0 {
		t.Fatal("found no integration-tagged tests — the collector is broken, not the repo")
	}
	if len(invs) == 0 {
		t.Fatal("found no `go test -tags integration` invocations in .github/workflows — every tagged test is dead")
	}

	var orphans []string
	for _, tt := range tests {
		covered := false
		for _, inv := range invs {
			if inv.covers(tt, t) {
				covered = true
				break
			}
		}
		if !covered {
			orphans = append(orphans, tt.pkg+"."+tt.name+"  ("+tt.file+")")
		}
	}
	sort.Strings(orphans)

	if len(orphans) > 0 {
		t.Errorf("%d integration-tagged test(s) are wired into NO CI invocation — they compile, "+
			"they are reviewed, and they never run:\n\t%s\n\n"+
			"Fix by adding a step to .github/workflows that names the package and a -run pattern "+
			"matching the test (and give it whatever service/DSN it needs — a test that skips is "+
			"not a test that ran).",
			len(orphans), strings.Join(orphans, "\n\t"))
	}
}

// TestIntegrationInvocationsTargetRealPackages catches the inverse drift: a
// workflow naming a package or pattern that matches nothing, which silently
// buys no coverage while looking like a gate.
func TestIntegrationInvocationsTargetRealPackages(t *testing.T) {
	root := repoRoot(t)
	tests := collectTaggedTests(t, root)
	invs := collectInvocations(t, root)

	for _, inv := range invs {
		matched := false
		for _, tt := range tests {
			if inv.covers(tt, t) {
				matched = true
				break
			}
		}
		if !matched {
			t.Errorf("%s runs `go test -tags integration ./%s -run %q` but that matches NO "+
				"integration-tagged test — the step passes without testing anything",
				inv.workflow, inv.pkg, inv.run)
		}
	}
}
