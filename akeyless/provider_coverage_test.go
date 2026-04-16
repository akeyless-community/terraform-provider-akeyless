package akeyless

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestProviderMapsCoveredByAcceptanceTestFiles ensures every registered resource
// and data source appears in at least one acceptance test config under akeyless/tests.
func TestProviderMapsCoveredByAcceptanceTestFiles(t *testing.T) {
	t.Parallel()

	_, file, _, _ := runtime.Caller(0)
	testsRoot := filepath.Join(filepath.Dir(file), "tests")

	var blob strings.Builder
	err := filepath.Walk(testsRoot, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		if !strings.HasSuffix(info.Name(), "_test.go") {
			return nil
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		blob.Write(b)
		blob.WriteByte('\n')
		return nil
	})
	if err != nil {
		t.Fatalf("walk tests: %v", err)
	}

	body := blob.String()
	p := Provider()

	for name := range p.ResourcesMap {
		needle := `resource "` + name + `"`
		if !strings.Contains(body, needle) {
			t.Errorf("resource %q has no matching acceptance test substring %s", name, needle)
		}
	}
	for name := range p.DataSourcesMap {
		needle := `data "` + name + `"`
		if !strings.Contains(body, needle) {
			t.Errorf("data source %q has no matching acceptance test substring %s", name, needle)
		}
	}
}
