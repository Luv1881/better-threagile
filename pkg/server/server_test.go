package server

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/threagile/threagile/pkg/risks"
	"github.com/threagile/threagile/pkg/types"
)

// --- hash utilities ---------------------------------------------------------

func TestHashSHA256_Deterministic(t *testing.T) {
	h1 := hashSHA256([]byte("hello"))
	h2 := hashSHA256([]byte("hello"))
	if h1 != h2 {
		t.Error("hashSHA256 is not deterministic")
	}
	if h1 == "" {
		t.Error("hashSHA256 returned empty string")
	}
}

func TestHashSHA256_DifferentInputs(t *testing.T) {
	if hashSHA256([]byte("a")) == hashSHA256([]byte("b")) {
		t.Error("hashSHA256 collision on different inputs")
	}
}

func TestHash_Deterministic(t *testing.T) {
	if hash("x") != hash("x") {
		t.Error("hash is not deterministic")
	}
}

func TestXOR_RoundTrip(t *testing.T) {
	key := []byte{0x01, 0x02, 0x03, 0x04}
	xorKey := []byte{0xAA, 0xBB, 0xCC, 0xDD}
	encrypted := xor(key, xorKey)
	decrypted := xor(encrypted, xorKey)
	for i := range key {
		if decrypted[i] != key[i] {
			t.Errorf("XOR round-trip failed at index %d", i)
		}
	}
}

func TestXOR_LengthMismatch_Panics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic for length mismatch")
		}
	}()
	xor([]byte{1, 2}, []byte{1})
}

// --- zip/unzip --------------------------------------------------------------

func TestZipAndUnzip_RoundTrip(t *testing.T) {
	dir := t.TempDir()

	// Create two source files
	f1 := filepath.Join(dir, "file1.txt")
	f2 := filepath.Join(dir, "file2.txt")
	if err := os.WriteFile(f1, []byte("content one"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(f2, []byte("content two"), 0o644); err != nil {
		t.Fatal(err)
	}

	zipPath := filepath.Join(dir, "test.zip")
	if err := zipFiles(zipPath, []string{f1, f2}); err != nil {
		t.Fatalf("zipFiles: %v", err)
	}

	// Unzip into a fresh directory
	destDir := filepath.Join(dir, "extracted")
	if err := os.MkdirAll(destDir, 0o755); err != nil {
		t.Fatal(err)
	}
	extracted, err := unzip(zipPath, destDir)
	if err != nil {
		t.Fatalf("unzip: %v", err)
	}
	if len(extracted) != 2 {
		t.Errorf("expected 2 files extracted, got %d", len(extracted))
	}
}

func TestUnzip_NonExistentFile(t *testing.T) {
	_, err := unzip("/tmp/does-not-exist.zip", t.TempDir())
	if err == nil {
		t.Fatal("expected error for nonexistent zip")
	}
}

// --- addSupportedTags -------------------------------------------------------

func TestAddSupportedTags_InsertsTags(t *testing.T) {
	s := &server{
		builtinRiskRules: risks.GetBuiltInRiskRules(),
		customRiskRules:  nil,
		config:           &stubConfig{},
	}

	input := []byte("some yaml\ntags_available:\nmore yaml")
	output := s.addSupportedTags(input)

	// The placeholder should be replaced with actual tags
	outStr := string(output)
	if outStr == string(input) {
		t.Error("addSupportedTags made no change to input containing tags_available")
	}
	// Must still contain tags_available as prefix of the replacement
	if len(outStr) <= len(string(input)) {
		t.Error("output should be longer than input after tag injection")
	}
}

func TestAddSupportedTags_NoPlaceholder_Unchanged(t *testing.T) {
	s := &server{
		builtinRiskRules: risks.GetBuiltInRiskRules(),
		customRiskRules:  nil,
		config:           &stubConfig{},
	}

	input := []byte("yaml without the placeholder")
	output := s.addSupportedTags(input)
	if string(output) != string(input) {
		t.Error("addSupportedTags should not modify input lacking tags_available")
	}
}

// stubConfig satisfies serverConfigReader with safe zero values.
type stubConfig struct{}

func (s *stubConfig) GetBuildTimestamp() string                         { return "" }
func (s *stubConfig) GetVerbose() bool                                  { return false }
func (s *stubConfig) GetInteractive() bool                              { return false }
func (s *stubConfig) GetAppFolder() string                              { return "" }
func (s *stubConfig) GetPluginFolder() string                           { return "" }
func (s *stubConfig) GetDataFolder() string                             { return "" }
func (s *stubConfig) GetOutputFolder() string                           { return "" }
func (s *stubConfig) GetServerFolder() string                           { return "" }
func (s *stubConfig) GetTempFolder() string                             { return "" }
func (s *stubConfig) GetKeyFolder() string                              { return "" }
func (s *stubConfig) GetInputFile() string                              { return "" }
func (s *stubConfig) GetImportedInputFile() string                      { return "" }
func (s *stubConfig) GetDataFlowDiagramFilenamePNG() string             { return "" }
func (s *stubConfig) GetDataAssetDiagramFilenamePNG() string            { return "" }
func (s *stubConfig) GetDataFlowDiagramFilenameDOT() string             { return "" }
func (s *stubConfig) GetDataAssetDiagramFilenameDOT() string            { return "" }
func (s *stubConfig) GetReportFilename() string                         { return "" }
func (s *stubConfig) GetExcelRisksFilename() string                     { return "" }
func (s *stubConfig) GetRiskExcelConfigHideColumns() []string           { return nil }
func (s *stubConfig) GetRiskExcelConfigSortByColumns() []string         { return nil }
func (s *stubConfig) GetRiskExcelConfigWidthOfColumns() map[string]float64 { return nil }
func (s *stubConfig) GetExcelTagsFilename() string                      { return "" }
func (s *stubConfig) GetJsonRisksFilename() string                      { return "" }
func (s *stubConfig) GetJsonTechnicalAssetsFilename() string            { return "" }
func (s *stubConfig) GetJsonStatsFilename() string                      { return "" }
func (s *stubConfig) GetTemplateFilename() string                       { return "" }
func (s *stubConfig) GetTechnologyFilename() string                     { return "" }
func (s *stubConfig) GetRiskRulePlugins() []string                      { return nil }
func (s *stubConfig) GetSkipRiskRules() []string                        { return nil }
func (s *stubConfig) GetExecuteModelMacro() string                      { return "" }
func (s *stubConfig) GetServerMode() bool                               { return false }
func (s *stubConfig) GetDiagramDPI() int                                { return 100 }
func (s *stubConfig) GetServerPort() int                                { return 8080 }
func (s *stubConfig) GetGraphvizDPI() int                               { return 120 }
func (s *stubConfig) GetMaxGraphvizDPI() int                            { return 300 }
func (s *stubConfig) GetBackupHistoryFilesToKeep() int                  { return 50 }
func (s *stubConfig) GetAddModelTitle() bool                            { return false }
func (s *stubConfig) GetAddLegend() bool                                { return false }
func (s *stubConfig) GetKeepDiagramSourceFiles() bool                   { return false }
func (s *stubConfig) GetIgnoreOrphanedRiskTracking() bool               { return false }
func (s *stubConfig) GetThreagileVersion() string                       { return "test" }
func (s *stubConfig) GetProgressReporter() types.ProgressReporter { return nil }
func (s *stubConfig) GetMethodology() string { return "" }
func (s *stubConfig) GetRulePack() string    { return "" }
