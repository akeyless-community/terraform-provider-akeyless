// generated file
package common

import (
	"strings"
	"testing"
)

func TestEnsureLeadingSlash(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"path", "/path"},
		{"/path", "/path"},
		{"", ""},
		{"/", "/"},
		{"a/b/c", "/a/b/c"},
	}
	for _, tt := range tests {
		got := EnsureLeadingSlash(tt.input)
		if got != tt.expected {
			t.Errorf("EnsureLeadingSlash(%q) = %q, want %q", tt.input, got, tt.expected)
		}
	}
}

func TestExpandStringList(t *testing.T) {
	tests := []struct {
		name     string
		input    []interface{}
		expected []string
	}{
		{"normal", []interface{}{"a", "b", "c"}, []string{"a", "b", "c"}},
		{"empty", []interface{}{}, []string{}},
		{"with empty strings", []interface{}{"a", "", "c"}, []string{"a", "c"}},
		{"with nil", []interface{}{"a", nil, "c"}, []string{"a", "c"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ExpandStringList(tt.input)
			if len(got) != len(tt.expected) {
				t.Errorf("ExpandStringList() len = %d, want %d", len(got), len(tt.expected))
				return
			}
			for i := range got {
				if got[i] != tt.expected[i] {
					t.Errorf("ExpandStringList()[%d] = %q, want %q", i, got[i], tt.expected[i])
				}
			}
		})
	}
}

func TestBase64EncodeDecode(t *testing.T) {
	tests := []string{"hello", "test data", "", "special chars: !@#$%^&*()"}
	for _, input := range tests {
		encoded := Base64Encode(input)
		decoded, err := Base64Decode(encoded)
		if err != nil {
			t.Errorf("Base64Decode(%q) error: %v", encoded, err)
			continue
		}
		if decoded != input {
			t.Errorf("Base64Decode(Base64Encode(%q)) = %q", input, decoded)
		}
	}
}

func TestBase64DecodeInvalid(t *testing.T) {
	_, err := Base64Decode("not-valid-base64!!!")
	if err == nil {
		t.Error("Base64Decode with invalid input should return error")
	}
}

func TestSecondsToTimeString(t *testing.T) {
	tests := []struct {
		input    int
		expected string
	}{
		{0, "0s"},
		{59, "59s"},
		{60, "1m"},
		{61, "1m1s"},
		{3600, "1h"},
		{3661, "1h1m1s"},
		{86400, "1d"},
		{90061, "1d1h1m1s"},
	}
	for _, tt := range tests {
		got := SecondsToTimeString(tt.input)
		if got != tt.expected {
			t.Errorf("SecondsToTimeString(%d) = %q, want %q", tt.input, got, tt.expected)
		}
	}
}

func TestExtractLogForwardingFormat(t *testing.T) {
	if got := ExtractLogForwardingFormat(true); got != "json" {
		t.Errorf("ExtractLogForwardingFormat(true) = %q, want %q", got, "json")
	}
	if got := ExtractLogForwardingFormat(false); got != "text" {
		t.Errorf("ExtractLogForwardingFormat(false) = %q, want %q", got, "text")
	}
}

func TestConvertNanoSecondsIntoDurationString(t *testing.T) {
	tests := []struct {
		input    int64
		expected string
	}{
		{0, "0s"},
		{1e9, "1s"},
		{60e9, "1m0s"},
		{61e9, "1m1s"},
		{3600e9, "1h0m0s"},
	}
	for _, tt := range tests {
		got := ConvertNanoSecondsIntoDurationString(tt.input)
		if got != tt.expected {
			t.Errorf("ConvertNanoSecondsIntoDurationString(%d) = %q, want %q", tt.input, got, tt.expected)
		}
	}
}

func TestDiffSuppressDuration(t *testing.T) {
	tests := []struct {
		old, new string
		expected bool
	}{
		{"1h", "60m", true},
		{"1h30m", "90m", true},
		{"1h", "1h", true},
		{"1h", "2h", false},
		{"invalid", "invalid", true},
		{"invalid", "1h", false},
	}
	for _, tt := range tests {
		got := DiffSuppressDuration("", tt.old, tt.new, nil)
		if got != tt.expected {
			t.Errorf("DiffSuppressDuration(%q, %q) = %v, want %v", tt.old, tt.new, got, tt.expected)
		}
	}
}

func TestDiffSuppressOnLeadingSlash(t *testing.T) {
	tests := []struct {
		old, new string
		expected bool
	}{
		{"path", "/path", true},
		{"/path", "path", true},
		{"/path", "/path", true},
		{"path", "path", true},
		{"path1", "path2", false},
	}
	for _, tt := range tests {
		got := DiffSuppressOnLeadingSlash("", tt.old, tt.new, nil)
		if got != tt.expected {
			t.Errorf("DiffSuppressOnLeadingSlash(%q, %q) = %v, want %v", tt.old, tt.new, got, tt.expected)
		}
	}
}

func TestGenerateRandomAlphaNumericString(t *testing.T) {
	for _, length := range []int{0, 1, 10, 50} {
		got := GenerateRandomAlphaNumericString(length)
		if len(got) != length {
			t.Errorf("GenerateRandomAlphaNumericString(%d) len = %d", length, len(got))
		}
	}
}

func TestGenerateRandomLowercasedString(t *testing.T) {
	got := GenerateRandomLowercasedString(100)
	if len(got) != 100 {
		t.Errorf("GenerateRandomLowercasedString(100) len = %d", len(got))
	}
	if got != strings.ToLower(got) {
		t.Error("GenerateRandomLowercasedString should return only lowercase characters")
	}
}
