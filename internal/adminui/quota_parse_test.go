package adminui

import "testing"

func TestParseQuotaBytes_Valid(t *testing.T) {
	tests := []struct {
		in   string
		want int64
	}{
		{in: "0", want: 0},
		{in: "1024", want: 1024},
		{in: "10KB", want: 10_000},
		{in: "10 kb", want: 10_000},
		{in: "500MB", want: 500_000_000},
		{in: "1.5GB", want: 1_500_000_000},
		{in: "512MiB", want: 512 * (1 << 20)},
		{in: "2 GiB", want: 2 * (1 << 30)},
		{in: "1TiB", want: 1 << 40},
	}

	for _, tc := range tests {
		got, err := parseQuotaBytes(tc.in)
		if err != nil {
			t.Fatalf("input %q: unexpected error: %v", tc.in, err)
		}
		if got != tc.want {
			t.Fatalf("input %q: got %d want %d", tc.in, got, tc.want)
		}
	}
}

func TestParseQuotaBytes_Invalid(t *testing.T) {
	inputs := []string{
		"",
		"-1",
		"abc",
		"1..2GB",
		"1.",
		"GB",
		"1XB",
		"0.1B",
	}

	for _, in := range inputs {
		if _, err := parseQuotaBytes(in); err == nil {
			t.Fatalf("input %q: expected error", in)
		}
	}
}
