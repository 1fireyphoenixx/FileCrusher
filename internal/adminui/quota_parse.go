package adminui

import (
	"errors"
	"fmt"
	"math/big"
	"strconv"
	"strings"
)

var quotaDisplayUnits = []struct {
	name  string
	bytes int64
}{
	{name: "PiB", bytes: 1 << 50},
	{name: "TiB", bytes: 1 << 40},
	{name: "GiB", bytes: 1 << 30},
	{name: "MiB", bytes: 1 << 20},
	{name: "KiB", bytes: 1 << 10},
}

var quotaMultipliers = map[string]int64{
	"":    1,
	"B":   1,
	"K":   1_000,
	"KB":  1_000,
	"M":   1_000_000,
	"MB":  1_000_000,
	"G":   1_000_000_000,
	"GB":  1_000_000_000,
	"T":   1_000_000_000_000,
	"TB":  1_000_000_000_000,
	"P":   1_000_000_000_000_000,
	"PB":  1_000_000_000_000_000,
	"KI":  1 << 10,
	"KIB": 1 << 10,
	"MI":  1 << 20,
	"MIB": 1 << 20,
	"GI":  1 << 30,
	"GIB": 1 << 30,
	"TI":  1 << 40,
	"TIB": 1 << 40,
	"PI":  1 << 50,
	"PIB": 1 << 50,
}

func parseQuotaBytes(input string) (int64, error) {
	raw := strings.TrimSpace(input)
	if raw == "" {
		return 0, errors.New("quota is required")
	}
	if strings.HasPrefix(raw, "-") {
		return 0, errors.New("quota must be non-negative")
	}

	numPart, unitPart, err := splitQuotaInput(raw)
	if err != nil {
		return 0, err
	}

	mult, ok := quotaMultipliers[strings.ToUpper(strings.TrimSpace(unitPart))]
	if !ok {
		return 0, fmt.Errorf("unknown quota unit %q", unitPart)
	}

	bytes, err := decimalToScaledInt(numPart, mult)
	if err != nil {
		return 0, err
	}
	if bytes < 0 {
		return 0, errors.New("quota must be non-negative")
	}
	return bytes, nil
}

func splitQuotaInput(s string) (string, string, error) {
	i := 0
	dot := false
	for i < len(s) {
		ch := s[i]
		if ch >= '0' && ch <= '9' {
			i++
			continue
		}
		if ch == '.' {
			if dot {
				return "", "", errors.New("invalid quota number")
			}
			dot = true
			i++
			continue
		}
		break
	}
	if i == 0 {
		return "", "", errors.New("invalid quota number")
	}
	numPart := s[:i]
	if numPart == "." || strings.HasSuffix(numPart, ".") {
		return "", "", errors.New("invalid quota number")
	}
	unitPart := strings.TrimSpace(s[i:])
	return numPart, unitPart, nil
}

func decimalToScaledInt(numPart string, scale int64) (int64, error) {
	parts := strings.SplitN(numPart, ".", 2)
	whole := parts[0]
	frac := ""
	if len(parts) == 2 {
		frac = parts[1]
	}
	if whole == "" {
		whole = "0"
	}
	numerStr := strings.TrimLeft(whole+frac, "0")
	if numerStr == "" {
		numerStr = "0"
	}

	numer := &big.Int{}
	if _, ok := numer.SetString(numerStr, 10); !ok {
		return 0, errors.New("invalid quota number")
	}
	denom := big.NewInt(1)
	if len(frac) > 0 {
		ten := big.NewInt(10)
		d := &big.Int{}
		d.Exp(ten, big.NewInt(int64(len(frac))), nil)
		denom = d
	}

	prod := &big.Int{}
	prod.Mul(numer, big.NewInt(scale))

	q := &big.Int{}
	r := &big.Int{}
	q.QuoRem(prod, denom, r)
	if r.Sign() != 0 {
		return 0, errors.New("quota must resolve to whole bytes")
	}
	if !q.IsInt64() {
		return 0, errors.New("quota is too large")
	}
	return q.Int64(), nil
}

func formatQuotaBytes(v int64) string {
	if v <= 0 {
		return "unlimited"
	}
	for _, u := range quotaDisplayUnits {
		if v >= u.bytes {
			whole := v / u.bytes
			frac := ((v % u.bytes) * 10) / u.bytes
			if frac == 0 {
				return fmt.Sprintf("%d %s", whole, u.name)
			}
			return fmt.Sprintf("%d.%d %s", whole, frac, u.name)
		}
	}
	if v == 1 {
		return "1 byte"
	}
	return fmt.Sprintf("%d bytes", v)
}

func formatQuotaBytesForInput(v int64) string {
	if v <= 0 {
		return "0"
	}
	return strconv.FormatInt(v, 10)
}
