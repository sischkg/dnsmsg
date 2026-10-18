package dnsmsg

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func writeTestFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("os.WriteFile(%s) error = %v", path, err)
	}
	return path
}

func TestReadKeyFile(t *testing.T) {
	dir := t.TempDir()

	// A ZSK (flags 256) RSASHA1 key. Public key is {0x61, 0x62, 0x63} = "abc".
	keyContent := `example.com. IN DNSKEY 256 3 5 YWJj
`
	path := writeTestFile(t, dir, "Kexample.com.+005+12345.key", keyContent)

	key, err := ReadKeyFile(path)
	if err != nil {
		t.Fatalf("ReadKeyFile() error = %v", err)
	}

	if key.Name.String() != "example.com." {
		t.Errorf("key.Name.String() = %q, want %q", key.Name.String(), "example.com.")
	}
	if key.Flags != 256 {
		t.Errorf("key.Flags = %v, want 256", key.Flags)
	}
	if key.Protocol != 3 {
		t.Errorf("key.Protocol = %v, want 3", key.Protocol)
	}
	if key.Algorithm != 5 {
		t.Errorf("key.Algorithm = %v, want 5", key.Algorithm)
	}
	wantPublic := []byte{0x61, 0x62, 0x63}
	if !reflect.DeepEqual(key.PublicKey, wantPublic) {
		t.Errorf("key.PublicKey = %v, want %v", key.PublicKey, wantPublic)
	}
	if key.PrivateKey != nil {
		t.Errorf("key.PrivateKey = %v, want nil", key.PrivateKey)
	}
}

func TestReadKeyFileKSK(t *testing.T) {
	dir := t.TempDir()

	// A KSK (flags 257) RSASHA256 key.
	keyContent := `example.com. IN DNSKEY 257 3 8 AAECAwQFBgc
`
	path := writeTestFile(t, dir, "Kexample.com.+008+54321.key", keyContent)

	key, err := ReadKeyFile(path)
	if err != nil {
		t.Fatalf("ReadKeyFile() error = %v", err)
	}

	if key.Flags != 257 {
		t.Errorf("key.Flags = %v, want 257", key.Flags)
	}
	if key.Algorithm != 8 {
		t.Errorf("key.Algorithm = %v, want 8", key.Algorithm)
	}
	wantPublic := []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07}
	if !reflect.DeepEqual(key.PublicKey, wantPublic) {
		t.Errorf("key.PublicKey = %v, want %v", key.PublicKey, wantPublic)
	}
}

func TestReadKeyFileToDNSKEY(t *testing.T) {
	dir := t.TempDir()

	keyContent := `example.com. IN DNSKEY 256 3 13 //79/A
`
	path := writeTestFile(t, dir, "Kexample.com.+013+00001.key", keyContent)

	key, err := ReadKeyFile(path)
	if err != nil {
		t.Fatalf("ReadKeyFile() error = %v", err)
	}

	dnskey := key.ToDNSKEY()
	if dnskey.Type() != TYPE_DNSKEY {
		t.Errorf("ToDNSKEY().Type() = %v, want %v", dnskey.Type(), TYPE_DNSKEY)
	}
	if dnskey.Flags != 256 {
		t.Errorf("ToDNSKEY().Flags = %v, want 256", dnskey.Flags)
	}
	if dnskey.Algorithm != 13 {
		t.Errorf("ToDNSKEY().Algorithm = %v, want 13", dnskey.Algorithm)
	}
	wantPublic := []byte{0xFF, 0xFE, 0xFD, 0xFC}
	if !reflect.DeepEqual(dnskey.PublicKey, wantPublic) {
		t.Errorf("ToDNSKEY().PublicKey = %v, want %v", dnskey.PublicKey, wantPublic)
	}
}

func TestReadKeyFileErrors(t *testing.T) {
	dir := t.TempDir()

	tests := []struct {
		name    string
		content string
	}{
		{
			name:    "empty file",
			content: "",
		},
		{
			name:    "only comments",
			content: "; this is a comment\n# another comment\n",
		},
		{
			name:    "only directives",
			content: "$ORIGIN example.com.\n$TTL 3600\n",
		},
		{
			name:    "invalid line - too few fields",
			content: "example.com. IN DNSKEY 256 3\n",
		},
		{
			name:    "invalid line - wrong class",
			content: "example.com. CH DNSKEY 256 3 5 YWJj\n",
		},
		{
			name:    "invalid line - wrong type",
			content: "example.com. IN NS 256 3 5 YWJj\n",
		},
		{
			name:    "invalid line - non-numeric flags",
			content: "example.com. IN DNSKEY abc 3 5 YWJj\n",
		},
		{
			name:    "invalid line - invalid base64",
			content: "example.com. IN DNSKEY 256 3 5 !!!invalid!!! \n",
		},
		{
			name:    "invalid domain name - empty label",
			content: "example..com IN DNSKEY 256 3 5 YWJj\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := writeTestFile(t, dir, "test.key", tt.content)
			if _, err := ReadKeyFile(path); err == nil {
				t.Errorf("ReadKeyFile() expected error, got nil")
			}
		})
	}
}

func TestReadKeyFileNotFound(t *testing.T) {
	if _, err := ReadKeyFile("/nonexistent/path/keyfile.key"); err == nil {
		t.Errorf("ReadKeyFile() expected error for missing file, got nil")
	}
}

func TestReadPrivateKeyFileRSA(t *testing.T) {
	dir := t.TempDir()

	privateContent := `Private-key-format: v1.3
Algorithm: 5 (RSASHA1)
Modulus: AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8
PublicExponent: AQAB
PrivateExponent: q83v
Prime1: AAAA
Prime2: BBBB
Exponent1: CCCC
Exponent2: DDDD
Coefficient: EEEE
Created: 20230101000000
Publish: 20230101000000
Activate: 20230101000000
`
	path := writeTestFile(t, dir, "Kexample.com.+005+12345.private", privateContent)

	key, err := ReadPrivateKeyFile(path)
	if err != nil {
		t.Fatalf("ReadPrivateKeyFile() error = %v", err)
	}

	if key.Algorithm != 5 {
		t.Errorf("key.Algorithm = %v, want 5", key.Algorithm)
	}
	if key.PublicKey != nil {
		t.Errorf("key.PublicKey = %v, want nil", key.PublicKey)
	}

	// PrivateExponent should be stored both as PrivateKey and in PrivateParams.
	wantPrivateExponent := []byte{0xAB, 0xCD, 0xEF}
	if !reflect.DeepEqual(key.PrivateKey, wantPrivateExponent) {
		t.Errorf("key.PrivateKey = %v, want %v", key.PrivateKey, wantPrivateExponent)
	}
	if !reflect.DeepEqual(key.PrivateParams["PrivateExponent"], wantPrivateExponent) {
		t.Errorf("key.PrivateParams[PrivateExponent] = %v, want %v", key.PrivateParams["PrivateExponent"], wantPrivateExponent)
	}

	// Other params should also be present.
	if _, ok := key.PrivateParams["Modulus"]; !ok {
		t.Errorf("key.PrivateParams missing Modulus")
	}
	if _, ok := key.PrivateParams["PublicExponent"]; !ok {
		t.Errorf("key.PrivateParams missing PublicExponent")
	}
}

func TestReadPrivateKeyFileECDSA(t *testing.T) {
	dir := t.TempDir()

	privateContent := `Private-key-format: v1.3
Algorithm: 13 (ECDSAP256SHA256)
PrivateKey: AA
Created: 20230101000000
Publish: 20230101000000
Activate: 20230101000000
`
	path := writeTestFile(t, dir, "Kexample.com.+013+00001.private", privateContent)

	key, err := ReadPrivateKeyFile(path)
	if err != nil {
		t.Fatalf("ReadPrivateKeyFile() error = %v", err)
	}

	if key.Algorithm != 13 {
		t.Errorf("key.Algorithm = %v, want 13", key.Algorithm)
	}
	wantPrivate := []byte{0x00}
	if !reflect.DeepEqual(key.PrivateKey, wantPrivate) {
		t.Errorf("key.PrivateKey = %v, want %v", key.PrivateKey, wantPrivate)
	}
	if !reflect.DeepEqual(key.PrivateParams["PrivateKey"], wantPrivate) {
		t.Errorf("key.PrivateParams[PrivateKey] = %v, want %v", key.PrivateParams["PrivateKey"], wantPrivate)
	}
}

func TestReadPrivateKeyFileErrors(t *testing.T) {
	dir := t.TempDir()

	tests := []struct {
		name    string
		content string
	}{
		{
			name:    "empty file",
			content: "",
		},
		{
			name:    "no algorithm",
			content: "Private-key-format: v1.3\n",
		},
		{
			name:    "invalid algorithm number",
			content: "Private-key-format: v1.3\nAlgorithm: abc (RSASHA1)\n",
		},
		{
			name:    "invalid base64 parameter",
			content: "Private-key-format: v1.3\nAlgorithm: 5 (RSASHA1)\nModulus: !!!invalid!!!\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := writeTestFile(t, dir, "test.private", tt.content)
			if _, err := ReadPrivateKeyFile(path); err == nil {
				t.Errorf("ReadPrivateKeyFile() expected error, got nil")
			}
		})
	}
}

func TestReadPrivateKeyFileNotFound(t *testing.T) {
	if _, err := ReadPrivateKeyFile("/nonexistent/path/keyfile.private"); err == nil {
		t.Errorf("ReadPrivateKeyFile() expected error for missing file, got nil")
	}
}

func TestSupportedDNSSECAlgorithms(t *testing.T) {
	algs := SupportedDNSSECAlgorithms()

	// 期待する対応アルゴリズム（昇順）
	want := []uint8{5, 7, 8, 10, 13, 14, 15}
	if len(algs) != len(want) {
		t.Errorf("SupportedDNSSECAlgorithms() = %v, want %v", algs, want)
		return
	}
	for i := range want {
		if algs[i] != want[i] {
			t.Errorf("SupportedDNSSECAlgorithms()[%d] = %d, want %d", i, algs[i], want[i])
		}
	}

	// すべて返されたアルゴリズムが SignRRSet で使えること（dnssecAlgorithmHash で ok == true）
	for _, alg := range algs {
		if _, ok := dnssecAlgorithmHash(alg); !ok {
			t.Errorf("algorithm %d is in SupportedDNSSECAlgorithms but not supported by dnssecAlgorithmHash", alg)
		}
	}

	// サポートされていないアルゴリズムが含まれていないこと
	for _, unsupported := range []uint8{1, 2, 3, 4, 6, 9, 11, 12, 16} {
		for _, alg := range algs {
			if alg == unsupported {
				t.Errorf("SupportedDNSSECAlgorithms() contains unsupported algorithm %d", alg)
			}
		}
	}
}
