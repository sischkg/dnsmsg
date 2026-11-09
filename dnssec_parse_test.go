package dnsmsg

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"testing/iotest"
)

// The tests here exercise the byte-string and io.Reader API in dnssec_parse.go:
// the same parsing ReadKeyFile and ReadPrivateKeyFile do, reached without a
// filesystem.  The fixtures are built with the same helpers the other DNSSEC
// tests use, so that an expected value is derived from the bytes that were
// encoded rather than copied from a file.

const (
	parseTestKeySource    = "DNSSEC key data"
	parseTestPrivateKeyID = "DNSSEC private key data"
)

// dnssecKeyFileContents renders one DNSKEY record line in the form a .key file
// carries, with the public key material base64-encoded the way this package
// writes it.
func dnssecKeyFileContents(name string, flags uint16, algorithm uint8, material []byte) string {
	return fmt.Sprintf("%s IN DNSKEY %d 3 %d %s\n", name, flags, algorithm, encodeBase64(material))
}

// chunkBase64 splits one base64 string into space separated pieces, the way a
// long key is wrapped in a .key file line.  The pieces are fragments of one
// encoding and carry no meaning of their own: the parser joins the fields back
// together before decoding, so only a single encodeBase64 of the whole material
// may be split this way.
func chunkBase64(encoded string, size int) string {
	chunks := make([]string, 0, (len(encoded)+size-1)/size)
	for start := 0; start < len(encoded); start += size {
		end := min(start+size, len(encoded))
		chunks = append(chunks, encoded[start:end])
	}
	return strings.Join(chunks, " ")
}

// dnssecPrivateKeyFileContents renders a .private file body for an algorithm and
// a set of private parameters, with every value base64-encoded and the
// parameters sorted so that the same map always produces the same file.
func dnssecPrivateKeyFileContents(algorithm uint8, params map[string][]byte) string {
	names := make([]string, 0, len(params))
	for name := range params {
		names = append(names, name)
	}
	sort.Strings(names)

	var sb strings.Builder
	sb.WriteString("Private-key-format: v1.3\n")
	sb.WriteString(fmt.Sprintf("Algorithm: %d\n", algorithm))
	for _, name := range names {
		sb.WriteString(fmt.Sprintf("%s: %s\n", name, encodeBase64(params[name])))
	}
	return sb.String()
}

// TestParseDNSSECKey parses .key contents given as bytes: the fields of the
// record, the base64 decoding of the public key, and the lines the parser skips
// on the way to the record.
func TestParseDNSSECKey(t *testing.T) {
	const material = "abcdefghijklmnopqrstuvwxyz"

	tests := []struct {
		name          string
		data          string
		wantName      string
		wantFlags     uint16
		wantProtocol  uint8
		wantAlgorithm uint8
		wantMaterial  string
	}{
		{
			name:          "zone signing key",
			data:          dnssecKeyFileContents("example.com.", 256, 8, []byte(material)),
			wantName:      "example.com.",
			wantFlags:     256,
			wantProtocol:  3,
			wantAlgorithm: 8,
			wantMaterial:  material,
		},
		{
			name:          "key signing key",
			data:          dnssecKeyFileContents("example.com.", 257, 15, []byte("AB")),
			wantName:      "example.com.",
			wantFlags:     257,
			wantProtocol:  3,
			wantAlgorithm: 15,
			wantMaterial:  "AB",
		},
		{
			name:          "no trailing newline",
			data:          strings.TrimSuffix(dnssecKeyFileContents("example.org.", 257, 13, []byte("CD")), "\n"),
			wantName:      "example.org.",
			wantFlags:     257,
			wantProtocol:  3,
			wantAlgorithm: 13,
			wantMaterial:  "CD",
		},
		{
			name: "comments directives and blank lines",
			data: "; a comment\n" +
				"# another comment\n" +
				"\n" +
				"$ORIGIN example.com.\n" +
				"$TTL 3600\n" +
				dnssecKeyFileContents("example.com.", 256, 5, []byte("EF")) +
				"; a trailing comment\n",
			wantName:      "example.com.",
			wantFlags:     256,
			wantProtocol:  3,
			wantAlgorithm: 5,
			wantMaterial:  "EF",
		},
		{
			name: "public key in space separated chunks",
			data: "example.com. IN DNSKEY 256 3 8 " +
				chunkBase64(encodeBase64([]byte(material)), 12) + "\n",
			wantName:      "example.com.",
			wantFlags:     256,
			wantProtocol:  3,
			wantAlgorithm: 8,
			wantMaterial:  material,
		},
		{
			name:          "CRLF line endings",
			data:          strings.ReplaceAll(dnssecKeyFileContents("example.net.", 257, 14, []byte("GH")), "\n", "\r\n"),
			wantName:      "example.net.",
			wantFlags:     257,
			wantProtocol:  3,
			wantAlgorithm: 14,
			wantMaterial:  "GH",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			key, err := ParseDNSSECKey([]byte(tc.data))
			if err != nil {
				t.Fatalf("ParseDNSSECKey() error = %v", err)
			}
			if key == nil {
				t.Fatalf("ParseDNSSECKey() returned a nil key without an error")
			}
			if got := key.Name.String(); got != tc.wantName {
				t.Errorf("key.Name = %q, want %q", got, tc.wantName)
			}
			if key.Flags != tc.wantFlags {
				t.Errorf("key.Flags = %d, want %d", key.Flags, tc.wantFlags)
			}
			if key.Protocol != tc.wantProtocol {
				t.Errorf("key.Protocol = %d, want %d", key.Protocol, tc.wantProtocol)
			}
			if key.Algorithm != tc.wantAlgorithm {
				t.Errorf("key.Algorithm = %d, want %d", key.Algorithm, tc.wantAlgorithm)
			}
			if string(key.PublicKey) != tc.wantMaterial {
				t.Errorf("key.PublicKey = %q, want %q", key.PublicKey, tc.wantMaterial)
			}
			// A .key file carries no private material.
			if key.PrivateKey != nil {
				t.Errorf("key.PrivateKey = %x, want nil", key.PrivateKey)
			}
			if key.PrivateParams != nil {
				t.Errorf("key.PrivateParams = %v, want nil", key.PrivateParams)
			}
		})
	}

	// The same parser over the public half of a generated key, for every
	// algorithm this package can sign with.
	for _, algorithm := range SupportedDNSSECAlgorithms() {
		t.Run(fmt.Sprintf("generated %s key", algorithmName(algorithm)), func(t *testing.T) {
			testKey := newVerifyTestKey(t, algorithm)
			material := dnskeyMaterialFromPublicKey(t, testKey.pubkey)

			key, err := ParseDNSSECKey([]byte(dnssecKeyFileContents(dnssecKeygenZone+".", 257, algorithm, material)))
			if err != nil {
				t.Fatalf("ParseDNSSECKey() error = %v", err)
			}
			if got := key.Name.String(); got != dnssecKeygenZone+"." {
				t.Errorf("key.Name = %q, want %q", got, dnssecKeygenZone+".")
			}
			if key.Algorithm != algorithm {
				t.Errorf("key.Algorithm = %d, want %d", key.Algorithm, algorithm)
			}
			if key.Flags != 257 || key.Protocol != 3 {
				t.Errorf("key.Flags, key.Protocol = %d, %d, want 257, 3", key.Flags, key.Protocol)
			}
			if !bytes.Equal(key.PublicKey, material) {
				t.Errorf("key.PublicKey is %d octets, want the %d octets of the generated public key",
					len(key.PublicKey), len(material))
			}
			if _, err := key.KeyTag(); err != nil {
				t.Errorf("key.KeyTag() error = %v", err)
			}
		})
	}
}

// TestParseDNSSECKeyErrors covers .key contents that are not a DNSKEY record.
// Every case must report an error: a byte string that cannot be parsed never
// produces a key that only looks valid.
func TestParseDNSSECKeyErrors(t *testing.T) {
	tests := []struct {
		name string
		data string
		want []string
	}{
		{
			name: "empty data",
			data: "",
			want: []string{"no DNSKEY record found in " + parseTestKeySource},
		},
		{
			name: "only comments and blank lines",
			data: "; nothing here\n\n# still nothing\n$TTL 3600\n",
			want: []string{"no DNSKEY record found in " + parseTestKeySource},
		},
		{
			name: "too few fields",
			data: "example.com. IN DNSKEY 256 3 8\n",
			want: []string{"cannot parse " + parseTestKeySource, "expected at least 7 fields"},
		},
		{
			name: "wrong class",
			data: "example.com. CH DNSKEY 256 3 8 YWJj\n",
			want: []string{"cannot parse " + parseTestKeySource, "expected class IN"},
		},
		{
			name: "wrong record type",
			data: "example.com. IN RRSIG 256 3 8 YWJj\n",
			want: []string{"cannot parse " + parseTestKeySource, "expected type DNSKEY"},
		},
		{
			name: "invalid owner name",
			data: "exam..ple.com. IN DNSKEY 256 3 8 YWJj\n",
			want: []string{"cannot parse " + parseTestKeySource, "invalid DNSKEY name"},
		},
		{
			name: "flags not a number",
			data: "example.com. IN DNSKEY x 3 8 YWJj\n",
			want: []string{"cannot parse " + parseTestKeySource, `invalid flags "x"`},
		},
		{
			name: "flags out of range",
			data: "example.com. IN DNSKEY 65536 3 8 YWJj\n",
			want: []string{"cannot parse " + parseTestKeySource, `invalid flags "65536"`},
		},
		{
			name: "protocol not a number",
			data: "example.com. IN DNSKEY 256 x 8 YWJj\n",
			want: []string{"cannot parse " + parseTestKeySource, `invalid protocol "x"`},
		},
		{
			name: "algorithm out of range",
			data: "example.com. IN DNSKEY 256 3 256 YWJj\n",
			want: []string{"cannot parse " + parseTestKeySource, `invalid algorithm "256"`},
		},
		{
			name: "public key is not base64",
			data: "example.com. IN DNSKEY 256 3 8 !!!\n",
			want: []string{"cannot parse " + parseTestKeySource, "invalid DNSKEY public key"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			key, err := ParseDNSSECKey([]byte(tc.data))
			if err == nil {
				t.Fatalf("ParseDNSSECKey() error = nil, want an error; key = %s", describeDNSSECKey(key))
			}
			if key != nil {
				t.Errorf("ParseDNSSECKey() returned %s with an error, want nil", describeDNSSECKey(key))
			}
			for _, want := range tc.want {
				if !errorContains(err, want) {
					t.Errorf("ParseDNSSECKey() error = %q, want it to mention %q", err, want)
				}
			}
		})
	}
}

// TestParseDNSSECPrivateKey parses .private contents given as bytes: the
// algorithm, the base64-decoded parameters, and the scalar ReadPrivateKeyFile
// mirrors into DNSSECKey.PrivateKey.
func TestParseDNSSECPrivateKey(t *testing.T) {
	t.Run("Ed25519 written as a person writes one", func(t *testing.T) {
		seed := []byte("01234567890123456789012345678901")
		data := "Private-key-format: v1.3\n" +
			"Algorithm: 15 (Ed25519)\n" +
			"PrivateKey: " + encodeBase64(seed) + "\n"

		key, err := ParseDNSSECPrivateKey([]byte(data))
		if err != nil {
			t.Fatalf("ParseDNSSECPrivateKey() error = %v", err)
		}
		if key.Algorithm != 15 {
			t.Errorf("key.Algorithm = %d, want 15", key.Algorithm)
		}
		if !bytes.Equal(key.PrivateKey, seed) {
			t.Errorf("key.PrivateKey = %x, want the seed %x", key.PrivateKey, seed)
		}
		if !bytes.Equal(key.PrivateParams["PrivateKey"], seed) {
			t.Errorf("key.PrivateParams[\"PrivateKey\"] = %x, want the seed %x", key.PrivateParams["PrivateKey"], seed)
		}
	})

	// Every algorithm this package signs with, from the parameters of a
	// generated key: what was encoded is what the parser must return.
	for _, algorithm := range SupportedDNSSECAlgorithms() {
		t.Run(algorithmName(algorithm), func(t *testing.T) {
			testKey := newVerifyTestKey(t, algorithm)
			params := dnssecPrivateKeyParams(t, testKey.signer)

			key, err := ParseDNSSECPrivateKey([]byte(dnssecPrivateKeyFileContents(algorithm, params)))
			if err != nil {
				t.Fatalf("ParseDNSSECPrivateKey() error = %v", err)
			}
			if key.Algorithm != algorithm {
				t.Errorf("key.Algorithm = %d, want %d", key.Algorithm, algorithm)
			}
			if !reflect.DeepEqual(key.PrivateParams, params) {
				t.Errorf("key.PrivateParams = %v, want the parameters that were encoded", describeDNSSECKey(key))
			}
			wantScalar := dnssecPrivateScalarFromParams(params)
			if !bytes.Equal(key.PrivateKey, wantScalar) {
				t.Errorf("key.PrivateKey = %x, want the private scalar %x", key.PrivateKey, wantScalar)
			}
			if key.PublicKey != nil {
				t.Errorf("key.PublicKey = %x, want nil: a .private file carries no public key", key.PublicKey)
			}
		})
	}
}

// TestParseDNSSECPrivateKeyErrors covers .private contents that do not describe
// a key.  Note that a "Name:" line is not accepted here: that line is only
// tolerated when reading a key pair, where the .key file supplies the name.
func TestParseDNSSECPrivateKeyErrors(t *testing.T) {
	tests := []struct {
		name string
		data string
		want []string
	}{
		{
			name: "empty data",
			data: "",
			want: []string{"no algorithm found in " + parseTestPrivateKeyID},
		},
		{
			name: "only comments and blank lines",
			data: "; nothing\n\nPrivate-key-format: v1.3\n",
			want: []string{"no algorithm found in " + parseTestPrivateKeyID},
		},
		{
			name: "parameters without an algorithm",
			data: "Private-key-format: v1.3\nPrivateKey: " + encodeBase64([]byte("seed")) + "\n",
			want: []string{"no algorithm found in " + parseTestPrivateKeyID},
		},
		{
			name: "algorithm is not a number",
			data: "Private-key-format: v1.3\nAlgorithm: abc\n",
			want: []string{"cannot parse " + parseTestPrivateKeyID, `invalid algorithm number "abc"`},
		},
		{
			name: "algorithm has no value",
			data: "Private-key-format: v1.3\nAlgorithm:\n",
			want: []string{"cannot parse " + parseTestPrivateKeyID, "empty algorithm value"},
		},
		{
			name: "algorithm out of range",
			data: "Private-key-format: v1.3\nAlgorithm: 256\nPrivateKey: " + encodeBase64([]byte("seed")) + "\n",
			want: []string{"cannot parse " + parseTestPrivateKeyID, `invalid algorithm number "256"`},
		},
		{
			name: "a parameter is not base64",
			data: "Private-key-format: v1.3\nAlgorithm: 5\nModulus: !!!\n",
			want: []string{`cannot decode private key parameter "Modulus"`},
		},
		{
			name: "a Name line is not a private parameter",
			data: "Private-key-format: v1.3\nAlgorithm: 15\nName: example.com.\nPrivateKey: " + encodeBase64([]byte("01234567890123456789012345678901")) + "\n",
			want: []string{`cannot decode private key parameter "Name"`},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			key, err := ParseDNSSECPrivateKey([]byte(tc.data))
			if err == nil {
				t.Fatalf("ParseDNSSECPrivateKey() error = nil, want an error; key = %s", describeDNSSECKey(key))
			}
			if key != nil {
				t.Errorf("ParseDNSSECPrivateKey() returned %s with an error, want nil", describeDNSSECKey(key))
			}
			for _, want := range tc.want {
				if !errorContains(err, want) {
					t.Errorf("ParseDNSSECPrivateKey() error = %q, want it to mention %q", err, want)
				}
			}
		})
	}
}

// TestParseDNSSECKeyWithSource checks that the source argument names the data
// the parser could not read, and that an empty source falls back to the label
// the byte-string API uses by default.
func TestParseDNSSECKeyWithSource(t *testing.T) {
	t.Run("named source", func(t *testing.T) {
		_, err := ParseDNSSECKeyWithSource(nil, "embedded config")
		if !errorContains(err, "no DNSKEY record found in embedded config") {
			t.Errorf("ParseDNSSECKeyWithSource() error = %v, want it to name the embedded config", err)
		}

		_, err = ParseDNSSECKeyWithSource([]byte("example.com. IN DNSKEY 256 3 8\n"), "embedded config")
		if !errorContains(err, "cannot parse embedded config: invalid DNSKEY key line") {
			t.Errorf("ParseDNSSECKeyWithSource() error = %v, want it to name the embedded config", err)
		}
	})

	t.Run("empty source uses the default label", func(t *testing.T) {
		_, err := ParseDNSSECKeyWithSource(nil, "")
		if !errorContains(err, "no DNSKEY record found in "+parseTestKeySource) {
			t.Errorf("ParseDNSSECKeyWithSource() error = %v, want it to mention %q", err, parseTestKeySource)
		}
	})

	t.Run("a valid key parses whatever its source is called", func(t *testing.T) {
		testKey := newVerifyTestKey(t, 15)
		material := dnskeyMaterialFromPublicKey(t, testKey.pubkey)

		key, err := ParseDNSSECKeyWithSource([]byte(dnssecKeyFileContents("example.com.", 257, 15, material)), "Kexample.com.+015+12345.key")
		if err != nil {
			t.Fatalf("ParseDNSSECKeyWithSource() error = %v", err)
		}
		if !bytes.Equal(key.PublicKey, material) {
			t.Errorf("key.PublicKey does not match the public key that was encoded")
		}
	})
}

// TestParseDNSSECPrivateKeyWithSource is the same check for the private half.
func TestParseDNSSECPrivateKeyWithSource(t *testing.T) {
	t.Run("named source", func(t *testing.T) {
		_, err := ParseDNSSECPrivateKeyWithSource(nil, "config block")
		if !errorContains(err, "no algorithm found in config block") {
			t.Errorf("ParseDNSSECPrivateKeyWithSource() error = %v, want it to name the config block", err)
		}

		_, err = ParseDNSSECPrivateKeyWithSource([]byte("Algorithm: abc\n"), "config block")
		if !errorContains(err, "cannot parse config block: invalid algorithm number") {
			t.Errorf("ParseDNSSECPrivateKeyWithSource() error = %v, want it to name the config block", err)
		}

		_, err = ParseDNSSECPrivateKeyWithSource([]byte("Algorithm: 5\nModulus: !!!\n"), "config block")
		if !errorContains(err, `cannot decode private key parameter "Modulus" in config block`) {
			t.Errorf("ParseDNSSECPrivateKeyWithSource() error = %v, want it to name the config block", err)
		}
	})

	t.Run("empty source uses the default label", func(t *testing.T) {
		_, err := ParseDNSSECPrivateKeyWithSource(nil, "")
		if !errorContains(err, "no algorithm found in "+parseTestPrivateKeyID) {
			t.Errorf("ParseDNSSECPrivateKeyWithSource() error = %v, want it to mention %q", err, parseTestPrivateKeyID)
		}
	})
}

// errReaderSentinel is the failure a failing io.Reader returns, so that a test
// can tell a read failure apart from a parse failure.
var errReaderSentinel = errors.New("the reader failed")

// TestReadDNSSECKeyReader reads .key contents through an io.Reader: the whole
// content is read once, a reader that hands out one octet at a time works, and
// a reader that fails reports its own error.
func TestReadDNSSECKeyReader(t *testing.T) {
	valid := dnssecKeyFileContents("example.com.", 256, 8, []byte("abcdefgh"))

	t.Run("reader result equals the byte string result", func(t *testing.T) {
		fromReader, err := ReadDNSSECKey(strings.NewReader(valid))
		if err != nil {
			t.Fatalf("ReadDNSSECKey() error = %v", err)
		}
		fromBytes, err := ParseDNSSECKey([]byte(valid))
		if err != nil {
			t.Fatalf("ParseDNSSECKey() error = %v", err)
		}
		if describeDNSSECKey(fromReader) != describeDNSSECKey(fromBytes) {
			t.Errorf("ReadDNSSECKey() returned %s, want %s", describeDNSSECKey(fromReader), describeDNSSECKey(fromBytes))
		}
	})

	t.Run("the whole reader is consumed", func(t *testing.T) {
		r := bytes.NewReader([]byte(valid))
		if _, err := ReadDNSSECKey(r); err != nil {
			t.Fatalf("ReadDNSSECKey() error = %v", err)
		}
		if r.Len() != 0 {
			t.Errorf("%d unread octets remain in the reader, want 0", r.Len())
		}
	})

	t.Run("one octet at a time", func(t *testing.T) {
		key, err := ReadDNSSECKey(iotest.OneByteReader(strings.NewReader(valid)))
		if err != nil {
			t.Fatalf("ReadDNSSECKey() error = %v", err)
		}
		if got := key.Name.String(); got != "example.com." {
			t.Errorf("key.Name = %q, want %q", got, "example.com.")
		}
	})

	t.Run("a failing reader reports its own error", func(t *testing.T) {
		key, err := ReadDNSSECKey(iotest.ErrReader(errReaderSentinel))
		if !errors.Is(err, errReaderSentinel) {
			t.Errorf("ReadDNSSECKey() error = %v, want it to report %v", err, errReaderSentinel)
		}
		if !errorContains(err, "cannot read DNSSEC key data") {
			t.Errorf("ReadDNSSECKey() error = %q, want it to say what it was reading", err)
		}
		if key != nil {
			t.Errorf("ReadDNSSECKey() returned %s with an error, want nil", describeDNSSECKey(key))
		}
	})

	t.Run("content that reads but does not parse is a parse error", func(t *testing.T) {
		_, err := ReadDNSSECKey(strings.NewReader(""))
		if !errorContains(err, "no DNSKEY record found in "+parseTestKeySource) {
			t.Errorf("ReadDNSSECKey() error = %v, want the parser's own error", err)
		}
	})
}

// TestReadDNSSECPrivateKeyReader is the same for the private half.
func TestReadDNSSECPrivateKeyReader(t *testing.T) {
	valid := dnssecPrivateKeyFileContents(15, map[string][]byte{
		"PrivateKey": []byte("01234567890123456789012345678901"),
	})

	t.Run("reader result equals the byte string result", func(t *testing.T) {
		fromReader, err := ReadDNSSECPrivateKey(strings.NewReader(valid))
		if err != nil {
			t.Fatalf("ReadDNSSECPrivateKey() error = %v", err)
		}
		fromBytes, err := ParseDNSSECPrivateKey([]byte(valid))
		if err != nil {
			t.Fatalf("ParseDNSSECPrivateKey() error = %v", err)
		}
		if describeDNSSECKey(fromReader) != describeDNSSECKey(fromBytes) {
			t.Errorf("ReadDNSSECPrivateKey() returned %s, want %s", describeDNSSECKey(fromReader), describeDNSSECKey(fromBytes))
		}
	})

	t.Run("the whole reader is consumed", func(t *testing.T) {
		r := bytes.NewReader([]byte(valid))
		if _, err := ReadDNSSECPrivateKey(r); err != nil {
			t.Fatalf("ReadDNSSECPrivateKey() error = %v", err)
		}
		if r.Len() != 0 {
			t.Errorf("%d unread octets remain in the reader, want 0", r.Len())
		}
	})

	t.Run("one octet at a time", func(t *testing.T) {
		key, err := ReadDNSSECPrivateKey(iotest.OneByteReader(strings.NewReader(valid)))
		if err != nil {
			t.Fatalf("ReadDNSSECPrivateKey() error = %v", err)
		}
		if key.Algorithm != 15 {
			t.Errorf("key.Algorithm = %d, want 15", key.Algorithm)
		}
	})

	t.Run("a failing reader reports its own error", func(t *testing.T) {
		key, err := ReadDNSSECPrivateKey(iotest.ErrReader(errReaderSentinel))
		if !errors.Is(err, errReaderSentinel) {
			t.Errorf("ReadDNSSECPrivateKey() error = %v, want it to report %v", err, errReaderSentinel)
		}
		if !errorContains(err, "cannot read DNSSEC private key data") {
			t.Errorf("ReadDNSSECPrivateKey() error = %q, want it to say what it was reading", err)
		}
		if key != nil {
			t.Errorf("ReadDNSSECPrivateKey() returned %s with an error, want nil", describeDNSSECKey(key))
		}
	})

	t.Run("content that reads but does not parse is a parse error", func(t *testing.T) {
		_, err := ReadDNSSECPrivateKey(strings.NewReader(""))
		if !errorContains(err, "no algorithm found in "+parseTestPrivateKeyID) {
			t.Errorf("ReadDNSSECPrivateKey() error = %v, want the parser's own error", err)
		}
	})
}

// parseTestScratchDir creates a scratch directory under tmp/, the way every
// other test in this package keeps its temporary files inside the repository.
func parseTestScratchDir(t *testing.T) string {
	t.Helper()

	if err := os.MkdirAll("tmp", 0o755); err != nil {
		t.Fatal(err)
	}
	dir, err := os.MkdirTemp("tmp", strings.ReplaceAll(t.Name(), "/", "-")+"-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir
}

// TestParseDNSSECKeysMatchReadKeyFile is the equivalence the split of parsing
// and file reading depends on: for the same bytes, the byte-string API and
// ReadKeyFile / ReadPrivateKeyFile produce the same key, and when the bytes do
// not parse they report the same failure and name the path they were given.
// The two APIs spell that name differently on purpose — the file API writes
// "key file <path>", the byte API writes the source label its caller passed,
// here the same path — so the test compares the reason each error gives for
// the failure (and the presence of the path), not the full sentence around it.
func TestParseDNSSECKeysMatchReadKeyFile(t *testing.T) {
	type fileCase struct {
		contents string
		reason   string // what both errors must say about the failure; empty for contents that parse
	}

	cases := []struct {
		label    string
		prefix   string
		suffix   string
		readKey  func(string) (*DNSSECKey, error)
		parse    func([]byte, string) (*DNSSECKey, error)
		contents []fileCase
	}{
		{
			label:   "ReadKeyFile",
			prefix:  "key",
			suffix:  ".key",
			readKey: ReadKeyFile,
			parse:   ParseDNSSECKeyWithSource,
			contents: []fileCase{
				{dnssecKeyFileContents("example.com.", 257, 8, []byte("abcdefghijklmnopqrstuvwxyz")), ""},
				{"example.com. IN DNSKEY 256 3\n", `invalid DNSKEY key line "example.com. IN DNSKEY 256 3": expected at least 7 fields`},
				{"; a comment and nothing else\n", "no DNSKEY record found in "},
			},
		},
		{
			label:   "ReadPrivateKeyFile",
			prefix:  "private",
			suffix:  ".private",
			readKey: ReadPrivateKeyFile,
			parse:   ParseDNSSECPrivateKeyWithSource,
			contents: []fileCase{
				{dnssecPrivateKeyFileContents(15, map[string][]byte{
					"PrivateKey": []byte("01234567890123456789012345678901"),
				}), ""},
				{"Private-key-format: v1.3\nAlgorithm: 5\nModulus: !!!\n", `cannot decode private key parameter "Modulus"`},
				{"Private-key-format: v1.3\nModulus: AQEB\n", "no algorithm found in "},
			},
		},
	}

	dir := parseTestScratchDir(t)

	for _, group := range cases {
		for i, tc := range group.contents {
			path := filepath.Join(dir, fmt.Sprintf("%s-%d%s", group.prefix, i, group.suffix))
			if err := os.WriteFile(path, []byte(tc.contents), 0o644); err != nil {
				t.Fatal(err)
			}

			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}

			fromFile, errFile := group.readKey(path)
			fromBytes, errBytes := group.parse(data, path)

			if (errFile == nil) != (errBytes == nil) {
				t.Fatalf("%s() error = %v, Parse*WithSource() error = %v: want both or neither", group.label, errFile, errBytes)
			}
			if errFile != nil {
				if !errorContains(errFile, tc.reason) {
					t.Errorf("%s(%s) error = %q\nwant an error saying %q", group.label, path, errFile, tc.reason)
				}
				if !errorContains(errBytes, tc.reason) {
					t.Errorf("Parse*WithSource(%s) error = %q\nwant an error saying %q", path, errBytes, tc.reason)
				}
				if !strings.Contains(errFile.Error(), path) || !strings.Contains(errBytes.Error(), path) {
					t.Errorf("%s-style error = %q, byte-API error = %q\nboth must name %s", group.label, errFile, errBytes, path)
				}
				continue
			}
			if describeDNSSECKey(fromFile) != describeDNSSECKey(fromBytes) {
				t.Errorf("%s(%s) returned %s\nParse*WithSource() returned %s\nwant the same key", group.label, path, describeDNSSECKey(fromFile), describeDNSSECKey(fromBytes))
			}
		}
	}
}

// TestParseGeneratedKeysMatchReadKeyFile runs the same comparison over real
// dnssec-keygen output, whose files carry the wrapping and parameter spellings
// a hand-written fixture does not.
func TestParseGeneratedKeysMatchReadKeyFile(t *testing.T) {
	if !dnssecKeygenAvailable(t) {
		return
	}

	for _, kg := range keygenAlgorithms {
		t.Run(kg.name, func(t *testing.T) {
			dir := keygenTempDir(t)
			baseName := generateKeyWithDnssecKeygen(t, dir, kg, dnssecKeygenZone)

			for _, pair := range []struct {
				suffix  string
				readKey func(string) (*DNSSECKey, error)
				parse   func([]byte, string) (*DNSSECKey, error)
			}{
				{".key", ReadKeyFile, ParseDNSSECKeyWithSource},
				{".private", ReadPrivateKeyFile, ParseDNSSECPrivateKeyWithSource},
			} {
				path := filepath.Join(dir, baseName+pair.suffix)
				data, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}

				fromFile, errFile := pair.readKey(path)
				fromBytes, errBytes := pair.parse(data, path)
				if errFile != nil {
					t.Fatalf("reading %s: %v", path, errFile)
				}
				if errBytes != nil {
					t.Fatalf("Parse*WithSource(%s) error = %v", path, errBytes)
				}
				if describeDNSSECKey(fromFile) != describeDNSSECKey(fromBytes) {
					t.Errorf("reading %s as bytes returned %s\nreading it as a file returned %s\nwant the same key",
						path, describeDNSSECKey(fromBytes), describeDNSSECKey(fromFile))
				}
			}
		})
	}
}

// TestParseDNSSECKeyLine parses one line, including one with padding around it.
// The errors are parseKeyLine's own, without the wrapper parseKeyData adds.
func TestParseDNSSECKeyLine(t *testing.T) {
	t.Run("valid line", func(t *testing.T) {
		const material = "some public key bytes"
		key, err := ParseDNSSECKeyLine(dnssecKeyFileContents("example.com.", 257, 5, []byte(material)))
		if err != nil {
			t.Fatalf("ParseDNSSECKeyLine() error = %v", err)
		}
		if key.Flags != 257 || key.Algorithm != 5 {
			t.Errorf("key.Flags, key.Algorithm = %d, %d, want 257, 5", key.Flags, key.Algorithm)
		}
		if string(key.PublicKey) != material {
			t.Errorf("key.PublicKey = %q, want %q", key.PublicKey, material)
		}
	})

	t.Run("surrounding whitespace", func(t *testing.T) {
		line := "  \t" + strings.TrimSuffix(dnssecKeyFileContents("example.com.", 256, 8, []byte("ab")), "\n") + "\t \r"
		key, err := ParseDNSSECKeyLine(line)
		if err != nil {
			t.Fatalf("ParseDNSSECKeyLine() error = %v", err)
		}
		if got := key.Name.String(); got != "example.com." {
			t.Errorf("key.Name = %q, want %q", got, "example.com.")
		}
	})

	tests := []struct {
		name string
		line string
		want string
	}{
		{
			name: "empty line",
			line: "",
			want: "expected at least 7 fields",
		},
		{
			name: "wrong class",
			line: "example.com. CH DNSKEY 256 3 8 YWJj",
			want: "expected class IN",
		},
		{
			name: "wrong type",
			line: "example.com. IN A 256 3 8 YWJj",
			want: "expected type DNSKEY",
		},
		{
			name: "bad flags",
			line: "example.com. IN DNSKEY -1 3 8 YWJj",
			want: `invalid flags "-1"`,
		},
		{
			name: "bad protocol",
			line: "example.com. IN DNSKEY 256 256 8 YWJj",
			want: `invalid protocol "256"`,
		},
		{
			name: "bad algorithm",
			line: "example.com. IN DNSKEY 256 3 -1 YWJj",
			want: `invalid algorithm "-1"`,
		},
		{
			name: "bad public key",
			line: "example.com. IN DNSKEY 256 3 8 @@@@@",
			want: "invalid DNSKEY public key",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			key, err := ParseDNSSECKeyLine(tc.line)
			if err == nil {
				t.Fatalf("ParseDNSSECKeyLine(%q) error = nil, want an error", tc.line)
			}
			if key != nil {
				t.Errorf("ParseDNSSECKeyLine(%q) returned %s with an error, want nil", tc.line, describeDNSSECKey(key))
			}
			if !errorContains(err, tc.want) {
				t.Errorf("ParseDNSSECKeyLine(%q) error = %q, want it to mention %q", tc.line, err, tc.want)
			}
			if errorContains(err, "cannot parse") {
				t.Errorf("ParseDNSSECKeyLine(%q) error = %q, want the line's own error without the parse wrapper", tc.line, err)
			}
		})
	}
}

// TestParseAndMergeGeneratedKeysSignAndVerify is the whole path a program that
// keeps key material outside the filesystem takes: parse both halves from bytes,
// merge them, compute the key tag, and sign and verify an RRSet with the result.
// The key tag must be the one dnssec-keygen put in the file names.
func TestParseAndMergeGeneratedKeysSignAndVerify(t *testing.T) {
	if !dnssecKeygenAvailable(t) {
		return
	}

	for _, kg := range keygenAlgorithms {
		t.Run(kg.name, func(t *testing.T) {
			dir := keygenTempDir(t)
			baseName := generateKeyWithDnssecKeygen(t, dir, kg, dnssecKeygenZone)

			publicData, err := os.ReadFile(filepath.Join(dir, baseName+".key"))
			if err != nil {
				t.Fatal(err)
			}
			privateData, err := os.ReadFile(filepath.Join(dir, baseName+".private"))
			if err != nil {
				t.Fatal(err)
			}

			public, err := ParseDNSSECKey(publicData)
			if err != nil {
				t.Fatalf("ParseDNSSECKey() error = %v", err)
			}
			private, err := ReadDNSSECPrivateKey(bytes.NewReader(privateData))
			if err != nil {
				t.Fatalf("ReadDNSSECPrivateKey() error = %v", err)
			}

			merged, err := MergeDNSSECKey(public, private)
			if err != nil {
				t.Fatalf("MergeDNSSECKey() error = %v", err)
			}

			wantTag := keyTagFromKeyBaseName(t, baseName)
			gotTag, err := merged.KeyTag()
			if err != nil {
				t.Fatalf("merged.KeyTag() error = %v", err)
			}
			if gotTag != wantTag {
				t.Errorf("merged.KeyTag() = %d, want the key tag dnssec-keygen recorded in %s", gotTag, baseName)
			}
			recordTag := merged.ToDNSKEY().KeyTag()
			if recordTag != wantTag {
				t.Errorf("merged.ToDNSKEY().KeyTag() = %d, want %d", recordTag, wantTag)
			}

			if !kg.sign {
				// An algorithm this package cannot sign with still parses and
				// reports its tag; only signing is out of scope.
				if _, err := NewDNSSECSigner(merged); err == nil {
					t.Errorf("NewDNSSECSigner() error = nil for algorithm %d, which this package does not sign with", merged.Algorithm)
				}
				return
			}

			signer, err := NewDNSSECSigner(merged)
			if err != nil {
				t.Fatalf("NewDNSSECSigner() error = %v", err)
			}
			signAndVerifyRRSet(t, merged, signer, merged.PublicKey)
		})
	}
}

// TestParseAndMergeGeneratedKeysWithoutKeygen is the same path with keys
// generated in memory, so that it runs where dnssec-keygen is not installed and
// covers every algorithm this package signs with.
func TestParseAndMergeGeneratedKeysWithoutKeygen(t *testing.T) {
	for _, algorithm := range SupportedDNSSECAlgorithms() {
		t.Run(algorithmName(algorithm), func(t *testing.T) {
			testKey := newVerifyTestKey(t, algorithm)
			material := dnskeyMaterialFromPublicKey(t, testKey.pubkey)
			params := dnssecPrivateKeyParams(t, testKey.signer)

			public, err := ParseDNSSECKey([]byte(dnssecKeyFileContents(dnssecKeygenZone+".", 257, algorithm, material)))
			if err != nil {
				t.Fatalf("ParseDNSSECKey() error = %v", err)
			}
			private, err := ParseDNSSECPrivateKey([]byte(dnssecPrivateKeyFileContents(algorithm, params)))
			if err != nil {
				t.Fatalf("ParseDNSSECPrivateKey() error = %v", err)
			}

			merged, err := MergeDNSSECKey(public, private)
			if err != nil {
				t.Fatalf("MergeDNSSECKey() error = %v", err)
			}
			if merged.Algorithm != algorithm {
				t.Errorf("merged.Algorithm = %d, want %d", merged.Algorithm, algorithm)
			}
			if !bytes.Equal(merged.PublicKey, material) {
				t.Errorf("merged.PublicKey does not match the public half the .key contents carried")
			}
			wantScalar := dnssecPrivateScalarFromParams(params)
			if !bytes.Equal(merged.PrivateKey, wantScalar) {
				t.Errorf("merged.PrivateKey = %x, want the private scalar %x", merged.PrivateKey, wantScalar)
			}

			keyTag, err := merged.KeyTag()
			if err != nil {
				t.Fatalf("merged.KeyTag() error = %v", err)
			}
			if want := merged.ToDNSKEY().KeyTag(); keyTag != want {
				t.Errorf("merged.KeyTag() = %d, want the key tag of the DNSKEY record, %d", keyTag, want)
			}

			signer, err := NewDNSSECSigner(merged)
			if err != nil {
				t.Fatalf("NewDNSSECSigner() error = %v", err)
			}
			signAndVerifyRRSet(t, merged, signer, material)
		})
	}
}

// TestParseDNSSECPrivateKeyMatchesReadPrivateKeyFile checks that the private
// half parsed from bytes is the value NewDNSSECSigner can sign with, which is
// what a caller that reads the file itself needs.
func TestParseDNSSECPrivateKeyMatchesReadPrivateKeyFile(t *testing.T) {
	testKey := newVerifyTestKey(t, 15)
	params := dnssecPrivateKeyParams(t, testKey.signer)
	data := []byte(dnssecPrivateKeyFileContents(15, params))

	dir := parseTestScratchDir(t)
	path := filepath.Join(dir, "Kexample.com.+015+00000.private")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}

	fromFile, err := ReadPrivateKeyFile(path)
	if err != nil {
		t.Fatalf("ReadPrivateKeyFile() error = %v", err)
	}
	fromBytes, err := ParseDNSSECPrivateKey(data)
	if err != nil {
		t.Fatalf("ParseDNSSECPrivateKey() error = %v", err)
	}
	if describeDNSSECKey(fromFile) != describeDNSSECKey(fromBytes) {
		t.Errorf("parsing the octets returned %s\nreading the file returned %s\nwant the same key", describeDNSSECKey(fromBytes), describeDNSSECKey(fromFile))
	}

	// The parsed private half alone has no public key, so it cannot compute a
	// key tag, and NewDNSSECSigner still builds a signer from it.
	if _, err := fromBytes.KeyTag(); err == nil {
		t.Errorf("fromBytes.KeyTag() error = nil, want an error: a .private file carries no public key")
	}
	if _, err := fromFile.KeyTag(); err == nil {
		t.Errorf("fromFile.KeyTag() error = nil, want an error: a .private file carries no public key")
	}
	signer, err := NewDNSSECSigner(fromBytes)
	if err != nil {
		t.Fatalf("NewDNSSECSigner() error = %v", err)
	}
	if !bytes.Equal(dnskeyMaterialFromPublicKey(t, signer.Public()), dnskeyMaterialFromPublicKey(t, testKey.pubkey)) {
		t.Errorf("the signer built from the parsed bytes is not the key those bytes describe")
	}
}

// A Reader implementation that is not a bytes.Reader or strings.Reader, to keep
// the API honest about only needing io.Reader.
type countingReader struct {
	t      *testing.T
	data   io.Reader
	calls  int
	closed bool
}

func (r *countingReader) Read(p []byte) (int, error) {
	r.calls++
	if r.closed {
		return 0, io.EOF
	}
	n, err := r.data.Read(p)
	if err != nil && !errors.Is(err, io.EOF) {
		r.t.Errorf("countingReader: %v", err)
	}
	if errors.Is(err, io.EOF) {
		r.closed = true
	}
	return n, err
}

func TestParseDNSSECKeysAcceptAnyReader(t *testing.T) {
	keyData := dnssecKeyFileContents("example.com.", 256, 8, []byte("abcdefgh"))
	privateData := dnssecPrivateKeyFileContents(8, map[string][]byte{
		"Modulus":         []byte("n"),
		"PublicExponent":  []byte("AQAB"),
		"PrivateExponent": []byte("d"),
	})

	r := &countingReader{t: t, data: strings.NewReader(keyData)}
	key, err := ReadDNSSECKey(r)
	if err != nil {
		t.Fatalf("ReadDNSSECKey() error = %v", err)
	}
	if r.calls == 0 {
		t.Errorf("ReadDNSSECKey() did not call Read on the reader it was given")
	}
	want, err := ParseDNSSECKey([]byte(keyData))
	if err != nil {
		t.Fatal(err)
	}
	if describeDNSSECKey(key) != describeDNSSECKey(want) {
		t.Errorf("ReadDNSSECKey() returned %s, want %s", describeDNSSECKey(key), describeDNSSECKey(want))
	}

	r = &countingReader{t: t, data: strings.NewReader(privateData)}
	private, err := ReadDNSSECPrivateKey(r)
	if err != nil {
		t.Fatalf("ReadDNSSECPrivateKey() error = %v", err)
	}
	if r.calls == 0 {
		t.Errorf("ReadDNSSECPrivateKey() did not call Read on the reader it was given")
	}
	wantPrivate, err := ParseDNSSECPrivateKey([]byte(privateData))
	if err != nil {
		t.Fatal(err)
	}
	if describeDNSSECKey(private) != describeDNSSECKey(wantPrivate) {
		t.Errorf("ReadDNSSECPrivateKey() returned %s, want %s", describeDNSSECKey(private), describeDNSSECKey(wantPrivate))
	}
	if !bytes.Equal(private.PrivateKey, []byte("d")) {
		t.Errorf("private.PrivateKey = %x, want the PrivateExponent", private.PrivateKey)
	}
}
