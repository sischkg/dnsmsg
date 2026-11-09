package dnsmsg

import (
	"path/filepath"
	"strings"
	"testing"
)

// TestNewDNSSECKeyFileNameFromString covers the spellings of a dnssec-keygen
// key file name that parse: bare names, names with and without the ".key" or
// ".private" suffix, full paths, and the boundary values of the algorithm and
// key tag fields.  No file is involved: none of these names exists.
func TestNewDNSSECKeyFileNameFromString(t *testing.T) {
	cases := []struct {
		name     string
		input    string
		baseName string
		wantName string
		algo     uint8
		keyTag   uint16
	}{
		{
			name:     "bare base name",
			input:    "Kexample.com.+008+12345",
			baseName: "Kexample.com.+008+12345",
			wantName: "example.com.",
			algo:     8,
			keyTag:   12345,
		},
		{
			name:     "key file",
			input:    "Kexample.com.+008+12345.key",
			baseName: "Kexample.com.+008+12345",
			wantName: "example.com.",
			algo:     8,
			keyTag:   12345,
		},
		{
			name:     "private file",
			input:    "Kexample.com.+013+02570.private",
			baseName: "Kexample.com.+013+02570",
			wantName: "example.com.",
			algo:     13,
			keyTag:   2570,
		},
		{
			name:     "full path to a key file",
			input:    "/some/dir/Kexample.com.+013+43580.key",
			baseName: "Kexample.com.+013+43580",
			wantName: "example.com.",
			algo:     13,
			keyTag:   43580,
		},
		{
			name:     "relative path without a suffix",
			input:    "keys/Kexample.com.+008+1",
			baseName: "Kexample.com.+008+1",
			wantName: "example.com.",
			algo:     8,
			keyTag:   1,
		},
		{
			name:     "fields without leading zeroes",
			input:    "Kexample.com.+8+1",
			baseName: "Kexample.com.+8+1",
			wantName: "example.com.",
			algo:     8,
			keyTag:   1,
		},
		{
			name:     "zero algorithm and zero key tag",
			input:    "Kexample.com.+0+0",
			baseName: "Kexample.com.+0+0",
			wantName: "example.com.",
			algo:     0,
			keyTag:   0,
		},
		{
			name:     "largest algorithm and key tag",
			input:    "Kexample.com.+255+65535",
			baseName: "Kexample.com.+255+65535",
			wantName: "example.com.",
			algo:     255,
			keyTag:   65535,
		},
		{
			name:     "root owner name",
			input:    "K.+013+43580",
			baseName: "K.+013+43580",
			wantName: ".",
			algo:     13,
			keyTag:   43580,
		},
		{
			name:     "mixed case owner name",
			input:    "Ksub.EXAMPLE.Com.+008+1",
			baseName: "Ksub.EXAMPLE.Com.+008+1",
			wantName: "sub.EXAMPLE.Com.",
			algo:     8,
			keyTag:   1,
		},
		{
			name:     "owner name with a \\DDD escape",
			input:    `Kweird\046name.example.+008+1`,
			baseName: `Kweird\046name.example.+008+1`,
			wantName: `weird\046name.example.`,
			algo:     8,
			keyTag:   1,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := NewDNSSECKeyFileNameFromString(tc.input)
			if err != nil {
				t.Fatalf("NewDNSSECKeyFileNameFromString(%q): %v", tc.input, err)
			}
			if got.BaseName != tc.baseName {
				t.Errorf("BaseName = %q, want %q", got.BaseName, tc.baseName)
			}
			want, err := NewDomainNameFromString(tc.wantName)
			if err != nil {
				t.Fatalf("NewDomainNameFromString(%q): %v", tc.wantName, err)
			}
			if !got.Name.Equal(want) {
				t.Errorf("Name = %q, want the name %q", got.Name.String(), tc.wantName)
			}
			if got.Algorithm != tc.algo {
				t.Errorf("Algorithm = %d, want %d", got.Algorithm, tc.algo)
			}
			if got.KeyTag != tc.keyTag {
				t.Errorf("KeyTag = %d, want %d", got.KeyTag, tc.keyTag)
			}
		})
	}
}

// TestNewDNSSECKeyFileNameFromStringErrors covers the names that are not a
// dnssec-keygen key file name.  Every error names the part of the name that
// caused it.
func TestNewDNSSECKeyFileNameFromStringErrors(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "empty name",
			input: "",
			want:  "the name is empty",
		},
		{
			name:  "key suffix with no name before it",
			input: ".key",
			want:  "the name is empty",
		},
		{
			name:  "private suffix with no name before it",
			input: ".private",
			want:  "the name is empty",
		},
		{
			name:  "key suffix not lower case",
			input: "Kexample.com.+008+12345.Key",
			want:  `key file suffix is ".Key", which is not spelled in lower case`,
		},
		{
			name:  "private suffix not lower case",
			input: "Kexample.com.+008+12345.PRIVATE",
			want:  `key file suffix is ".PRIVATE", which is not spelled in lower case`,
		},
		{
			name:  "no K prefix",
			input: "example.com.+008+12345",
			want:  `the name does not begin with "K"`,
		},
		{
			name:  "lower case k prefix",
			input: "kexample.com.+008+12345",
			want:  `the name does not begin with "K"`,
		},
		{
			name:  "K alone",
			input: "K",
			want:  "want 3: the owner name, the algorithm and the key tag",
		},
		{
			name:  "two fields",
			input: "K+008",
			want:  "want 3: the owner name, the algorithm and the key tag",
		},
		{
			name:  "missing key tag field",
			input: "Kexample.com.+008",
			want:  "want 3: the owner name, the algorithm and the key tag",
		},
		{
			name:  "four fields",
			input: "Kexample.com.+008+1+2",
			want:  "want 3: the owner name, the algorithm and the key tag",
		},
		{
			name:  "owner name containing a plus",
			input: "Kbad+name.example.+008+1",
			want:  "want 3: the owner name, the algorithm and the key tag",
		},
		{
			name:  "empty label in the owner name",
			input: "K..+008+1",
			want:  `owner name ".."`,
		},
		{
			name:  "algorithm above 255",
			input: "Kexample.com.+256+1",
			want:  `algorithm "256"`,
		},
		{
			name:  "algorithm not a number",
			input: "Kexample.com.+abc+1",
			want:  `algorithm "abc"`,
		},
		{
			name:  "algorithm field empty",
			input: "Kexample.com.++1",
			want:  `algorithm ""`,
		},
		{
			name:  "key tag above 65535",
			input: "Kexample.com.+008+65536",
			want:  `key tag "65536"`,
		},
		{
			name:  "key tag not a number",
			input: "Kexample.com.+008+abc",
			want:  `key tag "abc"`,
		},
		{
			name:  "key tag negative",
			input: "Kexample.com.+008+-1",
			want:  `key tag "-1"`,
		},
		{
			name:  "some other suffix is not stripped and reaches the key tag field",
			input: "Kzone.example.+008+123.tar.gz",
			want:  `key tag "123.tar.gz"`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := NewDNSSECKeyFileNameFromString(tc.input)
			if err == nil {
				t.Fatalf("NewDNSSECKeyFileNameFromString(%q) returned %+v, want an error", tc.input, got)
			}
			if !strings.HasPrefix(err.Error(), "cannot parse DNSSEC key file name") {
				t.Errorf("error %q does not begin with the key file name prefix", err)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not contain %q", err, tc.want)
			}
		})
	}
}

// TestNewDNSSECKeyBaseName checks the spelling the generator produces,
// including the zero-padding dnssec-keygen uses for the algorithm and key tag
// fields.
func TestNewDNSSECKeyBaseName(t *testing.T) {
	cases := []struct {
		name  string
		input string
		algo  uint8
		tag   uint16
		want  string
	}{
		{
			name:  "zone key name",
			input: "example.com.",
			algo:  8,
			tag:   12345,
			want:  "Kexample.com.+008+12345",
		},
		{
			name:  "root zone",
			input: ".",
			algo:  13,
			tag:   43580,
			want:  "K.+013+43580",
		},
		{
			name:  "zero fields are zero-padded",
			input: "x.example.",
			algo:  0,
			tag:   0,
			want:  "Kx.example.+000+00000",
		},
		{
			name:  "small key tag is zero-padded to five digits",
			input: "x.example.",
			algo:  13,
			tag:   1,
			want:  "Kx.example.+013+00001",
		},
		{
			name:  "largest fields need no padding",
			input: "x.example.",
			algo:  255,
			tag:   65535,
			want:  "Kx.example.+255+65535",
		},
		{
			name:  "owner name case is preserved",
			input: "Sub.Example.",
			algo:  8,
			tag:   12345,
			want:  "KSub.Example.+008+12345",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			name, err := NewDomainNameFromString(tc.input)
			if err != nil {
				t.Fatalf("NewDomainNameFromString(%q): %v", tc.input, err)
			}
			got := NewDNSSECKeyBaseName(name, tc.algo, tc.tag)
			if got != tc.want {
				t.Errorf("NewDNSSECKeyBaseName returned %q, want %q", got, tc.want)
			}
		})
	}
}

// TestNewDNSSECKeyBaseNameRoundTrip parses every generated base name back with
// NewDNSSECKeyFileNameFromString, with and without each file suffix, and
// requires the parsed fields to be the generated ones.
func TestNewDNSSECKeyBaseNameRoundTrip(t *testing.T) {
	names := []string{"example.com.", ".", "sub.example.com."}
	for _, nameText := range names {
		name, err := NewDomainNameFromString(nameText)
		if err != nil {
			t.Fatalf("NewDomainNameFromString(%q): %v", nameText, err)
		}
		for _, alg := range []uint8{0, 8, 13, 255} {
			for _, tag := range []uint16{0, 1, 2570, 43580, 65535} {
				baseName := NewDNSSECKeyBaseName(name, alg, tag)
				for _, input := range []string{baseName, baseName + ".key", baseName + ".private"} {
					got, err := NewDNSSECKeyFileNameFromString(input)
					if err != nil {
						t.Fatalf("NewDNSSECKeyFileNameFromString(%q): %v", input, err)
					}
					if got.BaseName != baseName {
						t.Errorf("BaseName = %q, want %q", got.BaseName, baseName)
					}
					if !got.Name.Equal(name) {
						t.Errorf("Name = %q, want the name %q", got.Name.String(), nameText)
					}
					if got.Algorithm != alg {
						t.Errorf("Algorithm = %d, want %d", got.Algorithm, alg)
					}
					if got.KeyTag != tag {
						t.Errorf("KeyTag = %d, want %d", got.KeyTag, tag)
					}
				}
			}
		}
	}
}

// TestNewDNSSECKeyFileNameFromKeygenFiles parses the file names real
// dnssec-keygen runs created and compares every field with what the tool
// recorded in the file name and in the .key file: the key tag field against
// keyTagFromKeyBaseName, the algorithm against the requested one, and the
// owner name against the Name ReadKeyFile parsed.  It also requires
// NewDNSSECKeyBaseName to reproduce the base name byte for byte.
func TestNewDNSSECKeyFileNameFromKeygenFiles(t *testing.T) {
	if !dnssecKeygenAvailable(t) {
		return
	}

	// Three algorithms are enough to cover RSA, ECDSA and Ed25519 file names.
	for _, kg := range []keygenAlgorithm{keygenAlgorithms[2], keygenAlgorithms[4], keygenAlgorithms[6]} {
		t.Run(kg.name, func(t *testing.T) {
			dir := keygenTempDir(t)
			baseName := generateKeyWithDnssecKeygen(t, dir, kg, dnssecKeygenZone)
			wantTag := keyTagFromKeyBaseName(t, baseName)

			key, err := ReadKeyFile(filepath.Join(dir, baseName+".key"))
			if err != nil {
				t.Fatalf("ReadKeyFile(%s.key): %v", baseName, err)
			}
			if key.Algorithm != kg.algo {
				t.Fatalf("%s.key declares algorithm %d, want %d", baseName, key.Algorithm, kg.algo)
			}

			for _, input := range []string{
				baseName,
				baseName + ".key",
				baseName + ".private",
				filepath.Join(dir, baseName+".key"),
			} {
				got, err := NewDNSSECKeyFileNameFromString(input)
				if err != nil {
					t.Fatalf("NewDNSSECKeyFileNameFromString(%q): %v", input, err)
				}
				if got.BaseName != baseName {
					t.Errorf("NewDNSSECKeyFileNameFromString(%q): BaseName = %q, want %q", input, got.BaseName, baseName)
				}
				if !got.Name.Equal(key.Name) {
					t.Errorf("NewDNSSECKeyFileNameFromString(%q): Name = %q, want the name in %s.key", input, got.Name.String(), baseName)
				}
				if got.Algorithm != kg.algo {
					t.Errorf("NewDNSSECKeyFileNameFromString(%q): Algorithm = %d, want %d", input, got.Algorithm, kg.algo)
				}
				if got.KeyTag != wantTag {
					t.Errorf("NewDNSSECKeyFileNameFromString(%q): KeyTag = %d, want %d", input, got.KeyTag, wantTag)
				}
			}

			if generated := NewDNSSECKeyBaseName(key.Name, key.Algorithm, wantTag); generated != baseName {
				t.Errorf("NewDNSSECKeyBaseName returned %q, want the generated name %q", generated, baseName)
			}
		})
	}
}

// TestInferDNSSECKeyNameFromFileName covers the owner name the helper reads out
// of every spelling of a key file name.  The same rules as
// TestNewDNSSECKeyFileNameFromString apply, but only the name is returned.
func TestInferDNSSECKeyNameFromFileName(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "bare base name",
			input: "Kexample.com.+008+12345",
			want:  "example.com.",
		},
		{
			name:  "key file",
			input: "Kexample.com.+008+12345.key",
			want:  "example.com.",
		},
		{
			name:  "private file",
			input: "Kexample.com.+013+02570.private",
			want:  "example.com.",
		},
		{
			name:  "full path to a private file",
			input: "/etc/bind/keys/Kexample.com.+013+02570.private",
			want:  "example.com.",
		},
		{
			name:  "relative path without a suffix",
			input: "keys/Kexample.com.+008+1",
			want:  "example.com.",
		},
		{
			name:  "fields without leading zeroes",
			input: "Kexample.com.+8+1",
			want:  "example.com.",
		},
		{
			name:  "root owner name",
			input: "K.+013+43580.private",
			want:  ".",
		},
		{
			name:  "mixed case owner name",
			input: "Ksub.EXAMPLE.Com.+008+1.private",
			want:  "sub.EXAMPLE.Com.",
		},
		{
			// The name is returned as a DomainName, so its presentation form is the
			// one DomainName.String writes: the \DDD escape becomes the shorter
			// equivalent \. spelling.
			name:  "owner name with a \\DDD escape",
			input: `Kweird\046name.example.+008+1.private`,
			want:  `weird\.name.example.`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := InferDNSSECKeyNameFromFileName(tc.input)
			if err != nil {
				t.Fatalf("InferDNSSECKeyNameFromFileName(%q): %v", tc.input, err)
			}
			if got.String() != tc.want {
				t.Errorf("InferDNSSECKeyNameFromFileName(%q) = %q, want %q", tc.input, got.String(), tc.want)
			}
		})
	}
}

// TestInferDNSSECKeyNameFromFileNameErrors covers the names the helper refuses.
// A file name that is not a dnssec-keygen key file name is an error rather than
// a guess, and every error names the file name it was asked about and the part
// of that name that caused it.
func TestInferDNSSECKeyNameFromFileNameErrors(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "empty name",
			input: "",
			want:  "the name is empty",
		},
		{
			name:  "private suffix with no name before it",
			input: ".private",
			want:  "the name is empty",
		},
		{
			name:  "private suffix not lower case",
			input: "Kexample.com.+008+12345.PRIVATE",
			want:  `key file suffix is ".PRIVATE", which is not spelled in lower case`,
		},
		{
			name:  "not a key file name",
			input: "example.com.private",
			want:  `the name does not begin with "K"`,
		},
		{
			name:  "an unrelated file",
			input: "Kexample.com.zone",
			want:  `after the "K" prefix the name has 1 fields separated by "+"`,
		},
		{
			name:  "missing key tag field",
			input: "Kexample.com.+008.private",
			want:  "want 3: the owner name, the algorithm and the key tag",
		},
		{
			name:  "algorithm not a number",
			input: "Kexample.com.+abc+1.private",
			want:  `algorithm "abc"`,
		},
		{
			name:  "key tag above 65535",
			input: "Kexample.com.+008+65536.private",
			want:  `key tag "65536"`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := InferDNSSECKeyNameFromFileName(tc.input)
			if err == nil {
				t.Fatalf("InferDNSSECKeyNameFromFileName(%q) returned %q, want an error", tc.input, got.String())
			}
			prefix := "cannot infer DNSSEC key name from " + tc.input + ": "
			if !strings.HasPrefix(err.Error(), prefix) {
				t.Errorf("error %q does not begin with %q", err, prefix)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not contain %q", err, tc.want)
			}
			if len(got.labels) > 0 {
				t.Errorf("InferDNSSECKeyNameFromFileName(%q) returned the name %q alongside the error", tc.input, got.String())
			}
		})
	}
}

// TestInferDNSSECKeyNameFromKeygenFiles checks the case the helper exists for:
// a key read from a .private file alone, whose owner name is present only in the
// file name.  The inferred name is the name that key's .key file declares.
func TestInferDNSSECKeyNameFromKeygenFiles(t *testing.T) {
	if !dnssecKeygenAvailable(t) {
		return
	}

	// Two algorithms are enough here: the file names do not depend on the key
	// material, and both RSA and Ed25519 are covered elsewhere.
	for _, kg := range []keygenAlgorithm{keygenAlgorithms[2], keygenAlgorithms[6]} {
		t.Run(kg.name, func(t *testing.T) {
			dir := keygenTempDir(t)
			baseName := generateKeyWithDnssecKeygen(t, dir, kg, dnssecKeygenZone)
			wantTag := keyTagFromKeyBaseName(t, baseName)
			privatePath := filepath.Join(dir, baseName+".private")

			key, err := ReadKeyFile(filepath.Join(dir, baseName+".key"))
			if err != nil {
				t.Fatalf("ReadKeyFile(%s.key): %v", baseName, err)
			}

			// ReadPrivateKeyFile keeps the name empty: that is what the helper is
			// for.
			fromPrivate, err := ReadPrivateKeyFile(privatePath)
			if err != nil {
				t.Fatalf("ReadPrivateKeyFile(%s.private): %v", baseName, err)
			}
			// A name with no labels at all is the zero value DomainName, which is
			// not the root: the root is the name with the root label alone.
			if len(fromPrivate.Name.labels) > 0 {
				t.Errorf("ReadPrivateKeyFile named the key %q; the name of a key read from a .private file has no labels", fromPrivate.Name.String())
			}

			for _, input := range []string{
				baseName,
				baseName + ".key",
				baseName + ".private",
				filepath.Join(dir, baseName+".key"),
				privatePath,
			} {
				got, err := InferDNSSECKeyNameFromFileName(input)
				if err != nil {
					t.Fatalf("InferDNSSECKeyNameFromFileName(%q): %v", input, err)
				}
				if !got.Equal(key.Name) {
					t.Errorf("InferDNSSECKeyNameFromFileName(%q) = %q, want the name %q in %s.key", input, got.String(), key.Name.String(), baseName)
				}
			}

			// The inferred name is a usable key name: it generates the file name it
			// came from.
			inferred, err := InferDNSSECKeyNameFromFileName(privatePath)
			if err != nil {
				t.Fatalf("InferDNSSECKeyNameFromFileName(%q): %v", privatePath, err)
			}
			fromPrivate.Name = inferred
			if got, err := fromPrivate.KeyTag(); err == nil {
				t.Errorf("KeyTag returned %d for a key with no public key material, want an error", got)
			}
			merged, err := ReadDNSSECKeyFiles(filepath.Join(dir, baseName+".key"), privatePath)
			if err != nil {
				t.Fatalf("ReadDNSSECKeyFiles(%s): %v", baseName, err)
			}
			merged.Name = inferred
			if !merged.Name.Equal(key.Name) {
				t.Errorf("the merged key is named %q, want %q", merged.Name.String(), key.Name.String())
			}
			gotTag, err := merged.KeyTag()
			if err != nil {
				t.Fatalf("merged key KeyTag: %v", err)
			}
			if gotTag != wantTag {
				t.Errorf("KeyTag = %d, want the key tag %d in %s", gotTag, wantTag, baseName)
			}
			if generated := NewDNSSECKeyBaseName(merged.Name, merged.Algorithm, gotTag); generated != baseName {
				t.Errorf("NewDNSSECKeyBaseName returned %q, want the generated name %q", generated, baseName)
			}
		})
	}
}
