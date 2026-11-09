package dnsmsg

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// writeScratchFile writes content to name in dir and returns the full path.
func writeScratchFile(t *testing.T, dir, name, content string) string {
	t.Helper()

	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("cannot write %s: %v", path, err)
	}
	return path
}

// readScratchFile returns the contents of name in dir.
func readScratchFile(t *testing.T, dir, name string) []byte {
	t.Helper()

	data, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		t.Fatalf("cannot read %s: %v", name, err)
	}
	return data
}

// replacePrivateKeyScalar returns the contents of a .private file with the value
// of its PrivateKey line replaced, so that the file describes a private key of
// the same algorithm but different key material.
func replacePrivateKeyScalar(t *testing.T, content, scalar string) string {
	t.Helper()

	kept := make([]string, 0, 8)
	replaced := false
	for _, raw := range strings.Split(content, "\n") {
		if strings.HasPrefix(strings.TrimSpace(raw), "PrivateKey:") {
			kept = append(kept, "PrivateKey: "+scalar)
			replaced = true
			continue
		}
		kept = append(kept, raw)
	}
	if !replaced {
		t.Fatalf("the private key file has no PrivateKey line to replace:\n%s", content)
	}
	return strings.Join(kept, "\n")
}

// replacePrivateAlgorithm returns the contents of a .private file with the value
// of its Algorithm line replaced, so that the file declares another algorithm
// while keeping its key material.
func replacePrivateAlgorithm(t *testing.T, content, value string) string {
	t.Helper()

	kept := make([]string, 0, 8)
	replaced := false
	for _, raw := range strings.Split(content, "\n") {
		if strings.HasPrefix(strings.TrimSpace(raw), "Algorithm:") {
			kept = append(kept, "Algorithm: "+value)
			replaced = true
			continue
		}
		kept = append(kept, raw)
	}
	if !replaced {
		t.Fatalf("the private key file has no Algorithm line to replace:\n%s", content)
	}
	return strings.Join(kept, "\n")
}

// checkMergedKeyFields checks that the merged key holds the fields of the two
// files it was read from.
func checkMergedKeyFields(t *testing.T, merged, fromKeyFile, fromPrivateFile *DNSSECKey) {
	t.Helper()

	if !merged.Name.Equal(fromKeyFile.Name) {
		t.Errorf("Name = %s, want the .key file name %s", merged.Name, fromKeyFile.Name)
	}
	if merged.Flags != fromKeyFile.Flags {
		t.Errorf("Flags = %d, want the .key file flags %d", merged.Flags, fromKeyFile.Flags)
	}
	if merged.Protocol != fromKeyFile.Protocol {
		t.Errorf("Protocol = %d, want the .key file protocol %d", merged.Protocol, fromKeyFile.Protocol)
	}
	if !bytes.Equal(merged.PublicKey, fromKeyFile.PublicKey) {
		t.Errorf("PublicKey = %x, want the .key file public key %x", merged.PublicKey, fromKeyFile.PublicKey)
	}
	if merged.Algorithm != fromKeyFile.Algorithm {
		t.Errorf("Algorithm = %d, want the algorithm the .key file declares, %d", merged.Algorithm, fromKeyFile.Algorithm)
	}
	if merged.Algorithm != fromPrivateFile.Algorithm {
		t.Errorf("Algorithm = %d, want the algorithm the .private file declares, %d", merged.Algorithm, fromPrivateFile.Algorithm)
	}
	if !bytes.Equal(merged.PrivateKey, fromPrivateFile.PrivateKey) {
		t.Errorf("PrivateKey = %x, want the .private file private key %x", merged.PrivateKey, fromPrivateFile.PrivateKey)
	}
	if len(merged.PrivateParams) != len(fromPrivateFile.PrivateParams) {
		t.Errorf("PrivateParams holds %d parameters, want the %d of the .private file",
			len(merged.PrivateParams), len(fromPrivateFile.PrivateParams))
	}
	for name, want := range fromPrivateFile.PrivateParams {
		got, ok := merged.PrivateParams[name]
		if !ok {
			t.Errorf("PrivateParams is missing the parameter %q", name)
			continue
		}
		if !bytes.Equal(got, want) {
			t.Errorf("PrivateParams[%q] = %x, want %x", name, got, want)
		}
	}
	if _, ok := merged.PrivateParams["Name"]; ok {
		t.Error("PrivateParams carries the key file name under the parameter \"Name\", which the .private file does not define")
	}
}

// keyTagOf checks that the merged key's key tag is the one dnssec-keygen
// recorded in the file name, and that the two ways of computing it agree.
func keyTagOf(t *testing.T, key *DNSSECKey, want uint16) {
	t.Helper()

	tag, err := key.KeyTag()
	if err != nil {
		t.Fatalf("(*DNSSECKey).KeyTag: %v", err)
	}
	if tag != want {
		t.Errorf("(*DNSSECKey).KeyTag() = %d, want the key tag dnssec-keygen recorded in the file name, %d", tag, want)
	}
	dnskey := key.ToDNSKEY()
	if got := dnskey.KeyTag(); got != tag {
		t.Errorf("RecordDNSKEY.KeyTag() = %d, want the same tag as (*DNSSECKey).KeyTag, %d", got, tag)
	}
}

// checkKeyPairDNSKEY checks that a merged key describes the DNSKEY it was read
// from: ToDNSKEY holds its public key material, and the two ways of computing
// the key tag agree.
func checkKeyPairDNSKEY(t *testing.T, key *DNSSECKey) {
	t.Helper()

	dnskey := key.ToDNSKEY()
	if dnskey.Algorithm != key.Algorithm {
		t.Errorf("RecordDNSKEY.Algorithm = %d, want the merged key algorithm %d", dnskey.Algorithm, key.Algorithm)
	}
	if len(dnskey.PublicKey) == 0 {
		t.Error("RecordDNSKEY.PublicKey is empty, want the public key of the .key file")
	}
	tag, err := key.KeyTag()
	if err != nil {
		t.Fatalf("(*DNSSECKey).KeyTag: %v", err)
	}
	if want := DNSSECKeyTag(dnskey.CanonicalWireFormat()); tag != want {
		t.Errorf("(*DNSSECKey).KeyTag() = %d, want the tag computed over the DNSKEY RDATA, %d", tag, want)
	}
	if got := dnskey.KeyTag(); got != tag {
		t.Errorf("RecordDNSKEY.KeyTag() = %d, want the same tag as (*DNSSECKey).KeyTag, %d", got, tag)
	}
}

// TestReadDNSSECKeyPair reads the pair dnssec-keygen generated for each
// algorithm, checks the merged key against what the two files hold on their own,
// checks the key tag against the one dnssec-keygen put in the file name, and
// signs and verifies an RRSet with the merged key.
func TestReadDNSSECKeyPair(t *testing.T) {
	if !dnssecKeygenAvailable(t) {
		return
	}

	for _, kg := range keygenAlgorithms {
		t.Run(kg.name, func(t *testing.T) {
			dir := keygenTempDir(t)
			base := generateKeyWithDnssecKeygen(t, dir, kg, dnssecKeygenZone)
			keyPath := filepath.Join(dir, base+".key")
			privatePath := filepath.Join(dir, base+".private")

			key, err := ReadDNSSECKeyFiles(keyPath, privatePath)
			if err != nil {
				t.Fatalf("ReadDNSSECKeyFiles(%s, %s): %v", keyPath, privatePath, err)
			}

			fromKeyFile, err := ReadKeyFile(keyPath)
			if err != nil {
				t.Fatal(err)
			}
			fromPrivateFile, err := ReadPrivateKeyFile(privatePath)
			if err != nil {
				t.Fatal(err)
			}
			checkMergedKeyFields(t, key, fromKeyFile, fromPrivateFile)

			// The merged key is a whole key: its DNSKEY and key tag need no
			// second look at the .key file.
			dnskey := key.ToDNSKEY()
			if want := fromKeyFile.ToDNSKEY(); !bytes.Equal(dnskey.CanonicalWireFormat(), want.CanonicalWireFormat()) {
				t.Errorf("ToDNSKEY canonical wire format = %x, want the .key file DNSKEY %x",
					dnskey.CanonicalWireFormat(), want.CanonicalWireFormat())
			}
			keyTagOf(t, key, keyTagFromKeyBaseName(t, base))

			if !kg.sign {
				t.Logf("algorithm %d (%s) cannot be used for signing: the merged key is loaded without a signer",
					kg.algo, kg.name)
				return
			}

			signer, err := NewDNSSECSigner(key)
			if err != nil {
				t.Fatalf("NewDNSSECSigner: %v", err)
			}
			keyTag := keyTagFromKeyBaseName(t, base)
			rrset := buildVerifyTestRRSet(t)
			rrsig, err := SignRRSet(&rrset, signer, kg.algo, keyTag, key.Name, testInception, testExpiration)
			if err != nil {
				t.Fatalf("SignRRSet: %v", err)
			}
			if rrsig.KeyTag != keyTag {
				t.Errorf("RRSIG Key Tag = %d, want the merged key's tag %d", rrsig.KeyTag, keyTag)
			}
			if !rrsig.SignersName.Equal(key.Name) {
				t.Errorf("RRSIG Signer Name = %s, want the key owner name %s", rrsig.SignersName, key.Name)
			}
			if err := VerifyRRSetWithDNSKEY(&rrset, rrsig, &dnskey, testVerifyTime); err != nil {
				t.Errorf("VerifyRRSetWithDNSKEY: %v", err)
			}
		})
	}
}

// TestSignRRSetWithMergedKeyPair signs and verifies an RRSet with a merged key
// read from a real key pair, in the shape a signing program uses: read the
// pair, build the signer and key tag from it, sign one RRSet, and verify that
// signature against the DNSKEY the merged key produces.
func TestSignRRSetWithMergedKeyPair(t *testing.T) {
	if !dnssecKeygenAvailable(t) {
		return
	}

	for _, kg := range keygenAlgorithms {
		if !kg.sign {
			continue
		}
		t.Run(kg.name, func(t *testing.T) {
			dir := keygenTempDir(t)
			base := generateKeyWithDnssecKeygen(t, dir, kg, dnssecKeygenZone)

			key, err := ReadDNSSECKeyPair(filepath.Join(dir, base))
			if err != nil {
				t.Fatalf("ReadDNSSECKeyPair(%s): %v", base, err)
			}
			signer, err := NewDNSSECSigner(key)
			if err != nil {
				t.Fatalf("NewDNSSECSigner: %v", err)
			}
			keyTag, err := key.KeyTag()
			if err != nil {
				t.Fatalf("(*DNSSECKey).KeyTag: %v", err)
			}
			if want := keyTagFromKeyBaseName(t, base); keyTag != want {
				t.Errorf("key tag = %d, want the one dnssec-keygen recorded in the file name, %d", keyTag, want)
			}

			rrset := buildVerifyTestRRSet(t)
			rrsig, err := SignRRSet(&rrset, signer, key.Algorithm, keyTag, key.Name, testInception, testExpiration)
			if err != nil {
				t.Fatalf("SignRRSet: %v", err)
			}
			if rrsig.TypeCovered != uint16(rrset.Type) {
				t.Errorf("RRSIG Type Covered = %d, want the RRSet type %d", rrsig.TypeCovered, rrset.Type)
			}
			if rrsig.OrigTTL != rrset.TTL {
				t.Errorf("RRSIG Original TTL = %d, want the RRSet TTL %d", rrsig.OrigTTL, rrset.TTL)
			}
			if !rrsig.SignersName.Equal(key.Name) {
				t.Errorf("RRSIG Signer Name = %s, want the key owner name %s", rrsig.SignersName, key.Name)
			}

			dnskey := key.ToDNSKEY()
			if err := VerifyRRSetWithDNSKEY(&rrset, rrsig, &dnskey, testVerifyTime); err != nil {
				t.Errorf("VerifyRRSetWithDNSKEY: %v", err)
			}
			if err := VerifyRRSet(&rrset, rrsig, signer.Public(), testVerifyTime); err != nil {
				t.Errorf("VerifyRRSet: %v", err)
			}

			// The signature is outside the validity window the call asked for.
			if err := VerifyRRSetWithDNSKEY(&rrset, rrsig, &dnskey, time.Unix(int64(testExpiration)+3600, 0)); err == nil {
				t.Error("VerifyRRSetWithDNSKEY accepted a signature after its expiration")
			}
		})
	}
}

// TestReadDNSSECKeyPairBaseName checks that the bare base name, either file name
// and a base name with a directory in it all select the same pair.
func TestReadDNSSECKeyPairBaseName(t *testing.T) {
	if !dnssecKeygenAvailable(t) {
		return
	}

	dir := keygenTempDir(t)
	kg := keygenAlgorithms[6]
	base := generateKeyWithDnssecKeygen(t, dir, kg, dnssecKeygenZone)

	fromBase, err := ReadDNSSECKeyPair(filepath.Join(dir, base))
	if err != nil {
		t.Fatalf("ReadDNSSECKeyPair(%s): %v", filepath.Join(dir, base), err)
	}
	if fromBase.Algorithm != kg.algo {
		t.Errorf("algorithm from the base name = %d, want %d", fromBase.Algorithm, kg.algo)
	}

	for _, suffix := range []string{".key", ".private"} {
		fromFile, err := ReadDNSSECKeyPair(filepath.Join(dir, base+suffix))
		if err != nil {
			t.Fatalf("ReadDNSSECKeyPair(%s): %v", base+suffix, err)
		}
		if !fromFile.Name.Equal(fromBase.Name) || fromFile.Algorithm != fromBase.Algorithm {
			t.Errorf("ReadDNSSECKeyPair(%s) returned the key %s algorithm %d, want %s algorithm %d",
				base+suffix, fromFile.Name, fromFile.Algorithm, fromBase.Name, fromBase.Algorithm)
		}
		if !bytes.Equal(fromFile.PublicKey, fromBase.PublicKey) || !bytes.Equal(fromFile.PrivateKey, fromBase.PrivateKey) {
			t.Errorf("ReadDNSSECKeyPair(%s) returned different key material than the base name", base+suffix)
		}
	}

	// The two halves of a pair are looked up in the directory of the name the
	// caller passed, so a base name with a directory in it resolves there, while
	// the bare base name is looked up in the working directory.
	if _, err := os.Stat(filepath.Join(dir, base+".key")); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadDNSSECKeyPair(base); err == nil {
		t.Errorf("ReadDNSSECKeyPair(%s) found the pair in the working directory, where it is not", base)
	}
}

// TestDNSSECKeyPairFileNames checks how a base name is turned into the two file
// names without reading any file.
func TestDNSSECKeyPairFileNames(t *testing.T) {
	cases := []struct {
		name      string
		baseName  string
		keyFile   string
		private   string
		errSubstr string
	}{
		{
			name:     "bare base name",
			baseName: "Kexample.com.+008+12345",
			keyFile:  "Kexample.com.+008+12345.key",
			private:  "Kexample.com.+008+12345.private",
		},
		{
			name:     "key file name",
			baseName: "Kexample.com.+008+12345.key",
			keyFile:  "Kexample.com.+008+12345.key",
			private:  "Kexample.com.+008+12345.private",
		},
		{
			name:     "private key file name",
			baseName: "Kexample.com.+008+12345.private",
			keyFile:  "Kexample.com.+008+12345.key",
			private:  "Kexample.com.+008+12345.private",
		},
		{
			name:     "base name with a directory",
			baseName: "keys/Kexample.com.+008+12345.private",
			keyFile:  "keys/Kexample.com.+008+12345.key",
			private:  "keys/Kexample.com.+008+12345.private",
		},
		{
			name:      "a name that looks like a key file but is not one",
			baseName:  "Kexample.com.+008+12345.Key",
			errSubstr: `the key file suffix is ".Key", which is not spelled in lower case`,
		},
		{
			name:     "an unrelated suffix",
			baseName: "Kexample.com.+008+12345.key.bak",
			keyFile:  "Kexample.com.+008+12345.key.bak.key",
			private:  "Kexample.com.+008+12345.key.bak.private",
		},
		{
			name:     "a base name that is a domain name",
			baseName: "Kexample.com.+008+12345",
			keyFile:  "Kexample.com.+008+12345.key",
			private:  "Kexample.com.+008+12345.private",
		},
		{
			name:      "empty base name",
			baseName:  "",
			errSubstr: "the base name is empty",
		},
		{
			name:      "a suffix and nothing before it",
			baseName:  ".key",
			errSubstr: "the base name is empty",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			keyFile, privateFile, err := dnssecKeyPairFileNames(tc.baseName)
			if tc.errSubstr != "" {
				if err == nil {
					t.Fatalf("dnssecKeyPairFileNames(%q) returned no error, want one naming %q", tc.baseName, tc.errSubstr)
				}
				checkErrContains(t, err, tc.errSubstr)
				return
			}
			if err != nil {
				t.Fatalf("dnssecKeyPairFileNames(%q): %v", tc.baseName, err)
			}
			if keyFile != tc.keyFile {
				t.Errorf("the key file name is %q, want %q", keyFile, tc.keyFile)
			}
			if privateFile != tc.private {
				t.Errorf("the private key file name is %q, want %q", privateFile, tc.private)
			}
		})
	}
}

// TestReadDNSSECKeyPairFileNotFound checks that a base name with no pair beside
// it produces the error of the key file, which is the first of the two to be
// read, and names the file it looked for.
func TestReadDNSSECKeyPairFileNotFound(t *testing.T) {
	dir := keygenTempDir(t)
	baseName := "Kexample.com.+013+54321"
	keyFile, privateFile, err := dnssecKeyPairFileNames(baseName)
	if err != nil {
		t.Fatal(err)
	}

	key, err := ReadDNSSECKeyPair(filepath.Join(dir, baseName))
	if err == nil {
		t.Fatalf("ReadDNSSECKeyPair found a pair for %s, which has no files", baseName)
	}
	if key != nil {
		t.Errorf("ReadDNSSECKeyPair returned a key with an error: %v", key)
	}
	checkErrContains(t, err, filepath.Join(dir, keyFile))
	if strings.Contains(err.Error(), privateFile) {
		t.Errorf("the error mentions the private key file %s before the key file was read: %v", privateFile, err)
	}

	// Only one half of the pair is not a pair.
	writeScratchFile(t, dir, keyFile, algorithmNameKeyFileText(t, 15))
	if _, err := ReadDNSSECKeyPair(filepath.Join(dir, baseName)); err == nil {
		t.Error("ReadDNSSECKeyPair accepted a base name whose .private file does not exist")
	} else {
		checkErrContains(t, err, filepath.Join(dir, privateFile))
	}
}

// TestReadDNSSECKeyFilesErrors covers the ways a pair fails to load.  The two
// files start as real dnssec-keygen output, which the test then changes so that
// one half no longer belongs to the other, or so that one of them cannot be read.
func TestReadDNSSECKeyFilesErrors(t *testing.T) {
	if !dnssecKeygenAvailable(t) {
		return
	}
	// One key pair supplies the two texts the cases are built from, a second key
	// pair supplies a private key that belongs to a different public key.  Each
	// dnssec-keygen run needs a directory of its own, because it finds the files
	// it created by looking for the key files in the directory it ran in.  The
	// files each case writes are written in a directory of their own.
	dir := keygenTempDir(t)
	firstDir := keygenTempDir(t)
	first := generateKeyWithDnssecKeygen(t, firstDir, keygenAlgorithms[6], dnssecKeygenZone)
	keyText := string(readScratchFile(t, firstDir, first+".key"))
	privateText := string(readScratchFile(t, firstDir, first+".private"))

	secondDir := keygenTempDir(t)
	second := generateKeyWithDnssecKeygen(t, secondDir, keygenAlgorithms[6], dnssecKeygenZone)
	otherPrivateText := string(readScratchFile(t, secondDir, second+".private"))

	notAPair := "Private-key-format: v1.3\n"

	cases := []struct {
		name        string
		keyText     string
		privateText string
		errSubstr   string
		errFile     string
	}{
		{
			name:        "the private key of another key",
			keyText:     keyText,
			privateText: otherPrivateText,
			errSubstr:   "its private key does not match its DNSKEY public key",
			errFile:     "pair",
		},
		{
			name:        "a private scalar of the wrong length",
			keyText:     keyText,
			privateText: replacePrivateKeyScalar(t, privateText, encodeBase64(make([]byte, 36))),
			errSubstr:   "the seed must be 32 octets, got 36",
			errFile:     "pair",
		},
		{
			name:        "private key file without an algorithm",
			keyText:     keyText,
			privateText: notAPair,
			errSubstr:   "no algorithm found in private key file",
			errFile:     "private",
		},
		{
			name:        "private key file with a parameter that is not base64",
			keyText:     keyText,
			privateText: privateText + "Modulus: not base64 at all!!\n",
			errSubstr:   `cannot decode private key parameter "Modulus"`,
			errFile:     "private",
		},
		{
			// A file with only comments and zone directives has no line for the key
			// reader to try.
			name:        "key file with no DNSKEY record",
			keyText:     "; a comment\n$ORIGIN example.com.\n$TTL 3600\n",
			privateText: privateText,
			errSubstr:   "no DNSKEY record found in",
			errFile:     "key",
		},
		{
			// A record line that is not a DNSKEY record is refused by the line parser.
			name:        "key file whose record is not a DNSKEY",
			keyText:     "example.com. 3600 IN A 198.51.100.1\n",
			privateText: privateText,
			errSubstr:   "invalid DNSKEY key line",
			errFile:     "key",
		},
		{
			// The .private file cannot serve as the .key file: its first line is not
			// a record.
			name:        "private key file read as the key file",
			keyText:     privateText,
			privateText: privateText,
			errSubstr:   "invalid DNSKEY key line",
			errFile:     "key",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			baseName := strings.ReplaceAll(tc.name, " ", "-")
			keyFile := writeScratchFile(t, dir, baseName+".key", tc.keyText)
			privateFile := writeScratchFile(t, dir, baseName+".private", tc.privateText)

			key, err := ReadDNSSECKeyFiles(keyFile, privateFile)
			if err == nil {
				t.Fatalf("ReadDNSSECKeyFiles returned the key %s algorithm %d, want an error naming %q",
					key.Name, key.Algorithm, tc.errSubstr)
			}
			if key != nil {
				t.Errorf("ReadDNSSECKeyFiles returned a key with an error: %v", key)
			}
			checkErrContains(t, err, tc.errSubstr)

			// The error names the file the reader could not use, or both files
			// when the pair as a whole is not one key.
			switch tc.errFile {
			case "key":
				checkErrContains(t, err, keyFile)
			case "private":
				checkErrContains(t, err, privateFile)
			case "pair":
				checkErrContains(t, err, keyFile)
				checkErrContains(t, err, privateFile)
			}
		})
	}

	t.Run("empty file names", func(t *testing.T) {
		if _, err := ReadDNSSECKeyFiles("", ""); err == nil {
			t.Error("ReadDNSSECKeyFiles with empty file names returned no error")
		}
	})
}

// TestReadDNSSECKeyFilesAlgorithmMismatch is the case where both files are
// readable key files but do not belong to one key pair: the error names both
// algorithms and both files.
func TestReadDNSSECKeyFilesAlgorithmMismatch(t *testing.T) {
	// A real .key file and the .private file of a key of another algorithm: the
	// two files are not one key, and the error names both algorithms.
	keyDir := keygenTempDir(t)
	ed25519KeyName := generateKeyWithDnssecKeygen(t, keyDir, keygenAlgorithms[6], dnssecKeygenZone)
	keyFile := filepath.Join(keyDir, ed25519KeyName+".key")

	privateDir := keygenTempDir(t)
	ecdsaKeyName := generateKeyWithDnssecKeygen(t, privateDir, keygenAlgorithms[4], dnssecKeygenZone)
	privateFile := filepath.Join(privateDir, ecdsaKeyName+".private")

	key, err := ReadDNSSECKeyFiles(keyFile, privateFile)
	if err == nil {
		t.Fatalf("ReadDNSSECKeyFiles returned the key %s algorithm %d for two files of different algorithms",
			key.Name, key.Algorithm)
	}
	if key != nil {
		t.Errorf("ReadDNSSECKeyFiles returned a key with an error: %v", key)
	}

	for _, want := range []string{
		"algorithm 15 (ED25519)",
		"algorithm 13 (ECDSAP256SHA256)",
		keyFile,
		privateFile,
	} {
		checkErrContains(t, err, want)
	}

	// The same with an algorithm that was not passed to dnssec-keygen: the
	// Algorithm line of a real .private file is changed in the text, which is how
	// a mismatched pair looks when the two files were edited by hand.
	dir := keygenTempDir(t)
	baseName := generateKeyWithDnssecKeygen(t, dir, keygenAlgorithms[6], dnssecKeygenZone)
	otherKeyFile := filepath.Join(dir, baseName+".key")
	otherPrivateFile := writeScratchFile(t, dir, "edited.private",
		replacePrivateAlgorithm(t, string(readScratchFile(t, dir, baseName+".private")), "3 (DSA)"))

	_, err = ReadDNSSECKeyFiles(otherKeyFile, otherPrivateFile)
	if err == nil {
		t.Fatalf("ReadDNSSECKeyFiles accepted %s and a private key file that says algorithm 3", otherKeyFile)
	}
	for _, want := range []string{
		"algorithm 15 (ED25519)",
		"algorithm 3 (DSA)",
		otherKeyFile,
		otherPrivateFile,
	} {
		checkErrContains(t, err, want)
	}
}

// TestReadDNSSECKeyFilesUnsignableAlgorithm loads a pair whose algorithm this
// package cannot sign with, and so is not validated.  The key still describes
// the DNSKEY: its RDATA and key tag are computed, and it is only NewDNSSECSigner
// that declines it.
func TestReadDNSSECKeyFilesUnsignableAlgorithm(t *testing.T) {
	dir := keygenTempDir(t)

	// A DSA key pair: the private material is carried through even though this
	// package cannot build a signer for the algorithm.
	keyText := algorithmNameKeyFileText(t, 3)
	privateText := "Private-key-format: v1.3\nAlgorithm: 3 (DSA)\nPrivateExponent: AwQEBAQE\n"

	keyFile := writeScratchFile(t, dir, "dsa.key", keyText)
	privateFile := writeScratchFile(t, dir, "dsa.private", privateText)

	key, err := ReadDNSSECKeyFiles(keyFile, privateFile)
	if err != nil {
		t.Fatalf("ReadDNSSECKeyFiles with algorithm 3: %v", err)
	}
	if key.Algorithm != 3 {
		t.Errorf("Algorithm = %d, want 3", key.Algorithm)
	}
	if len(key.PrivateKey) == 0 {
		t.Error("PrivateKey is empty: the private exponent of the .private file was not carried through")
	}
	if len(key.PrivateParams) == 0 {
		t.Error("PrivateParams is empty: the parameters of the .private file were not carried through")
	}
	checkKeyPairDNSKEY(t, key)

	if _, err := NewDNSSECSigner(key); err == nil {
		t.Error("NewDNSSECSigner returned a signer for algorithm 3, which this package cannot sign with")
	} else {
		checkErrContains(t, err, "unsupported DNSSEC algorithm 3 for signing")
	}

	// A .private file with no private key material is still a key file, and the
	// pair still describes a DNSKEY; only signing is missing.
	privateText = string(withoutPrivateLine([]byte(privateText), "PrivateExponent"))
	noMaterialPrivateFile := writeScratchFile(t, dir, "dsa-no-material.private", privateText)
	key, err = ReadDNSSECKeyFiles(keyFile, noMaterialPrivateFile)
	if err != nil {
		t.Fatalf("ReadDNSSECKeyFiles with a private key file that has no parameters: %v", err)
	}
	if len(key.PrivateKey) != 0 || len(key.PrivateParams) != 0 {
		t.Errorf("PrivateKey = %x and PrivateParams holds %d parameters, want no private material",
			key.PrivateKey, len(key.PrivateParams))
	}
	checkKeyPairDNSKEY(t, key)

	if _, err := NewDNSSECSigner(key); err == nil {
		t.Error("NewDNSSECSigner returned a signer for a key with no private key material")
	} else {
		checkErrContains(t, err, "has no private key material")
	}
}

// TestReadDNSSECKeyPairWithoutPrivateKeyMaterial loads a pair whose .private file
// declares a supported algorithm but holds no private key material.  There is
// nothing to validate, so the pair loads; the key is a public key that only
// NewDNSSECSigner refuses.
func TestReadDNSSECKeyPairWithoutPrivateKeyMaterial(t *testing.T) {
	dir := keygenTempDir(t)

	keyFile := writeScratchFile(t, dir, "no-material.key", algorithmNameKeyFileText(t, 15))
	privateFile := writeScratchFile(t, dir, "no-material.private", "Private-key-format: v1.3\nAlgorithm: 15 (ED25519)\n")

	key, err := ReadDNSSECKeyFiles(keyFile, privateFile)
	if err != nil {
		t.Fatalf("ReadDNSSECKeyFiles: %v", err)
	}
	if len(key.PrivateKey) != 0 {
		t.Errorf("PrivateKey = %x, want no private key material", key.PrivateKey)
	}
	checkKeyPairDNSKEY(t, key)
	if _, err := NewDNSSECSigner(key); err == nil {
		t.Error("NewDNSSECSigner returned a signer for a key with no private key material")
	} else {
		checkErrContains(t, err, "has no private key material")
	}
}

// TestReadPrivateKeyFilePrivateNameLine checks that ReadPrivateKeyFile on its own
// keeps rejecting a .private file that carries a Name line: dnssec-keygen does
// not write one, and the pair reader is the only place that tolerates it.
func TestReadPrivateKeyFilePrivateNameLine(t *testing.T) {
	dir := keygenTempDir(t)

	base := "Private-key-format: v1.3\nAlgorithm: 15 (ED25519)\nPrivateKey: bm90IGEgcHJpdmF0ZSBrZXkgYnV0IGl0IGxvb2tzIGxpa2Ugb25lCg==\n"
	withName := "Name: example.com.\n" + base

	privateFile := writeScratchFile(t, dir, "with-name.private", withName)
	key, err := ReadPrivateKeyFile(privateFile)
	if err == nil {
		t.Fatalf("ReadPrivateKeyFile accepted a Name line and returned the key %s algorithm %d: %v",
			key.Name, key.Algorithm, key)
	}
	if key != nil {
		t.Errorf("ReadPrivateKeyFile returned a key with an error: %v", key)
	}
	checkErrContains(t, err, `cannot decode private key parameter "Name"`)

	// The same file without the Name line is a private key file.
	plain := writeScratchFile(t, dir, "without-name.private", base)
	if _, err := ReadPrivateKeyFile(plain); err != nil {
		t.Fatalf("ReadPrivateKeyFile(%s): %v", plain, err)
	}
}

// TestReadDNSSECKeyPairPrivateNameLine covers a pair whose .private file carries
// a Name line: the pair reader ignores the line and takes the owner name from
// the .key file.
func TestReadDNSSECKeyPairPrivateNameLine(t *testing.T) {
	if !dnssecKeygenAvailable(t) {
		return
	}

	dir := keygenTempDir(t)
	base := generateKeyWithDnssecKeygen(t, dir, keygenAlgorithms[6], dnssecKeygenZone)

	plain, err := ReadDNSSECKeyPair(filepath.Join(dir, base))
	if err != nil {
		t.Fatalf("ReadDNSSECKeyPair(%s): %v", base, err)
	}

	// Every spelling and every value of the field is dropped the same way: the
	// line is not read, so nothing it could say is checked.  The same pair is
	// read every time, with only the .private file edited, so that a key that
	// differs from the one read above would be the edited line being used.
	data := string(readScratchFile(t, dir, base+".private"))

	cases := []struct {
		name string
		line string
	}{
		{
			name: "the name of another zone",
			line: "Name: other.example.org.",
		},
		{
			name: "the owner name of the key",
			line: "Name: " + dnssecKeygenZone,
		},
		{
			name: "the same field in another spelling",
			line: "name: example.org.",
		},
		{
			name: "a value that is not a domain name",
			line: "Name: example.com",
		},
		{
			name: "no value at all",
			line: "Name:",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			edited := insertPrivateFileLine(t, data, "Private-key-format", tc.line)
			privateFile := writeScratchFile(t, dir, base+".private", edited)

			key, err := ReadDNSSECKeyPair(filepath.Join(dir, base))
			if err != nil {
				t.Fatalf("ReadDNSSECKeyPair with the line %q in %s: %v", tc.line, privateFile, err)
			}
			if !key.Name.Equal(plain.Name) {
				t.Errorf("Name = %s, want the .key file owner name %s", key.Name, plain.Name)
			}
			if key.Algorithm != plain.Algorithm || !bytes.Equal(key.PublicKey, plain.PublicKey) ||
				!bytes.Equal(key.PrivateKey, plain.PrivateKey) {
				t.Errorf("the key read from a .private file with a Name line differs from the key without one: "+
					"algorithm %d public key %x private key %x, want algorithm %d public key %x private key %x",
					key.Algorithm, key.PublicKey, key.PrivateKey, plain.Algorithm, plain.PublicKey, plain.PrivateKey)
			}
			if _, ok := key.PrivateParams["Name"]; ok {
				t.Errorf("PrivateParams carries the parameter %q of the Name line", tc.line)
			}
			keyTagOf(t, key, keyTagFromKeyBaseName(t, base))
		})
	}
}

// TestReadDNSSECKeyFilesDistinctBaseNames checks that two files whose base names
// do not match are not treated as one pair, and that the pair of matching base
// names still loads beside them.
func TestReadDNSSECKeyFilesDistinctBaseNames(t *testing.T) {
	if !dnssecKeygenAvailable(t) {
		return
	}

	dir := keygenTempDir(t)
	first := generateKeyWithDnssecKeygen(t, dir, keygenAlgorithms[6], dnssecKeygenZone)
	second := generateKeyWithDnssecKeygen(t, dir, keygenAlgorithms[5], "other.example.org")

	if _, err := ReadDNSSECKeyPair(filepath.Join(dir, first)); err != nil {
		t.Fatalf("ReadDNSSECKeyPair(%s): %v", first, err)
	}
	if _, err := ReadDNSSECKeyPair(filepath.Join(dir, second)); err != nil {
		t.Fatalf("ReadDNSSECKeyPair(%s): %v", second, err)
	}

	// The .key file of one key and the .private file of the other are not a pair:
	// the algorithms differ, so the pair is refused.
	key, err := ReadDNSSECKeyFiles(filepath.Join(dir, first+".key"), filepath.Join(dir, second+".private"))
	if err == nil {
		t.Fatalf("ReadDNSSECKeyFiles merged the .key file of %s with the .private file of %s: algorithm %d",
			first, second, key.Algorithm)
	}
	// keygenAlgorithms[6] is Ed25519 and keygenAlgorithms[5] is
	// ECDSAP384SHA384, which are the two keys generated above.
	for _, want := range []string{"algorithm 15 (ED25519)", "algorithm 14 (ECDSAP384SHA384)"} {
		checkErrContains(t, err, want)
	}
}

// TestReadDNSSECKeyPairDoesNotChangeTheFiles checks that loading a pair leaves
// the files it read exactly as they were, in particular that the tolerated Name
// line is not written out of the .private file.
func TestReadDNSSECKeyPairDoesNotChangeTheFiles(t *testing.T) {
	if !dnssecKeygenAvailable(t) {
		return
	}

	dir := keygenTempDir(t)
	base := generateKeyWithDnssecKeygen(t, dir, keygenAlgorithms[6], dnssecKeygenZone)

	before := directoryContents(t, dir)
	if _, err := ReadDNSSECKeyPair(filepath.Join(dir, base)); err != nil {
		t.Fatalf("ReadDNSSECKeyPair(%s): %v", base, err)
	}
	if after := directoryContents(t, dir); after != before {
		t.Errorf("the directory changed while the pair was read:\nbefore %safter %s", before, after)
	}

	// A .private file with a Name line keeps it.
	data := readScratchFile(t, dir, base+".private")
	writeScratchFile(t, dir, base+".private", insertPrivateFileLine(t, string(data), "Created", "Name: example.com."))
	before = directoryContents(t, dir)
	if _, err := ReadDNSSECKeyPair(filepath.Join(dir, base)); err != nil {
		t.Fatalf("ReadDNSSECKeyPair with a Name line: %v", err)
	}
	after := directoryContents(t, dir)
	if after != before {
		t.Errorf("the directory changed while the pair was read:\nbefore %safter %s", before, after)
	}
	if !strings.Contains(after, "Name: example.com.") {
		t.Errorf("the Name line is no longer in the .private file:%s", after)
	}
}

// directoryContents returns the contents of the regular files of dir as one
// string, so that a test can compare a directory before and after a call.
func directoryContents(t *testing.T, dir string) string {
	t.Helper()

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("cannot read the directory %s: %v", dir, err)
	}
	var out strings.Builder
	for _, entry := range entries {
		if !entry.Type().IsRegular() {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			t.Fatalf("cannot read %s: %v", entry.Name(), err)
		}
		out.WriteString(entry.Name())
		out.WriteString(" ")
		out.WriteString(strings.ReplaceAll(string(data), "\n", "\\n"))
		out.WriteString("\n")
	}
	return out.String()
}

// algorithmNameKeyFileText returns the contents of a .key file holding a DNSKEY
// of the given algorithm and fixed key material, for a test that needs to choose
// the algorithm of a pair.  The line is the shape dnssec-keygen writes: owner
// name, IN, DNSKEY and the RDATA, with no TTL, and the RDATA is the one this
// package's own DNSKEY serializer produces.
func algorithmNameKeyFileText(t *testing.T, algorithm uint8) string {
	t.Helper()

	dnskey := NewRecordDNSKEY(256, 3, algorithm, []byte{1, 2, 3, 4, 5})
	return "example.com. IN DNSKEY " + dnskey.String() + "\n"
}

// withoutPrivateLine returns the contents of a .private file with the lines
// starting with prefix removed.
func withoutPrivateLine(data []byte, prefix string) []byte {
	kept := make([]string, 0, len(data))
	for _, raw := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(strings.TrimSpace(raw), prefix) {
			continue
		}
		kept = append(kept, raw)
	}
	return []byte(strings.Join(kept, "\n"))
}

// insertPrivateFileLine returns the contents of a .private file with line
// inserted after the first line that starts with after.
func insertPrivateFileLine(t *testing.T, content, after, line string) string {
	t.Helper()

	lines := strings.Split(content, "\n")
	for i, l := range lines {
		if strings.HasPrefix(strings.TrimSpace(l), after) {
			out := make([]string, 0, len(lines)+1)
			out = append(out, lines[:i+1]...)
			out = append(out, line)
			out = append(out, lines[i+1:]...)
			return strings.Join(out, "\n")
		}
	}
	t.Fatalf("the private key file has no line starting with %q:\n%s", after, content)
	return content
}

func checkErrContains(t *testing.T, err error, want string) {
	t.Helper()

	if !strings.Contains(err.Error(), want) {
		t.Errorf("error %q does not contain %q", err.Error(), want)
	}
}
