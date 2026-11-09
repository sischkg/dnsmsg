package dnsmsg

import (
	"bytes"
	"fmt"
	"sort"
	"strings"
	"testing"
)

// These tests exercise MergeDNSSECKey, the public form of the merge
// ReadDNSSECKeyFiles uses for a key pair.  The keys are built in memory from
// generated key material, so no external tool is needed, and one test replays
// the merge over real dnssec-keygen output and compares it with the pair
// reader's result.

// mergeTestKeyPair returns the two arguments of a merge for one algorithm: a
// public half shaped like a .key file and a private half shaped like a
// .private file of the same key pair, plus the DNSKEY public key material of
// that key.  The two halves are built as separate values, so they share no
// storage with each other and a test can tell which half a merged field came
// from.
func mergeTestKeyPair(t *testing.T, algorithm uint8) (public, private *DNSSECKey, material []byte) {
	t.Helper()

	testKey := newVerifyTestKey(t, algorithm)
	material = dnskeyMaterialFromPublicKey(t, testKey.pubkey)
	params := dnssecPrivateKeyParams(t, testKey.signer)

	public = &DNSSECKey{
		Name:      testDomainName(t, dnssecKeygenZone+"."),
		Flags:     257,
		Protocol:  3,
		Algorithm: algorithm,
		PublicKey: append([]byte(nil), material...),
	}
	private = &DNSSECKey{
		Name:          testDomainName(t, dnssecKeygenZone+"."),
		Flags:         256,
		Protocol:      2,
		Algorithm:     algorithm,
		PrivateKey:    dnssecPrivateScalarFromParams(params),
		PrivateParams: clonePrivateParams(params),
	}
	return public, private, material
}

// dnssecPrivateScalarFromParams returns the private scalar or exponent a
// parameter map carries, the way ReadPrivateKeyFile mirrors it into
// DNSSECKey.PrivateKey.
func dnssecPrivateScalarFromParams(params map[string][]byte) []byte {
	for _, name := range []string{"PrivateKey", "PrivateExponent"} {
		for stored, value := range params {
			if strings.EqualFold(stored, name) {
				return append([]byte(nil), value...)
			}
		}
	}
	return nil
}

// describeDNSSECKey renders every field of a key, including whether a byte
// container is nil or empty, so that a test can compare a key with a snapshot
// of it taken before another value was modified.
func describeDNSSECKey(key *DNSSECKey) string {
	if key == nil {
		return "<nil>"
	}

	parts := []string{
		fmt.Sprintf("name=%s", key.Name),
		fmt.Sprintf("flags=%d", key.Flags),
		fmt.Sprintf("protocol=%d", key.Protocol),
		fmt.Sprintf("algorithm=%d", key.Algorithm),
		describeDNSSECKeyOctets("publickey", key.PublicKey),
		describeDNSSECKeyOctets("privatekey", key.PrivateKey),
	}

	names := make([]string, 0, len(key.PrivateParams))
	for name := range key.PrivateParams {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		parts = append(parts, fmt.Sprintf("param %s=%s", name, describeDNSSECKeyOctets("", key.PrivateParams[name])))
	}
	return strings.Join(parts, " ")
}

func describeDNSSECKeyOctets(field string, octets []byte) string {
	label := field
	if label != "" {
		label += " "
	}
	if octets == nil {
		return label + "<nil>"
	}
	if len(octets) == 0 {
		return label + "<empty>"
	}
	return fmt.Sprintf("%s%x", label, octets)
}

// mutateDNSSECKey changes every field of a key in place, including one byte of
// every octet string it holds and every label of its name, so that a shared
// backing array would show up in the value the key was built from.
func mutateDNSSECKey(key *DNSSECKey) {
	key.Flags ^= 1
	key.Protocol++
	key.Algorithm++
	flipDNSSECKeyOctets(key.PublicKey)
	flipDNSSECKeyOctets(key.PrivateKey)
	for _, value := range key.PrivateParams {
		flipDNSSECKeyOctets(value)
	}
	if key.PrivateParams != nil {
		key.PrivateParams["Mutated-By-Test"] = []byte{9}
	}
	for _, label := range key.Name.labels {
		flipDNSSECKeyOctets(label.data)
	}
}

func flipDNSSECKeyOctets(octets []byte) {
	if len(octets) > 0 {
		octets[0] ^= 0x01
	}
}

// dnssecKeyNamesEqual compares two names label by label, which is what a
// cloned name must match: the clone keeps every label byte as it is, so a
// comparison that folds case would hide a changed label.
func dnssecKeyNamesEqual(got, want DomainName) bool {
	if len(got.labels) != len(want.labels) {
		return false
	}
	for i := range want.labels {
		if !bytes.Equal(got.labels[i].data, want.labels[i].data) {
			return false
		}
	}
	return true
}

// checkMergedKeyArguments reports the merged key against the two arguments it
// was built from: the shared and public fields must be the public half's, the
// private material must be the private half's.
func checkMergedKeyArguments(t *testing.T, merged, public, private *DNSSECKey) {
	t.Helper()

	if !dnssecKeyNamesEqual(merged.Name, public.Name) {
		t.Errorf("Name = %s, want the public key's name %s", merged.Name, public.Name)
	}
	if merged.Flags != public.Flags {
		t.Errorf("Flags = %d, want the public key's flags %d", merged.Flags, public.Flags)
	}
	if merged.Protocol != public.Protocol {
		t.Errorf("Protocol = %d, want the public key's protocol %d", merged.Protocol, public.Protocol)
	}
	if merged.Algorithm != public.Algorithm {
		t.Errorf("Algorithm = %d, want the algorithm %d both keys name", merged.Algorithm, public.Algorithm)
	}
	if !bytes.Equal(merged.PublicKey, public.PublicKey) {
		t.Errorf("PublicKey = %x, want the public key's public key %x", merged.PublicKey, public.PublicKey)
	}
	if !bytes.Equal(merged.PrivateKey, private.PrivateKey) {
		t.Errorf("PrivateKey = %x, want the private key's private material %x", merged.PrivateKey, private.PrivateKey)
	}
	if !dnssecPrivateParamMapsEqual(merged.PrivateParams, private.PrivateParams) {
		t.Errorf("PrivateParams = %s, want the private key's parameters %s",
			describeDNSSECKey(&DNSSECKey{PrivateParams: merged.PrivateParams}),
			describeDNSSECKey(&DNSSECKey{PrivateParams: private.PrivateParams}))
	}
}

func dnssecPrivateParamMapsEqual(got, want map[string][]byte) bool {
	if len(got) != len(want) {
		return false
	}
	for name, value := range want {
		found, ok := got[name]
		if !ok || !bytes.Equal(found, value) {
			return false
		}
	}
	return true
}

// checkMergedKeyAsDNSKEY checks the merged key through the two DNSKEY helpers
// a caller uses it for: ToDNSKEY() describes the public half, and KeyTag() is
// that record's key tag.
func checkMergedKeyAsDNSKEY(t *testing.T, merged, public *DNSSECKey) {
	t.Helper()

	want := NewRecordDNSKEY(public.Flags, public.Protocol, public.Algorithm, public.PublicKey)
	got := merged.ToDNSKEY()
	if got.Flags != want.Flags {
		t.Errorf("ToDNSKEY().Flags = %d, want %d", got.Flags, want.Flags)
	}
	if got.Protocol != want.Protocol {
		t.Errorf("ToDNSKEY().Protocol = %d, want %d", got.Protocol, want.Protocol)
	}
	if got.Algorithm != want.Algorithm {
		t.Errorf("ToDNSKEY().Algorithm = %d, want %d", got.Algorithm, want.Algorithm)
	}
	if !bytes.Equal(got.PublicKey, want.PublicKey) {
		t.Errorf("ToDNSKEY().PublicKey = %x, want %x", got.PublicKey, want.PublicKey)
	}
	if !bytes.Equal(got.CanonicalWireFormat(), want.CanonicalWireFormat()) {
		t.Errorf("ToDNSKEY().CanonicalWireFormat() = %x, want %x", got.CanonicalWireFormat(), want.CanonicalWireFormat())
	}

	keyTag, err := merged.KeyTag()
	if err != nil {
		t.Fatalf("KeyTag() error = %v", err)
	}
	if keyTag != want.KeyTag() {
		t.Errorf("KeyTag() = %d, want the key tag of the public key, %d", keyTag, want.KeyTag())
	}
}

func TestMergeDNSSECKey(t *testing.T) {
	for _, algorithm := range SupportedDNSSECAlgorithms() {
		t.Run(algorithmName(algorithm), func(t *testing.T) {
			public, private, material := mergeTestKeyPair(t, algorithm)

			merged, err := MergeDNSSECKey(public, private)
			if err != nil {
				t.Fatalf("MergeDNSSECKey() error = %v", err)
			}
			if merged == nil {
				t.Fatalf("MergeDNSSECKey() returned nil, want a merged key")
			}

			checkMergedKeyArguments(t, merged, public, private)
			checkMergedKeyAsDNSKEY(t, merged, public)

			// The merged key is the value a caller signs with.
			signer, err := NewDNSSECSigner(merged)
			if err != nil {
				t.Fatalf("NewDNSSECSigner() error = %v", err)
			}
			signAndVerifyRRSet(t, merged, signer, material)
		})
	}
}

// TestMergeDNSSECKeyTakesSharedFieldsFromThePublicKey checks the documented
// field ownership when the two halves disagree: the merged key follows the
// public key for the name and the DNSKEY fields, follows the private key for
// the private material, and ignores private material carried by the public
// half.
func TestMergeDNSSECKeyTakesSharedFieldsFromThePublicKey(t *testing.T) {
	const algorithm = uint8(15)

	public, private, _ := mergeTestKeyPair(t, algorithm)

	// The public half disagrees with the private half about every field the
	// merge takes from it.
	public.Name = testDomainName(t, dnssecKeygenZone+".")
	public.Flags = 257
	public.Protocol = 3

	private.Name = testDomainName(t, "private.example.org.")
	private.Flags = 256
	private.Protocol = 4

	// The public half carries the private material of a different key, which
	// the merge must not use.
	otherPublic, otherPrivate, _ := mergeTestKeyPair(t, algorithm)
	public.PrivateKey = otherPrivate.PrivateKey
	public.PrivateParams = clonePrivateParams(otherPrivate.PrivateParams)

	merged, err := MergeDNSSECKey(public, private)
	if err != nil {
		t.Fatalf("MergeDNSSECKey() error = %v", err)
	}

	checkMergedKeyArguments(t, merged, public, private)
	if !dnssecKeyNamesEqual(merged.Name, public.Name) || dnssecKeyNamesEqual(merged.Name, private.Name) {
		t.Errorf("Name = %s, want the public key's name %s and not the private key's name %s",
			merged.Name, public.Name, private.Name)
	}
	if merged.PrivateKey == nil || !bytes.Equal(merged.PrivateKey, private.PrivateKey) {
		t.Errorf("PrivateKey = %x, want the private key's scalar %x, not the public key's %x",
			merged.PrivateKey, private.PrivateKey, public.PrivateKey)
	}

	// The merged key signs and verifies, so the private material it kept is
	// the one that belongs to the public key it kept.
	signer, err := NewDNSSECSigner(merged)
	if err != nil {
		t.Fatalf("NewDNSSECSigner() error = %v", err)
	}
	signAndVerifyRRSet(t, merged, signer, merged.PublicKey)

	_ = otherPublic
}

// TestMergeDNSSECKeyDoesNotShareStateWithItsArguments checks that the merge is
// non-destructive: the result is a new key, the arguments keep their own
// values, and no field of the result is a view onto a field of an argument.
func TestMergeDNSSECKeyDoesNotShareStateWithItsArguments(t *testing.T) {
	for _, algorithm := range SupportedDNSSECAlgorithms() {
		t.Run(algorithmName(algorithm), func(t *testing.T) {
			public, private, _ := mergeTestKeyPair(t, algorithm)
			beforePublic := describeDNSSECKey(public)
			beforePrivate := describeDNSSECKey(private)

			merged, err := MergeDNSSECKey(public, private)
			if err != nil {
				t.Fatalf("MergeDNSSECKey() error = %v", err)
			}
			if merged == public || merged == private {
				t.Fatalf("MergeDNSSECKey() returned one of its arguments (%p), want a new key", merged)
			}
			beforeMerged := describeDNSSECKey(merged)

			mutateDNSSECKey(merged)

			if after := describeDNSSECKey(public); after != beforePublic {
				t.Errorf("the public key changed when the merged key was modified:\nhave %s\nwant %s", after, beforePublic)
			}
			if after := describeDNSSECKey(private); after != beforePrivate {
				t.Errorf("the private key changed when the merged key was modified:\nhave %s\nwant %s", after, beforePrivate)
			}

			// Merging the same pair again produces the key the first merge
			// produced, which is what the arguments still describe.
			again, err := MergeDNSSECKey(public, private)
			if err != nil {
				t.Fatalf("MergeDNSSECKey() second call error = %v", err)
			}
			if after := describeDNSSECKey(again); after != beforeMerged {
				t.Errorf("a second MergeDNSSECKey() over the same arguments differs:\nhave %s\nwant %s", after, beforeMerged)
			}
		})
	}
}

func TestMergeDNSSECKeyErrors(t *testing.T) {
	const (
		signable = uint8(13)
		other    = uint8(15)
	)

	cases := []struct {
		name  string
		build func(t *testing.T, public, private *DNSSECKey) (*DNSSECKey, *DNSSECKey)
		want  []string
		not   []string
	}{
		{
			name:  "nil public key",
			build: func(t *testing.T, public, private *DNSSECKey) (*DNSSECKey, *DNSSECKey) { return nil, private },
			want:  []string{"the public key is nil"},
		},
		{
			name:  "nil private key",
			build: func(t *testing.T, public, private *DNSSECKey) (*DNSSECKey, *DNSSECKey) { return public, nil },
			want:  []string{"the private key is nil"},
		},
		{
			name: "public key without public key material",
			build: func(t *testing.T, public, private *DNSSECKey) (*DNSSECKey, *DNSSECKey) {
				public.PublicKey = nil
				return public, private
			},
			want: []string{"the public key carries no DNSKEY public key material", ".private file"},
		},
		{
			name: "public key with empty public key material",
			build: func(t *testing.T, public, private *DNSSECKey) (*DNSSECKey, *DNSSECKey) {
				public.PublicKey = []byte{}
				return public, private
			},
			want: []string{"the public key carries no DNSKEY public key material"},
		},
		{
			name: "private key without private material",
			build: func(t *testing.T, public, private *DNSSECKey) (*DNSSECKey, *DNSSECKey) {
				private.PrivateKey = nil
				private.PrivateParams = nil
				return public, private
			},
			want: []string{"the private key carries no private key material", ".key file"},
		},
		{
			name: "private key with an empty parameter map",
			build: func(t *testing.T, public, private *DNSSECKey) (*DNSSECKey, *DNSSECKey) {
				private.PrivateKey = nil
				private.PrivateParams = map[string][]byte{}
				return public, private
			},
			want: []string{"the private key carries no private key material"},
		},
		{
			name: "public key names no algorithm",
			build: func(t *testing.T, public, private *DNSSECKey) (*DNSSECKey, *DNSSECKey) {
				public.Algorithm = 0
				return public, private
			},
			want: []string{"the public key names no algorithm"},
		},
		{
			name: "private key names no algorithm",
			build: func(t *testing.T, public, private *DNSSECKey) (*DNSSECKey, *DNSSECKey) {
				private.Algorithm = 0
				return public, private
			},
			want: []string{"the private key names no algorithm"},
		},
		{
			name: "neither key names an algorithm",
			build: func(t *testing.T, public, private *DNSSECKey) (*DNSSECKey, *DNSSECKey) {
				public.Algorithm = 0
				private.Algorithm = 0
				return public, private
			},
			want: []string{"the public key names no algorithm"},
		},
		{
			name: "the private key names another algorithm",
			build: func(t *testing.T, public, private *DNSSECKey) (*DNSSECKey, *DNSSECKey) {
				private.Algorithm = other
				return public, private
			},
			want: []string{
				"the algorithms do not match",
				fmt.Sprintf("the public key uses algorithm %d (%s)", signable, DNSSECAlgorithm(signable)),
				fmt.Sprintf("the private key uses algorithm %d (%s)", other, DNSSECAlgorithm(other)),
			},
		},
		{
			name: "the public key names another algorithm",
			build: func(t *testing.T, public, private *DNSSECKey) (*DNSSECKey, *DNSSECKey) {
				public.Algorithm = other
				return public, private
			},
			want: []string{
				"the algorithms do not match",
				fmt.Sprintf("the public key uses algorithm %d (%s)", other, DNSSECAlgorithm(other)),
				fmt.Sprintf("the private key uses algorithm %d (%s)", signable, DNSSECAlgorithm(signable)),
			},
		},
		{
			name: "the private key belongs to another public key",
			build: func(t *testing.T, public, private *DNSSECKey) (*DNSSECKey, *DNSSECKey) {
				_, otherPrivate, _ := mergeTestKeyPair(t, signable)
				return public, otherPrivate
			},
			want: []string{"its private key does not match its DNSKEY public key"},
			not:  []string{"cannot merge DNSSEC key"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			public, private, _ := mergeTestKeyPair(t, signable)
			argsPublic, argsPrivate := tc.build(t, public, private)

			merged, err := MergeDNSSECKey(argsPublic, argsPrivate)
			if err == nil {
				t.Fatalf("MergeDNSSECKey() error = nil, want an error; merged key = %s", describeDNSSECKey(merged))
			}
			if merged != nil {
				t.Errorf("MergeDNSSECKey() returned a key with an error: %s", describeDNSSECKey(merged))
			}
			for _, want := range tc.want {
				checkErrContains(t, err, want)
			}
			for _, not := range tc.not {
				if errorContains(err, not) {
					t.Errorf("MergeDNSSECKey() error = %v, must not mention %q", err, not)
				}
			}
		})
	}
}

// TestMergeDNSSECKeyPrivateMaterialWithoutParameters merges keys whose private
// half carries its material as octets in DNSSECKey.PrivateKey and no parameter
// map, which is the shape a caller builds from raw key material rather than
// from a .private file.  That shape describes the private scalar of an ECDSA or
// Ed25519 key, so those merges produce a key that signs.  An RSA key is a set
// of numbers and not one octet string, so the same shape is rejected with the
// error NewDNSSECSigner gives for it: the merge does not reinterpret private key
// material, and so does not rename that error either.
func TestMergeDNSSECKeyPrivateMaterialWithoutParameters(t *testing.T) {
	for _, algorithm := range SupportedDNSSECAlgorithms() {
		t.Run(algorithmName(algorithm), func(t *testing.T) {
			public, private, material := mergeTestKeyPair(t, algorithm)
			private.PrivateParams = nil

			beforePublic, beforePrivate := describeDNSSECKey(public), describeDNSSECKey(private)
			merged, err := MergeDNSSECKey(public, private)
			if beforePublic != describeDNSSECKey(public) {
				t.Errorf("the public key changed from %s to %s", beforePublic, describeDNSSECKey(public))
			}
			if beforePrivate != describeDNSSECKey(private) {
				t.Errorf("the private key changed from %s to %s", beforePrivate, describeDNSSECKey(private))
			}

			if isDNSSECRSAAlgorithm(algorithm) {
				if err == nil {
					t.Fatalf("MergeDNSSECKey() error = nil, want an error; merged key = %s", describeDNSSECKey(merged))
				}
				if merged != nil {
					t.Errorf("MergeDNSSECKey() returned a key with an error: %s", describeDNSSECKey(merged))
				}
				// The private exponent is the only RSA number that is a fixed
				// octet string, so dnssecPrivateKeyParam answers the modulus and
				// public exponent lookups with it too, and the exponent that
				// results is the full private exponent: far larger than the
				// 2^31-1 range a public exponent must be in.
				checkErrContains(t, err, "invalid RSA public exponent")
				if errorContains(err, "cannot merge DNSSEC key") {
					t.Errorf("MergeDNSSECKey() error = %v, must not mention %q", err, "cannot merge DNSSEC key")
				}
				return
			}

			if err != nil {
				t.Fatalf("MergeDNSSECKey() error = %v", err)
			}
			checkMergedKeyArguments(t, merged, public, private)
			checkMergedKeyAsDNSKEY(t, merged, public)

			signer, err := NewDNSSECSigner(merged)
			if err != nil {
				t.Fatalf("NewDNSSECSigner() error = %v", err)
			}
			signAndVerifyRRSet(t, merged, signer, material)
		})
	}
}

// TestMergeDNSSECKeyUnsignableAlgorithm checks the merge of a pair this package
// cannot sign with: the merged key keeps its public half, so KeyTag() and
// ToDNSKEY() work, and only NewDNSSECSigner reports the algorithm.
func TestMergeDNSSECKeyUnsignableAlgorithm(t *testing.T) {
	const algorithm = uint8(16)

	public := &DNSSECKey{
		Name:      testDomainName(t, dnssecKeygenZone+"."),
		Flags:     257,
		Protocol:  3,
		Algorithm: algorithm,
		PublicKey: bytes.Repeat([]byte{0xa5}, 57),
	}
	private := &DNSSECKey{
		Name:          testDomainName(t, dnssecKeygenZone+"."),
		Flags:         256,
		Protocol:      3,
		Algorithm:     algorithm,
		PrivateKey:    bytes.Repeat([]byte{0x11}, 57),
		PrivateParams: map[string][]byte{"PrivateKey": bytes.Repeat([]byte{0x11}, 57)},
	}

	merged, err := MergeDNSSECKey(public, private)
	if err != nil {
		t.Fatalf("MergeDNSSECKey() error = %v", err)
	}
	checkMergedKeyArguments(t, merged, public, private)
	checkMergedKeyAsDNSKEY(t, merged, public)

	if _, err := NewDNSSECSigner(merged); err == nil {
		t.Errorf("NewDNSSECSigner() error = nil, want an error naming algorithm %d", algorithm)
	} else {
		checkErrContains(t, err, fmt.Sprintf("unsupported DNSSEC algorithm %d for signing", algorithm))
	}
}

// TestMergeDNSSECKeyFromDnssecKeygenFiles merges keys read from real
// dnssec-keygen output and compares the result with what ReadDNSSECKeyFiles
// builds for the same pair, which is the same merge through the file readers.
func TestMergeDNSSECKeyFromDnssecKeygenFiles(t *testing.T) {
	if !dnssecKeygenAvailable(t) {
		return
	}

	// A representative subset: one RSA algorithm, both ECDSA algorithms, the
	// two EdDSA algorithms.  The other algorithms are covered by the in-memory
	// tests, and every dnssec-keygen run is slow enough to keep this list short.
	for _, kg := range []keygenAlgorithm{
		{name: "RSASHA256", bits: 2048, algo: 8, sign: true},
		{name: "ECDSAP256SHA256", bits: 256, algo: 13, sign: true},
		{name: "Ed25519", bits: 0, algo: 15, sign: true},
		{name: "Ed448", bits: 0, algo: 16, sign: false},
	} {
		t.Run(algorithmName(kg.algo), func(t *testing.T) {
			dir := keygenTempDir(t)
			baseName := generateKeyWithDnssecKeygen(t, dir, kg, dnssecKeygenZone)

			public, err := ReadKeyFile(dir + "/" + baseName + ".key")
			if err != nil {
				t.Fatalf("ReadKeyFile() error = %v", err)
			}
			private, err := ReadPrivateKeyFile(dir + "/" + baseName + ".private")
			if err != nil {
				t.Fatalf("ReadPrivateKeyFile() error = %v", err)
			}

			merged, err := MergeDNSSECKey(public, private)
			if err != nil {
				t.Fatalf("MergeDNSSECKey() error = %v", err)
			}
			checkMergedKeyArguments(t, merged, public, private)
			checkMergedKeyAsDNSKEY(t, merged, public)

			// The same pair through the pair reader: same fields, same tag.
			fromFiles, err := ReadDNSSECKeyFiles(
				dir+"/"+baseName+".key",
				dir+"/"+baseName+".private",
			)
			if err != nil {
				t.Fatalf("ReadDNSSECKeyFiles() error = %v", err)
			}
			if got, want := describeDNSSECKey(merged), describeDNSSECKey(fromFiles); got != want {
				t.Errorf("MergeDNSSECKey() and ReadDNSSECKeyFiles() differ on the same pair:\nmerge  %s\npair   %s", got, want)
			}
			keyTagOf(t, merged, keyTagFromKeyBaseName(t, baseName))

			if !kg.sign {
				if _, err := NewDNSSECSigner(merged); err == nil {
					t.Errorf("NewDNSSECSigner() error = nil, want an error naming algorithm %d", kg.algo)
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
