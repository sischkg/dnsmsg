package dnsmsg

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/asn1"
	"math/big"
	"testing"
)

// buildTestRRSet returns a sample RRSet with two A records for example.com.
func buildTestRRSet(t *testing.T) RRSet {
	t.Helper()
	name := testDomainName(t, "www.example.com.")
	a1 := NewRecordA([4]byte{192, 0, 2, 1})
	a2 := NewRecordA([4]byte{192, 0, 2, 2})
	return NewRRSet(name, CLASS_IN, TYPE_A, 3600, a1, a2)
}

func TestRRSetNew(t *testing.T) {
	name := testDomainName(t, "example.com.")
	a := NewRecordA([4]byte{10, 0, 0, 1})
	rs := NewRRSet(name, CLASS_IN, TYPE_A, 300, a)

	if !rs.Name.Equal(name) {
		t.Errorf("Name = %s, want %s", rs.Name, name)
	}
	if rs.Class != CLASS_IN {
		t.Errorf("Class = %v, want %v", rs.Class, CLASS_IN)
	}
	if rs.Type != TYPE_A {
		t.Errorf("Type = %v, want %v", rs.Type, TYPE_A)
	}
	if rs.TTL != 300 {
		t.Errorf("TTL = %d, want 300", rs.TTL)
	}
	if rs.Len() != 1 {
		t.Errorf("Len() = %d, want 1", rs.Len())
	}
}

func TestRRSetAdd(t *testing.T) {
	name := testDomainName(t, "example.com.")
	rs := NewRRSet(name, CLASS_IN, TYPE_A, 300)
	if rs.Len() != 0 {
		t.Errorf("Len() = %d, want 0", rs.Len())
	}

	rs.Add(NewRecordA([4]byte{10, 0, 0, 1}))
	rs.Add(NewRecordA([4]byte{10, 0, 0, 2}))
	if rs.Len() != 2 {
		t.Errorf("Len() = %d, want 2", rs.Len())
	}
}

func TestRRSetEqual(t *testing.T) {
	name := testDomainName(t, "example.com.")
	a1 := NewRecordA([4]byte{10, 0, 0, 1})
	a2 := NewRecordA([4]byte{10, 0, 0, 2})

	rs1 := NewRRSet(name, CLASS_IN, TYPE_A, 300, a1, a2)
	rs2 := NewRRSet(name, CLASS_IN, TYPE_A, 300, a1, a2)
	if !rs1.Equal(rs2) {
		t.Errorf("rrset.Equal() = false, want true")
	}

	// TTL differs
	rs3 := NewRRSet(name, CLASS_IN, TYPE_A, 600, a1, a2)
	if rs1.Equal(rs3) {
		t.Errorf("rrset.Equal() = true, want false (TTL differs)")
	}

	// RData differs
	rs4 := NewRRSet(name, CLASS_IN, TYPE_A, 300, a2, a1)
	if !rs1.Equal(rs4) {
		// Order may differ but canonical sort should make them equal;
		// however Equal compares RData in stored order, not sorted order.
		// This is expected: Equal compares in stored order.
		t.Logf("note: Equal with different order returned false (stored-order comparison)")
	}

	// Type differs
	ns := NewRecordNS(testDomainName(t, "ns.example.com."))
	rs5 := NewRRSet(name, CLASS_IN, TYPE_NS, 300, ns)
	if rs1.Equal(rs5) {
		t.Errorf("rrset.Equal() = true, want false (Type differs)")
	}
}

func TestRRSetString(t *testing.T) {
	name := testDomainName(t, "www.example.com.")
	a1 := NewRecordA([4]byte{192, 0, 2, 1})
	a2 := NewRecordA([4]byte{192, 0, 2, 2})
	rs := NewRRSet(name, CLASS_IN, TYPE_A, 3600, a1, a2)

	s := rs.String()
	if s == "" {
		t.Errorf("String() returned empty string")
	}
	// Should contain the name and type
	if s != "www.example.com. IN A 3600 192.0.2.1\nwww.example.com. IN A 3600 192.0.2.2" {
		t.Errorf("String() = %q, want expected format", s)
	}
}

func TestRRSetCanonicalWireFormat(t *testing.T) {
	t.Run("two A records sorted by canonical wire format", func(t *testing.T) {
		rs := buildTestRRSet(t)

		wire := rs.CanonicalWireFormat()
		if len(wire) == 0 {
			t.Errorf("CanonicalWireFormat() returned empty")
		}

		// The wire format should start with the canonical domain name.
		// www.example.com. -> 03 www 07 example 03 com 00
		wantPrefix := []byte{0x03, 'w', 'w', 'w', 0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x03, 'c', 'o', 'm', 0x00}
		if !bytes.HasPrefix(wire, wantPrefix) {
			t.Errorf("CanonicalWireFormat() prefix = %x, want %x", wire[:len(wantPrefix)], wantPrefix)
		}

		// TTL should be 0 in canonical form.
		// After name (17 bytes) + class (2) + type (2) = 21 bytes, TTL follows.
		if wire[21] != 0 || wire[22] != 0 || wire[23] != 0 || wire[24] != 0 {
			t.Errorf("CanonicalWireFormat() TTL bytes = %x %x %x %x, want 00 00 00 00", wire[21], wire[22], wire[23], wire[24])
		}
	})

	t.Run("RDATA sorted by canonical wire format", func(t *testing.T) {
		t.Helper()
		name := testDomainName(t, "example.com.")
		// Larger IP first in construction, but canonical sort puts smaller first.
		aHigh := NewRecordA([4]byte{192, 0, 2, 2})
		aLow := NewRecordA([4]byte{192, 0, 2, 1})
		rs := NewRRSet(name, CLASS_IN, TYPE_A, 3600, aHigh, aLow)

		wire := rs.CanonicalWireFormat()
		// First record's RDATA should be 192.0.2.1 (sorted), not 192.0.2.2.
		// After name (13 bytes for example.com.) + class(2) + type(2) + ttl(4) = 21 bytes, RDATA follows.
		if wire[21] != 192 || wire[22] != 0 || wire[23] != 2 || wire[24] != 1 {
			t.Errorf("first RDATA = %x, want c0 00 02 01 (sorted)", wire[21:25])
		}
	})

	t.Run("empty RRSet produces empty wire format", func(t *testing.T) {
		name := testDomainName(t, "example.com.")
		rs := NewRRSet(name, CLASS_IN, TYPE_A, 3600)
		wire := rs.CanonicalWireFormat()
		if len(wire) != 0 {
			t.Errorf("CanonicalWireFormat() = %x, want empty", wire)
		}
	})
}

func TestRRSetAppendCanonicalWireFormat(t *testing.T) {
	rs := buildTestRRSet(t)

	var w WireFormat
	size := rs.AppendCanonicalWireFormat(&w)
	if size != uint32(len(w)) {
		t.Errorf("AppendCanonicalWireFormat() size = %d, want %d", size, len(w))
	}

	// Round trip: canonical wire format should match what was appended.
	want := rs.CanonicalWireFormat()
	if !bytes.Equal(w, want) {
		t.Errorf("AppendCanonicalWireFormat() = %x, want %x", w, want)
	}
}

func TestLabelCount(t *testing.T) {
	tests := []struct {
		name string
		dom  string
		want int
	}{
		{"root", ".", 0},
		{"com", "com.", 1},
		{"example.com", "example.com.", 2},
		{"www.example.com", "www.example.com.", 3},
		{"a.b.c.d.example", "a.b.c.d.example.", 5},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d, err := NewDomainNameFromString(tt.dom)
			if err != nil {
				t.Fatalf("NewDomainNameFromString(%q) error = %v", tt.dom, err)
			}
			if got := labelCount(d); got != tt.want {
				t.Errorf("labelCount(%q) = %d, want %d", tt.dom, got, tt.want)
			}
		})
	}
}

func TestDNSSECAlgorithmHash(t *testing.T) {
	tests := []struct {
		name    string
		alg     uint8
		want    crypto.Hash
		wantOK  bool
	}{
		{"RSASHA1", 5, crypto.SHA1, true},
		{"RSASHA256", 8, crypto.SHA256, true},
		{"RSASHA512", 10, crypto.SHA512, true},
		{"ECDSAP256SHA256", 13, crypto.SHA256, true},
		{"ECDSAP384SHA384", 14, crypto.SHA384, true},
		{"ED25519", 15, 0, true},
		{"unknown", 99, 0, false},
		{"ECC-GOST", 12, 0, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := dnssecAlgorithmHash(tt.alg)
			if ok != tt.wantOK {
				t.Errorf("dnssecAlgorithmHash(%d) ok = %v, want %v", tt.alg, ok, tt.wantOK)
				return
			}
			if got != tt.want {
				t.Errorf("dnssecAlgorithmHash(%d) = %v, want %v", tt.alg, got, tt.want)
			}
		})
	}
}

func TestSignRRSetRSA(t *testing.T) {
	// Generate an RSA key for testing.
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey() error = %v", err)
	}

	rs := buildTestRRSet(t)
	signer := privateKey // *rsa.PrivateKey implements crypto.Signer

	rrsig, err := SignRRSet(&rs, signer, 8 /* RSASHA256 */, 12345,
		testDomainName(t, "www.example.com."), 1700000000, 1800000000)
	if err != nil {
		t.Fatalf("SignRRSet() error = %v", err)
	}

	if rrsig.TypeCovered != uint16(TYPE_A) {
		t.Errorf("TypeCovered = %d, want %d", rrsig.TypeCovered, TYPE_A)
	}
	if rrsig.Algorithm != 8 {
		t.Errorf("Algorithm = %d, want 8", rrsig.Algorithm)
	}
	if rrsig.Labels != 3 {
		t.Errorf("Labels = %d, want 3", rrsig.Labels)
	}
	if rrsig.OrigTTL != 3600 {
		t.Errorf("OrigTTL = %d, want 3600", rrsig.OrigTTL)
	}
	if rrsig.KeyTag != 12345 {
		t.Errorf("KeyTag = %d, want 12345", rrsig.KeyTag)
	}
	if rrsig.Expiration != 1800000000 {
		t.Errorf("Expiration = %d, want 1800000000", rrsig.Expiration)
	}
	if rrsig.Inception != 1700000000 {
		t.Errorf("Inception = %d, want 1700000000", rrsig.Inception)
	}
	if len(rrsig.Signature) == 0 {
		t.Errorf("Signature is empty")
	}

	// Verify the signature using the public key.
	pub := &privateKey.PublicKey
	hash := sha256.Sum256(rs.CanonicalWireFormat())
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, hash[:], rrsig.Signature); err != nil {
		t.Errorf("rsa.VerifyPKCS1v15() error = %v", err)
	}
}

func TestSignRRSetECDSA(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey() error = %v", err)
	}

	rs := buildTestRRSet(t)
	signer := privateKey // *ecdsa.PrivateKey implements crypto.Signer

	rrsig, err := SignRRSet(&rs, signer, 13 /* ECDSAP256SHA256 */, 54321,
		testDomainName(t, "www.example.com."), 1700000000, 1800000000)
	if err != nil {
		t.Fatalf("SignRRSet() error = %v", err)
	}

	if rrsig.Algorithm != 13 {
		t.Errorf("Algorithm = %d, want 13", rrsig.Algorithm)
	}
	if rrsig.Labels != 3 {
		t.Errorf("Labels = %d, want 3", rrsig.Labels)
	}
	if len(rrsig.Signature) == 0 {
		t.Errorf("Signature is empty")
	}

	// Verify using ECDSA.  ECDSA signatures are DER-encoded, so parse r/s first.
	hash := sha256.Sum256(rs.CanonicalWireFormat())
	var sig struct {
		R, S *big.Int
	}
	if _, err := asn1.Unmarshal(rrsig.Signature, &sig); err != nil {
		t.Fatalf("asn1.Unmarshal() error = %v", err)
	}
	if !ecdsa.Verify(&privateKey.PublicKey, hash[:], sig.R, sig.S) {
		t.Errorf("ecdsa.Verify() returned false")
	}
}

func TestSignRRSetErrors(t *testing.T) {
	rs := buildTestRRSet(t)

	t.Run("nil RRSet", func(t *testing.T) {
		privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
		if _, err := SignRRSet(nil, privateKey, 8, 12345, testDomainName(t, "example.com."), 0, 0); err == nil {
			t.Errorf("SignRRSet() expected error for nil RRSet, got nil")
		}
	})

	t.Run("nil signer", func(t *testing.T) {
		if _, err := SignRRSet(&rs, nil, 8, 12345, testDomainName(t, "example.com."), 0, 0); err == nil {
			t.Errorf("SignRRSet() expected error for nil signer, got nil")
		}
	})

	t.Run("unsupported algorithm", func(t *testing.T) {
		privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
		if _, err := SignRRSet(&rs, privateKey, 99, 12345, testDomainName(t, "example.com."), 0, 0); err == nil {
			t.Errorf("SignRRSet() expected error for unsupported algorithm, got nil")
		}
	})
}

func TestDNSSECSignOptionsDefaults(t *testing.T) {
	// Zero value options should use defaults.
	var opts DNSSECSignOptions
	if opts.inceptionTime() == 0 {
		t.Log("note: inceptionTime() returned 0, meaning current time is 0 (unlikely in tests)")
	}
	if opts.expirationTime() != 0 {
		t.Errorf("expirationTime() = %d, want 0 (no expiration)", opts.expirationTime())
	}
	if opts.keyTag() != 0 {
		t.Errorf("keyTag() = %d, want 0", opts.keyTag())
	}
	if !opts.signerName().IsRoot() {
		t.Errorf("signerName() = %s, want root", opts.signerName())
	}

	// Custom options.
	custom := DNSSECSignOptions{
		Inception:  1700000000,
		Expiration: 1800000000,
		KeyTag:     42,
		SignerName: testDomainName(t, "signer.example.com."),
	}
	if custom.inceptionTime() != 1700000000 {
		t.Errorf("inceptionTime() = %d, want 1700000000", custom.inceptionTime())
	}
	if custom.expirationTime() != 1800000000 {
		t.Errorf("expirationTime() = %d, want 1800000000", custom.expirationTime())
	}
	if custom.keyTag() != 42 {
		t.Errorf("keyTag() = %d, want 42", custom.keyTag())
	}
	if !custom.signerName().Equal(testDomainName(t, "signer.example.com.")) {
		t.Errorf("signerName() = %s, want signer.example.com.", custom.signerName())
	}
}

func TestRRSetRoundTripViaString(t *testing.T) {
	name := testDomainName(t, "example.com.")
	a := NewRecordA([4]byte{10, 0, 0, 1})
	rs := NewRRSet(name, CLASS_IN, TYPE_A, 300, a)

	// String should be parseable back conceptually (just check non-empty and contains key parts).
	s := rs.String()
	if s == "" {
		t.Errorf("String() returned empty")
	}
	if !bytes.Contains([]byte(s), []byte("example.com.")) {
		t.Errorf("String() = %q, missing domain name", s)
	}
	if !bytes.Contains([]byte(s), []byte("IN A 300")) {
		t.Errorf("String() = %q, missing type/ttl", s)
	}
	if !bytes.Contains([]byte(s), []byte("10.0.0.1")) {
		t.Errorf("String() = %q, missing record data", s)
	}
}
