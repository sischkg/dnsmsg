package dnsmsg

import (
	"encoding/hex"
	"strings"
	"testing"
)

// testOctetsFromHex turns a hex string into the octets it spells, so that a
// key tag test case can be written out in full.
func testOctetsFromHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex.DecodeString(%q) error = %v", s, err)
	}
	return b
}

// keyTagTestVector is one RDATA and the key tag its octets add up to.  The
// first rows are the arithmetic of RFC 4034 Appendix B: a word is two octets,
// a trailing odd octet stands alone as the high-order byte of the last word,
// and the carry of the sum is added back in once.  The last row shows the low
// 16 bits being returned where the sum runs far past them.
func TestDNSSECKeyTag(t *testing.T) {
	tests := []struct {
		name  string
		rdata string
		want  uint16
	}{
		{name: "empty", rdata: "", want: 0},
		{name: "single zero octet", rdata: "00", want: 0},
		{name: "single octet is the high byte", rdata: "01", want: 256},
		{name: "one word", rdata: "0001", want: 1},
		{name: "two words", rdata: "00010002", want: 3},
		{name: "trailing odd octet", rdata: "0001000203", want: 771},
		{name: "largest word", rdata: "ffff", want: 65535},
		{name: "carry added back once", rdata: "ffffff", want: 65280},
		// RFC 4034 Appendix B の例: flags 256, protocol 3, algorithm 5, 公開鍵
		// 無しという DNSKEY RDATA は 0000 0305 0800 01 になり、その key tag は
		// 3077 である。
		{name: "appendix B example", rdata: "00000305080001", want: 3077},
		{name: "same octets reordered", rdata: "0305080100", want: 2822},
		{name: "appendix B key material", rdata: "0100020d", want: 781},
		{name: "carry folds twice", rdata: strings.Repeat("ff", 128), want: 65535},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rdata := testOctetsFromHex(t, tt.rdata)
			if got := DNSSECKeyTag(rdata); got != tt.want {
				t.Errorf("DNSSECKeyTag(%s) = %d, want %d", tt.rdata, got, tt.want)
			}
		})
	}
}

// TestRecordDNSKEYKeyTag checks the key tag of DNSKEY records, which is the
// key tag a resolver compares against RecordRRSIG.KeyTag.  The expected values
// are the RDATA of the record (flags, protocol, algorithm, public key) added
// up as in TestDNSSECKeyTag; the flags, protocol and algorithm octets alone
// already contribute 0001 + 0300 + 0005 + 0000 = 771, which is why the
// algorithm 5 records below start at 1029 and 1030.
func TestRecordDNSKEYKeyTag(t *testing.T) {
	tests := []struct {
		name      string
		flags     uint16
		protocol  uint8
		algorithm uint8
		publicKey string
		want      uint16
	}{
		{
			name:      "no public key",
			flags:     256,
			protocol:  3,
			algorithm: 5,
			publicKey: "",
			want:      1029,
		},
		{
			name:      "publish flag",
			flags:     257,
			protocol:  3,
			algorithm: 5,
			publicKey: "",
			want:      1030,
		},
		{
			// 01 0203: 公開鍵が 3 オクテットで、末尾の 1 オクテットが最後の
			// 語の上位バイトになる。
			name:      "odd length public key",
			flags:     256,
			protocol:  3,
			algorithm: 13,
			publicKey: "010203",
			want:      2063,
		},
		{
			name:      "appendix B key material",
			flags:     256,
			protocol:  3,
			algorithm: 13,
			publicKey: "0100020d",
			want:      1818,
		},
		{
			name:      "carry from the public key",
			flags:     256,
			protocol:  3,
			algorithm: 8,
			publicKey: "00" + strings.Repeat("ff", 128),
			want:      1032,
		},
		{
			name:      "carry folds twice",
			flags:     256,
			protocol:  3,
			algorithm: 13,
			publicKey: strings.Repeat("00", 32) + strings.Repeat("01", 32),
			want:      5149,
		},
		{
			name:      "64 bit public key",
			flags:     257,
			protocol:  3,
			algorithm: 10,
			publicKey: "00" + strings.Repeat("01", 128),
			want:      17483,
		},
		{
			name:      "all octets set",
			flags:     257,
			protocol:  3,
			algorithm: 15,
			publicKey: strings.Repeat("ff", 32),
			want:      1040,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dnskey := NewRecordDNSKEY(tt.flags, tt.protocol, tt.algorithm,
				testOctetsFromHex(t, tt.publicKey))

			got := dnskey.KeyTag()
			if got != tt.want {
				t.Errorf("RecordDNSKEY%+v.KeyTag() = %d, want %d",
					tt, got, tt.want)
			}

			// KeyTag is DNSSECKeyTag over the canonical RDATA of the record.
			rdata := dnskey.CanonicalWireFormat()
			if want := DNSSECKeyTag(rdata); got != want {
				t.Errorf("RecordDNSKEY.KeyTag() = %d, DNSSECKeyTag(%s) = %d",
					got, hex.EncodeToString(rdata), want)
			}

			// The key tag is a property of those octets only, so a copy of the
			// record made from its own wire format has the same key tag.
			if len(tt.publicKey) == 0 {
				// A record that publishes no public key cannot be parsed back:
				// ParseRecordDNSKEY requires a public key.
				return
			}
			reparsed, pos, err := ParseRecordDNSKEY(rdata, 0, uint32(len(rdata)))
			if err != nil {
				t.Fatalf("ParseRecordDNSKEY() error = %v", err)
			}
			if pos != uint32(len(rdata)) {
				t.Errorf("ParseRecordDNSKEY() pos = %d, want %d", pos, len(rdata))
			}
			if got := reparsed.KeyTag(); got != tt.want {
				t.Errorf("re-parsed RecordDNSKEY.KeyTag() = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestDNSSECKeyKeyTag(t *testing.T) {
	// A key tag does not depend on the key name, flags, protocol or algorithm
	// being anything sensible, only on the public key material they are
	// published with.
	const (
		flags     = 257
		protocol  = 3
		algorithm = 13
	)
	material := testOctetsFromHex(t, "0100020d"+strings.Repeat("ab", 15))
	dnskey := NewRecordDNSKEY(flags, protocol, algorithm, material)
	want := DNSSECKeyTag(dnskey.CanonicalWireFormat())

	key := &DNSSECKey{
		Flags:     flags,
		Protocol:  protocol,
		Algorithm: algorithm,
		Name:      testDomainName(t, "example.com."),
		PublicKey: material,
	}

	got, err := key.KeyTag()
	if err != nil {
		t.Fatalf("DNSSECKey.KeyTag() error = %v", err)
	}
	if got != want {
		t.Errorf("DNSSECKey.KeyTag() = %d, want %d", got, want)
	}
	if got := key.ToDNSKEY().KeyTag(); got != want {
		t.Errorf("ToDNSKEY().KeyTag() = %d, want %d", got, want)
	}

	// The key tag is a property of the published octets only, so the same
	// public key material published under another name has the same key tag.
	other := &DNSSECKey{
		Flags:     flags,
		Protocol:  protocol,
		Algorithm: algorithm,
		Name:      testDomainName(t, "other.example.org."),
		PublicKey: append([]byte(nil), material...),
	}
	if got, err := other.KeyTag(); err != nil {
		t.Errorf("key with another name: KeyTag() error = %v", err)
	} else if got != want {
		t.Errorf("key with another name: KeyTag() = %d, want %d", got, want)
	}
}

func TestDNSSECKeyKeyTagWithoutPublicKey(t *testing.T) {
	// Key material read from a .private file alone cannot have a key tag: the
	// four octets it would add up are flags, protocol and algorithm only, and
	// a value that looks like a key tag is not one.
	tests := []struct {
		name string
		key  *DNSSECKey
	}{
		{
			name: "key read from a .private file",
			key: &DNSSECKey{
				Flags:         257,
				Protocol:      3,
				Algorithm:     13,
				Name:          testDomainName(t, "example.com."),
				PrivateKey:    testOctetsFromHex(t, strings.Repeat("01", 32)),
				PrivateParams: map[string][]byte{"PrivateKey": testOctetsFromHex(t, strings.Repeat("01", 32))},
			},
		},
		{
			name: "public key left nil",
			key: &DNSSECKey{
				Flags:     257,
				Protocol:  3,
				Algorithm: 5,
				Name:      testDomainName(t, "example.com."),
			},
		},
		{
			name: "public key present but empty",
			key:  &DNSSECKey{Flags: 256, Protocol: 3, Algorithm: 8, Name: testDomainName(t, "example.com."), PublicKey: []byte{}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tag, err := tt.key.KeyTag()
			if err == nil {
				t.Fatalf("DNSSECKey.KeyTag() = %d, want an error", tag)
			}
			t.Logf("KeyTag() error = %v", err)
		})
	}

	if _, err := (*DNSSECKey)(nil).KeyTag(); err == nil {
		t.Error("DNSSECKey(nil).KeyTag() = nil error, want an error")
	}
}
