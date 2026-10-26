package dnsmsg

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

// The certificate association data of the two hashed TLSA examples of RFC 6698
// Section 2.3: a SHA-256 association of a CA certificate, and a SHA-512
// association of the public key of an end entity certificate.
const (
	tlsaSHA256Data = "d2abde240d7cd3ee6b4b28c54df034b97983a1d16e8a410e4561cb106618e971"
	tlsaSHA512Data = "92003ba34942dc74152e2f2c408d29eca5a520e7f2e06bb944f4dca346baf63c" +
		"1b177615d466f6c4b71c216a50292bd58c9ebdd2f74e38fe51ffd48c43326cbc"
)

func mustTLSA(t *testing.T, certUsage, selector, matchingType uint8, hexData string) RecordTLSA {
	t.Helper()
	r, err := NewRecordTLSAFromHex(certUsage, selector, matchingType, hexData)
	if err != nil {
		t.Fatalf("NewRecordTLSAFromHex(%d, %d, %d, %q): %v", certUsage, selector, matchingType, hexData, err)
	}
	return r
}

// tlsaRDATA gives the RDATA of a TLSA record: the certificate usage, the
// selector and the matching type as single octets, followed by the certificate
// association data given as a string of hexadecimal digits.
func tlsaRDATA(t *testing.T, certUsage, selector, matchingType uint8, hexData string) []byte {
	t.Helper()
	data, err := hex.DecodeString(hexData)
	if err != nil {
		t.Fatalf("tlsaRDATA(%q): %v", hexData, err)
	}
	return append([]byte{certUsage, selector, matchingType}, data...)
}

// The RFC 6698 Section 2.3 example of a SHA-256 association, both as a record
// and as its RDATA.
func rfcSHA256TLSA(t *testing.T) (RecordTLSA, []byte) {
	t.Helper()
	return mustTLSA(t, TLSACertUsageCA, TLSASelectorFullCertificate, TLSAMatchingSHA256, tlsaSHA256Data),
		tlsaRDATA(t, TLSACertUsageCA, TLSASelectorFullCertificate, TLSAMatchingSHA256, tlsaSHA256Data)
}

func TestParseRecordTLSA(t *testing.T) {
	sha256, sha256RDATA := rfcSHA256TLSA(t)
	sha512RDATA := tlsaRDATA(t, TLSACertUsageServiceConstraint, TLSASelectorSPKI, TLSAMatchingSHA512, tlsaSHA512Data)

	tests := []struct {
		name    string
		input   []byte
		begin   uint32
		end     uint32
		want    RecordTLSA
		wantPos uint32
		wantErr bool
	}{
		{
			name:    "the SHA-256 example of RFC 6698 Section 2.3",
			input:   sha256RDATA,
			begin:   0,
			want:    sha256,
			wantPos: uint32(len(sha256RDATA)),
		},
		{
			name:    "the SHA-512 example of RFC 6698 Section 2.3",
			input:   sha512RDATA,
			begin:   0,
			want:    mustTLSA(t, TLSACertUsageServiceConstraint, TLSASelectorSPKI, TLSAMatchingSHA512, tlsaSHA512Data),
			wantPos: uint32(len(sha512RDATA)),
		},
		{
			name:  "association data of a single octet",
			input: []byte{0x00, 0x00, 0x00, 0xAA},
			begin: 0,
			want: RecordTLSA{
				CertificateUsage: TLSACertUsageCA,
				Selector:         TLSASelectorFullCertificate,
				MatchingType:     TLSAMatchingNoHash,
				Data:             []byte{0xAA},
			},
			wantPos: 4,
		},
		{
			name:  "values reserved for private use are read as they are",
			input: []byte{0xFF, 0xFF, 0xFF, 0x01, 0x02, 0x03},
			begin: 0,
			want: RecordTLSA{
				CertificateUsage: TLSACertUsagePrivate,
				Selector:         TLSASelectorPrivate,
				MatchingType:     TLSAMatchingPrivate,
				Data:             []byte{0x01, 0x02, 0x03},
			},
			wantPos: 6,
		},
		{
			name:  "association data that is not the length its matching type gives",
			input: []byte{0x03, 0x01, 0x02, 0x11, 0x22, 0x33, 0x44, 0x55},
			begin: 0,
			want: RecordTLSA{
				CertificateUsage: TLSACertUsageDomainIssued,
				Selector:         TLSASelectorSPKI,
				MatchingType:     TLSAMatchingSHA512,
				Data:             []byte{0x11, 0x22, 0x33, 0x44, 0x55},
			},
			wantPos: 8,
		},
		{
			name:    "record parsed at an offset",
			input:   append([]byte{0xAA, 0xBB}, sha256RDATA...),
			begin:   2,
			want:    sha256,
			wantPos: uint32(2 + len(sha256RDATA)),
		},
		{
			name:    "truncated input - missing selector",
			input:   []byte{0x03, 0xE8},
			begin:   0,
			wantErr: true,
		},
		{
			name:    "truncated input - missing matching type",
			input:   []byte{0x03, 0xE8, 0x05},
			begin:   0,
			wantErr: true,
		},
		{
			name:    "truncated input - no association data",
			input:   []byte{0x03, 0x01, 0x02},
			begin:   0,
			wantErr: true,
		},
		{
			name:    "out of bounds begin",
			input:   []byte{0x03, 0x01, 0x02, 0xAA},
			begin:   10,
			wantErr: true,
		},
		{
			name:    "end beyond the message",
			input:   []byte{0x03, 0x01, 0x02, 0xAA},
			begin:   0,
			end:     10,
			wantErr: true,
		},
		{
			name: "association data bounded by RDLENGTH, trailing data ignored",
			input: append(
				[]byte{0x03, 0x01, 0x02, 0x49, 0x54, 0x13, 0x37},
				0xAA, 0xBB, 0xCC, // trailing bytes that must not be absorbed
			),
			begin: 0,
			end:   7, // 3 (the fixed fields) + 4 (the association data)
			want: RecordTLSA{
				CertificateUsage: TLSACertUsageDomainIssued,
				Selector:         TLSASelectorSPKI,
				MatchingType:     TLSAMatchingSHA512,
				Data:             []byte{0x49, 0x54, 0x13, 0x37},
			},
			wantPos: 7,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			end := tt.end
			if end == 0 {
				end = uint32(len(tt.input))
			}
			got, pos, err := ParseRecordTLSA(tt.input, tt.begin, end)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseRecordTLSA() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ParseRecordTLSA() got = %v, want %v", got, tt.want)
			}
			if pos != tt.wantPos {
				t.Errorf("ParseRecordTLSA() pos = %v, want %v", pos, tt.wantPos)
			}
		})
	}
}

// The octets of the association data belong to the record, not to the message:
// changing the message does not change the record.
func TestParseRecordTLSACopiesTheAssociationData(t *testing.T) {
	_, rdata := rfcSHA256TLSA(t)
	w := WireFormat(append(WireFormat{}, rdata...))

	got, _, err := ParseRecordTLSA(w, 0, uint32(len(w)))
	if err != nil {
		t.Fatalf("ParseRecordTLSA() error = %v", err)
	}
	w[len(w)-1] = 0x00

	if hex.EncodeToString(got.Data) != tlsaSHA256Data {
		t.Errorf("Data = %x, want %s", got.Data, tlsaSHA256Data)
	}
}

func TestNewRecordTLSA(t *testing.T) {
	got, err := NewRecordTLSA(3, 1, 2, []byte{0x01, 0x02})
	if err != nil {
		t.Fatalf("NewRecordTLSA() error = %v", err)
	}
	want := RecordTLSA{
		CertificateUsage: 3,
		Selector:         1,
		MatchingType:     2,
		Data:             []byte{0x01, 0x02},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("NewRecordTLSA() got = %v, want %v", got, want)
	}

	tests := []struct {
		name  string
		data  []byte
		isErr bool
	}{
		{
			name:  "empty association data",
			data:  []byte{},
			isErr: true,
		},
		{
			name:  "nil association data",
			data:  nil,
			isErr: true,
		},
		{
			name:  "association data longer than an RDATA can hold",
			data:  bytes.Repeat([]byte{0xAB}, tlsaMaxDataSize+1),
			isErr: true,
		},
		{
			name: "longest association data that fits in an RDATA",
			data: bytes.Repeat([]byte{0xAB}, tlsaMaxDataSize),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewRecordTLSA(3, 1, 2, tt.data)
			if (err != nil) != tt.isErr {
				t.Errorf("NewRecordTLSA() error = %v, wantErr %v", err, tt.isErr)
			}
		})
	}
}

func TestNewRecordTLSAFromHex(t *testing.T) {
	r, err := NewRecordTLSAFromHex(0, 0, 1, tlsaSHA256Data)
	if err != nil {
		t.Fatalf("NewRecordTLSAFromHex() error = %v", err)
	}
	if len(r.Data) != 32 {
		t.Errorf("Data is %d octets, want 32", len(r.Data))
	}
	if r, err = NewRecordTLSAFromHex(1, 1, 2, tlsaSHA512Data); err != nil {
		t.Fatalf("NewRecordTLSAFromHex() error = %v", err)
	}
	if len(r.Data) != 64 {
		t.Errorf("Data is %d octets, want 64", len(r.Data))
	}

	tests := []struct {
		name    string
		hexData string
		want    []byte
		wantErr bool
	}{
		{
			name:    "lower-case digits",
			hexData: "000102ff",
			want:    []byte{0x00, 0x01, 0x02, 0xff},
		},
		{
			name:    "upper-case digits are accepted",
			hexData: "000102FF",
			want:    []byte{0x00, 0x01, 0x02, 0xff},
		},
		{
			name:    "empty association data",
			hexData: "",
			wantErr: true,
		},
		{
			name:    "odd number of digits",
			hexData: "abc",
			wantErr: true,
		},
		{
			name:    "not a hexadecimal digit",
			hexData: "abcdxy",
			wantErr: true,
		},
		{
			name:    "whitespace is not part of the hexadecimal string",
			hexData: "abcd ef",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewRecordTLSAFromHex(3, 1, 2, tt.hexData)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewRecordTLSAFromHex(%q) error = %v, wantErr %v", tt.hexData, err, tt.wantErr)
				return
			}
			if !tt.wantErr && !bytes.Equal(got.Data, tt.want) {
				t.Errorf("NewRecordTLSAFromHex(%q) Data = %x, want %x", tt.hexData, got.Data, tt.want)
			}
		})
	}
}

func TestNewRecordTLSAFromString(t *testing.T) {
	sha256, _ := rfcSHA256TLSA(t)

	tests := []struct {
		name  string
		input string
		want  RecordTLSA
	}{
		{
			name:  "the SHA-256 example of RFC 6698 Section 3 on one line",
			input: "0 0 1 " + tlsaSHA256Data,
			want:  sha256,
		},
		{
			name: "the SHA-512 example of RFC 6698 Section 3, as a master file writes it",
			input: "1 1 2 92003ba34942dc74152e2f2c408d29ec\n" +
				"      a5a520e7f2e06bb944f4dca346baf63c\n" +
				"      1b177615d466f6c4b71c216a50292bd5\n" +
				"      8c9ebdd2f74e38fe51ffd48c43326cbc",
			want: mustTLSA(t, TLSACertUsageServiceConstraint, TLSASelectorSPKI, TLSAMatchingSHA512, tlsaSHA512Data),
		},
		{
			name:  "the full certificate association of RFC 6698 Section 3",
			input: "3 0 0 30820307308201efa0030201020200",
			want: RecordTLSA{
				CertificateUsage: TLSACertUsageDomainIssued,
				Selector:         TLSASelectorFullCertificate,
				MatchingType:     TLSAMatchingNoHash,
				Data:             []byte{0x30, 0x82, 0x03, 0x07, 0x30, 0x82, 0x01, 0xef, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x00},
			},
		},
		{
			name:  "upper-case digits are accepted",
			input: "3 1 1 D2ABDE240D7CD3EE6B4B28C54DF034B9",
			want: RecordTLSA{
				CertificateUsage: TLSACertUsageDomainIssued,
				Selector:         TLSASelectorSPKI,
				MatchingType:     TLSAMatchingSHA256,
				Data:             mustTLSA(t, 3, 1, 1, tlsaSHA256Data[:32]).Data,
			},
		},
		{
			name:  "surrounding and repeated whitespace",
			input: "  3\t1 2\t\t0102   0304  \n",
			want: RecordTLSA{
				CertificateUsage: TLSACertUsageDomainIssued,
				Selector:         TLSASelectorSPKI,
				MatchingType:     TLSAMatchingSHA512,
				Data:             []byte{0x01, 0x02, 0x03, 0x04},
			},
		},
		{
			name:  "the values reserved for private use",
			input: "255 255 255 2a",
			want: RecordTLSA{
				CertificateUsage: TLSACertUsagePrivate,
				Selector:         TLSASelectorPrivate,
				MatchingType:     TLSAMatchingPrivate,
				Data:             []byte{0x2a},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewRecordTLSAFromString(tt.input)
			if err != nil {
				t.Fatalf("NewRecordTLSAFromString(%q) error = %v", tt.input, err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewRecordTLSAFromString(%q) got = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestNewRecordTLSAFromStringErrors(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{name: "empty string", input: ""},
		{name: "no association data", input: "3 1 2"},
		{name: "only the certificate usage and the selector", input: "3 1"},
		{name: "certificate usage of 256", input: "256 1 1 2a"},
		{name: "selector of 256", input: "3 256 1 2a"},
		{name: "matching type of 256", input: "3 1 256 2a"},
		{name: "negative certificate usage", input: "-1 1 1 2a"},
		{name: "certificate usage that is not a number", input: "three 1 1 2a"},
		{name: "certificate usage with more than three digits", input: "1000 1 1 2a"},
		{name: "odd number of hexadecimal digits", input: "3 1 1 abc"},
		{name: "characters that are not hexadecimal digits", input: "3 1 1 xyzw"},
		{name: "association data given as two octets worth of separators", input: "3 1 1 ab cd ef gh"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewRecordTLSAFromString(tt.input)
			if err == nil {
				t.Errorf("NewRecordTLSAFromString(%q) = %v, want an error", tt.input, got)
				return
			}
			if !wantErrNamesRecord(err, "TLSA") {
				t.Errorf("NewRecordTLSAFromString(%q) error = %q, which does not name the TLSA record", tt.input, err)
			}
		})
	}
}

func TestRecordTLSAString(t *testing.T) {
	sha256, _ := rfcSHA256TLSA(t)

	tests := []struct {
		name string
		r    RecordTLSA
		want string
	}{
		{
			name: "the SHA-256 example of RFC 6698 Section 2.3",
			r:    sha256,
			want: "0 0 1 " + tlsaSHA256Data,
		},
		{
			name: "the SHA-512 example of RFC 6698 Section 2.3",
			r:    mustTLSA(t, TLSACertUsageServiceConstraint, TLSASelectorSPKI, TLSAMatchingSHA512, tlsaSHA512Data),
			want: "1 1 2 " + tlsaSHA512Data,
		},
		{
			name: "full certificate association of a single octet",
			r: RecordTLSA{
				CertificateUsage: TLSACertUsageDomainIssued,
				Selector:         TLSASelectorFullCertificate,
				MatchingType:     TLSAMatchingNoHash,
				Data:             []byte{0xAA},
			},
			want: "3 0 0 aa",
		},
		{
			name: "the values reserved for private use",
			r: RecordTLSA{
				CertificateUsage: TLSACertUsagePrivate,
				Selector:         TLSASelectorPrivate,
				MatchingType:     TLSAMatchingPrivate,
				Data:             []byte{0x01, 0x02, 0x03},
			},
			want: "255 255 255 010203",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.r.String()
			if got != tt.want {
				t.Errorf("String() = %q, want %q", got, tt.want)
			}
			// The presentation format is what String writes, so reading it back
			// gives the same record.
			roundTrip, err := NewRecordTLSAFromString(got)
			if err != nil {
				t.Errorf("NewRecordTLSAFromString(%q) error = %v", got, err)
				return
			}
			if !reflect.DeepEqual(roundTrip, tt.r) {
				t.Errorf("NewRecordTLSAFromString(%q) got = %v, want %v", got, roundTrip, tt.r)
			}
		})
	}
}

func TestRecordTLSAType(t *testing.T) {
	r := mustTLSA(t, TLSACertUsageDomainIssued, TLSASelectorSPKI, TLSAMatchingSHA256, tlsaSHA256Data)
	if r.Type() != TYPE_TLSA {
		t.Errorf("RecordTLSA.Type() = %v, want TYPE_TLSA", r.Type())
	}
	if TYPE_TLSA != 52 {
		t.Errorf("TYPE_TLSA = %d, want 52", TYPE_TLSA)
	}
	if TYPE_TLSA.String() != "TLSA" {
		t.Errorf("TYPE_TLSA.String() = %q, want %q", TYPE_TLSA.String(), "TLSA")
	}
	if n, err := NewType("TLSA"); err != nil || n != TYPE_TLSA {
		t.Errorf("NewType(%q) = %v, %v, want TYPE_TLSA, nil", "TLSA", n, err)
	}
	if n, err := NewType("TYPE52"); err != nil || n != TYPE_TLSA {
		t.Errorf("NewType(%q) = %v, %v, want TYPE_TLSA, nil", "TYPE52", n, err)
	}

	// The field values of the IANA registries RFC 6698 Section 7 cites.
	want := []struct {
		name  string
		got   uint8
		value uint8
	}{
		{name: "TLSACertUsageCA", got: TLSACertUsageCA, value: 0},
		{name: "TLSACertUsageServiceConstraint", got: TLSACertUsageServiceConstraint, value: 1},
		{name: "TLSACertUsageTrustAnchorAssertion", got: TLSACertUsageTrustAnchorAssertion, value: 2},
		{name: "TLSACertUsageDomainIssued", got: TLSACertUsageDomainIssued, value: 3},
		{name: "TLSACertUsagePrivate", got: TLSACertUsagePrivate, value: 255},
		{name: "TLSASelectorFullCertificate", got: TLSASelectorFullCertificate, value: 0},
		{name: "TLSASelectorSPKI", got: TLSASelectorSPKI, value: 1},
		{name: "TLSASelectorPrivate", got: TLSASelectorPrivate, value: 255},
		{name: "TLSAMatchingNoHash", got: TLSAMatchingNoHash, value: 0},
		{name: "TLSAMatchingSHA256", got: TLSAMatchingSHA256, value: 1},
		{name: "TLSAMatchingSHA512", got: TLSAMatchingSHA512, value: 2},
		{name: "TLSAMatchingPrivate", got: TLSAMatchingPrivate, value: 255},
	}
	for _, tt := range want {
		if tt.got != tt.value {
			t.Errorf("%s = %d, want %d", tt.name, tt.got, tt.value)
		}
	}
}

// A TLSA record holds no domain name, so the compression DB is not used and its
// canonical wire format and its RDATA are the same octets.
func TestRecordTLSAWireFormatRoundTrip(t *testing.T) {
	original, rdata := rfcSHA256TLSA(t)

	db := NewNameCompressionDB()
	db.AddDomainName(testDomainName(t, "_443._tcp.example.com."), 12)

	var w WireFormat
	size := original.AppendWireFormat(&w, db)
	if size != uint32(len(w)) {
		t.Errorf("AppendWireFormat() size = %v, want %v", size, len(w))
	}
	if size != uint32(len(rdata)) {
		t.Errorf("AppendWireFormat() size = %v, want %d", size, len(rdata))
	}
	if !bytes.Equal(w, rdata) {
		t.Errorf("AppendWireFormat() = % x, want % x", w, rdata)
	}

	got, pos, err := ParseRecordTLSA(w, 0, size)
	if err != nil {
		t.Fatalf("ParseRecordTLSA() error = %v", err)
	}
	if pos != size {
		t.Errorf("ParseRecordTLSA() pos = %v, want %v", pos, size)
	}
	if !reflect.DeepEqual(got, original) {
		t.Errorf("ParseRecordTLSA() got = %v, want %v", got, original)
	}

	var cw WireFormat
	cSize := original.AppendCanonicalWireFormat(&cw)
	if cSize != size {
		t.Errorf("AppendCanonicalWireFormat() size = %v, want %v", cSize, size)
	}
	if !bytes.Equal(cw, w) {
		t.Errorf("AppendCanonicalWireFormat() = % x, want % x", cw, w)
	}
	if !bytes.Equal(original.CanonicalWireFormat(), rdata) {
		t.Errorf("CanonicalWireFormat() = % x, want % x", original.CanonicalWireFormat(), rdata)
	}
}

func TestParseResourceRecordTLSA(t *testing.T) {
	_, rdata := rfcSHA256TLSA(t)

	// A TLSA record in a message, at the name RFC 7671 Section 3.1 gives it.
	var w WireFormat
	w.AppendDomainName(testDomainName(t, "_443._tcp.example.com."), nil)
	w.AppendUInt16(uint16(TYPE_TLSA))
	w.AppendUInt16(uint16(CLASS_IN))
	w.AppendUInt32(3600)
	w.AppendUInt16(uint16(len(rdata)))
	w.AppendBytes(rdata)

	rr, pos, err := ParseResourceRecord(w, 0)
	if err != nil {
		t.Fatalf("ParseResourceRecord() error = %v", err)
	}
	if pos != uint32(len(w)) {
		t.Errorf("ParseResourceRecord() pos = %v, want %v", pos, len(w))
	}
	if rr.Type != TYPE_TLSA {
		t.Errorf("Type = %v, want TYPE_TLSA", rr.Type)
	}
	if rr.TTL != 3600 {
		t.Errorf("TTL = %v, want 3600", rr.TTL)
	}
	rdata2, ok := rr.RData.(RecordTLSA)
	if !ok {
		t.Fatalf("RData = %T, want RecordTLSA", rr.RData)
	}
	if !reflect.DeepEqual(rdata2, mustTLSA(t, TLSACertUsageCA, TLSASelectorFullCertificate, TLSAMatchingSHA256, tlsaSHA256Data)) {
		t.Errorf("RData = %v, want the RFC 6698 SHA-256 record", rdata2)
	}
}

// A TLSA record in a message round-trips through the wire format, with the
// record name and the rest of the message left as they are.
func TestResourceRecordTLSAWireFormatRoundTrip(t *testing.T) {
	original, _ := rfcSHA256TLSA(t)
	rr := ResourceRecord{
		Name:  testDomainName(t, "_443._tcp.example.com."),
		Class: CLASS_IN,
		Type:  TYPE_TLSA,
		TTL:   3600,
		RData: original,
	}

	var w WireFormat
	size := AppendResourceRecord(&w, rr, NewNameCompressionDB())
	if size != uint32(len(w)) {
		t.Errorf("AppendResourceRecord() size = %v, want %v", size, len(w))
	}

	got, pos, err := ParseResourceRecord(w, 0)
	if err != nil {
		t.Fatalf("ParseResourceRecord() error = %v", err)
	}
	if pos != size {
		t.Errorf("ParseResourceRecord() pos = %v, want %v", pos, size)
	}
	if got.Name.String() != rr.Name.String() {
		t.Errorf("Name = %q, want %q", got.Name.String(), rr.Name.String())
	}
	if got.Type != TYPE_TLSA || got.Class != CLASS_IN || got.TTL != 3600 {
		t.Errorf("record header = %v %v %v, want TYPE_TLSA CLASS_IN 3600", got.Type, got.Class, got.TTL)
	}
	gotRData, ok := got.RData.(RecordTLSA)
	if !ok {
		t.Fatalf("RData = %T, want RecordTLSA", got.RData)
	}
	if !reflect.DeepEqual(gotRData, original) {
		t.Errorf("RData = %v, want %v", gotRData, original)
	}
}

func TestRecordTLSAJSON(t *testing.T) {
	tests := []struct {
		name string
		r    RecordTLSA
		want string
	}{
		{
			name: "the SHA-256 example of RFC 6698 Section 2.3",
			r:    mustTLSA(t, TLSACertUsageCA, TLSASelectorFullCertificate, TLSAMatchingSHA256, tlsaSHA256Data),
			want: `{"CertificateUsage":0,"Data":"d2abde240d7cd3ee6b4b28c54df034b97983a1d16e8a410e4561cb106618e971","MatchingType":1,"Selector":0}`,
		},
		{
			name: "the SHA-512 example of RFC 6698 Section 2.3",
			r:    mustTLSA(t, TLSACertUsageServiceConstraint, TLSASelectorSPKI, TLSAMatchingSHA512, tlsaSHA512Data),
			want: `{"CertificateUsage":1,"Data":"92003ba34942dc74152e2f2c408d29eca5a520e7f2e06bb944f4dca346baf63c1b177615d466f6c4b71c216a50292bd58c9ebdd2f74e38fe51ffd48c43326cbc","MatchingType":2,"Selector":1}`,
		},
		{
			name: "an unhashed association",
			r: RecordTLSA{
				CertificateUsage: TLSACertUsageDomainIssued,
				Selector:         TLSASelectorFullCertificate,
				MatchingType:     TLSAMatchingNoHash,
				Data:             []byte{0x30, 0x82},
			},
			want: `{"CertificateUsage":3,"Data":"3082","MatchingType":0,"Selector":0}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := json.Marshal(tt.r)
			if err != nil {
				t.Fatalf("json.Marshal() error = %v", err)
			}
			if string(data) != tt.want {
				t.Errorf("json.Marshal() = %s, want %s", data, tt.want)
			}

			// Unmarshalling the RDATA on its own gives the record back.
			var got RecordTLSA
			if err := json.Unmarshal(data, &got); err != nil {
				t.Fatalf("json.Unmarshal() error = %v", err)
			}
			if !reflect.DeepEqual(got, tt.r) {
				t.Errorf("json.Unmarshal() got = %v, want %v", got, tt.r)
			}

			// Unmarshalling the record as the RData of a resource record keeps
			// the TLSA type.
			rr := ResourceRecord{
				Name:  testDomainName(t, "_443._tcp.example.com."),
				Class: CLASS_IN,
				Type:  TYPE_TLSA,
				TTL:   3600,
				RData: tt.r,
			}
			rrData, err := json.Marshal(rr)
			if err != nil {
				t.Fatalf("json.Marshal(record) error = %v", err)
			}
			if !bytes.Contains(rrData, []byte(`"Type":"TLSA"`)) {
				t.Errorf("json.Marshal(record) = %s, which does not name the TLSA type", rrData)
			}
			var gotRR ResourceRecord
			if err := json.Unmarshal(rrData, &gotRR); err != nil {
				t.Fatalf("json.Unmarshal(record) error = %v", err)
			}
			gotRData, ok := gotRR.RData.(*RecordTLSA)
			if !ok {
				t.Fatalf("RData = %T, want *RecordTLSA", gotRR.RData)
			}
			if !reflect.DeepEqual(*gotRData, tt.r) {
				t.Errorf("RData = %v, want %v", gotRData, tt.r)
			}
		})
	}
}

// The three one-octet fields are also accepted as the decimal strings a JSON
// encoding of a master file may hold.
func TestRecordTLSAUnmarshalJSONFieldStrings(t *testing.T) {
	data := `{"CertificateUsage":"3","Selector":"1","MatchingType":"2","Data":"0102"}`
	var r RecordTLSA
	if err := json.Unmarshal([]byte(data), &r); err != nil {
		t.Fatalf("json.Unmarshal(%s) error = %v", data, err)
	}
	want := RecordTLSA{
		CertificateUsage: TLSACertUsageDomainIssued,
		Selector:         TLSASelectorSPKI,
		MatchingType:     TLSAMatchingSHA512,
		Data:             []byte{0x01, 0x02},
	}
	if !reflect.DeepEqual(r, want) {
		t.Errorf("json.Unmarshal(%s) got = %v, want %v", data, r, want)
	}
}

func TestRecordTLSAUnmarshalJSONErrors(t *testing.T) {
	tests := []struct {
		name string
		data string
	}{
		{
			name: "missing certificate usage",
			data: `{"Selector":1,"MatchingType":1,"Data":"0102"}`,
		},
		{
			name: "certificate usage that is not a number",
			data: `{"CertificateUsage":"CA","Selector":1,"MatchingType":1,"Data":"0102"}`,
		},
		{
			name: "selector of 256",
			data: `{"CertificateUsage":3,"Selector":256,"MatchingType":1,"Data":"0102"}`,
		},
		{
			name: "matching type of a JSON list",
			data: `{"CertificateUsage":3,"Selector":1,"MatchingType":[1],"Data":"0102"}`,
		},
		{
			name: "empty certificate association data",
			data: `{"CertificateUsage":3,"Selector":1,"MatchingType":1,"Data":""}`,
		},
		{
			name: "missing certificate association data",
			data: `{"CertificateUsage":3,"Selector":1,"MatchingType":1}`,
		},
		{
			name: "certificate association data that is not hexadecimal",
			data: `{"CertificateUsage":3,"Selector":1,"MatchingType":1,"Data":"xyzw"}`,
		},
		{
			name: "certificate association data with an odd number of digits",
			data: `{"CertificateUsage":3,"Selector":1,"MatchingType":1,"Data":"abc"}`,
		},
		{
			name: "certificate association data that is not a string",
			data: `{"CertificateUsage":3,"Selector":1,"MatchingType":1,"Data":[1,2]}`,
		},
		{
			name: "certificate association data longer than an RDATA",
			data: `{"CertificateUsage":3,"Selector":1,"MatchingType":1,"Data":"` + strings.Repeat("ab", tlsaMaxDataSize+1) + `"}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var r RecordTLSA
			err := json.Unmarshal([]byte(tt.data), &r)
			if err == nil {
				t.Fatalf("json.Unmarshal(%s) = %v, want an error", tt.data, r)
			}
			if !wantErrNamesRecord(err, "TLSA") {
				t.Errorf("json.Unmarshal(%s) error = %q, which does not name the TLSA record", tt.data, err)
			}
		})
	}
}
