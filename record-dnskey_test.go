package dnsmsg

import (
	"bytes"
	"reflect"
	"testing"
)

func TestParseRecordDNSKEY(t *testing.T) {
	tests := []struct {
		name    string
		input   []byte
		begin   uint32
		want    RecordDNSKEY
		wantPos uint32
		wantErr bool
	}{
		{
			name: "valid DNSKEY record with RSASHA1",
			// Flags=256 (0x0100), Protocol=3, Algorithm=5 (RSASHA1), PublicKey=6 bytes
			input: []byte{0x01, 0x00, 0x03, 0x05, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF},
			begin: 0,
			want: NewRecordDNSKEY(
				256,
				3,
				5,
				[]byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF},
			),
			wantPos: 10,
			wantErr: false,
		},
		{
			name: "valid DNSKEY record with RSASHA256",
			// Flags=256, Protocol=3, Algorithm=8 (RSASHA256), PublicKey=8 bytes
			input: []byte{0x01, 0x00, 0x03, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08},
			begin: 0,
			want: NewRecordDNSKEY(
				256,
				3,
				8,
				[]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08},
			),
			wantPos: 12,
			wantErr: false,
		},
		{
			name: "valid DNSKEY with ZSK flag",
			// Flags=256 (ZSK), Protocol=3, Algorithm=13 (ECDSAP256SHA256)
			input: []byte{0x01, 0x00, 0x03, 0x0D, 0xDE, 0xAD, 0xBE, 0xEF},
			begin: 0,
			want: NewRecordDNSKEY(
				256,
				3,
				13,
				[]byte{0xDE, 0xAD, 0xBE, 0xEF},
			),
			wantPos: 8,
			wantErr: false,
		},
		{
			name: "valid DNSKEY with KSK flag",
			// Flags=257 (KSK), Protocol=3, Algorithm=14 (ECDSAP384SHA384)
			input: []byte{0x01, 0x01, 0x03, 0x0E, 0xCA, 0xFE},
			begin: 0,
			want: NewRecordDNSKEY(
				257,
				3,
				14,
				[]byte{0xCA, 0xFE},
			),
			wantPos: 6,
			wantErr: false,
		},
		{
			name:    "truncated input - missing flags",
			input:   []byte{0x01},
			begin:   0,
			want:    RecordDNSKEY{},
			wantErr: true,
		},
		{
			name:    "truncated input - missing protocol",
			input:   []byte{0x01, 0x00},
			begin:   0,
			want:    RecordDNSKEY{},
			wantErr: true,
		},
		{
			name:    "truncated input - missing algorithm",
			input:   []byte{0x01, 0x00, 0x03},
			begin:   0,
			want:    RecordDNSKEY{},
			wantErr: true,
		},
		{
			name:    "empty public key",
			input:   []byte{0x01, 0x00, 0x03, 0x05},
			begin:   0,
			want:    RecordDNSKEY{},
			wantErr: true,
		},
		{
			name:    "out of bounds begin",
			input:   []byte{0x01, 0x00, 0x03, 0x05, 0xAA},
			begin:   10,
			want:    RecordDNSKEY{},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, pos, err := ParseRecordDNSKEY(tt.input, tt.begin)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseRecordDNSKEY() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ParseRecordDNSKEY() got = %v, want %v", got, tt.want)
			}
			if pos != tt.wantPos {
				t.Errorf("ParseRecordDNSKEY() pos = %v, want %v", pos, tt.wantPos)
			}
		})
	}
}

func TestNewRecordDNSKEYFromString(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    RecordDNSKEY
		wantErr bool
	}{
		{
			name:  "valid DNSKEY with RSASHA1",
			input: "256 3 5 YWJjZGVm", // "abcdef" in base64
			want: NewRecordDNSKEY(
				256,
				3,
				5,
				[]byte{'a', 'b', 'c', 'd', 'e', 'f'},
			),
			wantErr: false,
		},
		{
			name:  "valid DNSKEY with RSASHA256",
			input: "256 3 8 AAECAwQF", // 4 bytes in base64
			want: NewRecordDNSKEY(
				256,
				3,
				8,
				[]byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05},
			),
			wantErr: false,
		},
		{
			name:  "valid DNSKEY with KSK flag",
			input: "257 3 13 Q29yZQ", // "Core" in base64 without padding
			want: NewRecordDNSKEY(
				257,
				3,
				13,
				[]byte{'C', 'o', 'r', 'e'},
			),
			wantErr: false,
		},
		{
			name:  "valid DNSKEY with flags 0",
			input: "0 3 5 dGVzdA", // "test" in base64
			want: NewRecordDNSKEY(
				0,
				3,
				5,
				[]byte{'t', 'e', 's', 't'},
			),
			wantErr: false,
		},
		{
			name:    "invalid format - missing fields",
			input:   "256 3",
			want:    RecordDNSKEY{},
			wantErr: true,
		},
		{
			name:    "invalid format - non-numeric flags",
			input:   "abc 3 5 dGVzdA",
			want:    RecordDNSKEY{},
			wantErr: true,
		},
		{
			name:    "invalid format - non-numeric protocol",
			input:   "256 xyz 5 dGVzdA",
			want:    RecordDNSKEY{},
			wantErr: true,
		},
		{
			name:    "invalid format - non-numeric algorithm",
			input:   "256 3 abc dGVzdA",
			want:    RecordDNSKEY{},
			wantErr: true,
		},
		{
			name:    "invalid format - invalid base64",
			input:   "256 3 5 !!!invalid!!!",
			want:    RecordDNSKEY{},
			wantErr: true,
		},
		{
			name:    "invalid format - empty string",
			input:   "",
			want:    RecordDNSKEY{},
			wantErr: true,
		},
		{
			name:    "invalid format - extra spaces",
			input:   "256  3 5 dGVzdA",
			want:    RecordDNSKEY{},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewRecordDNSKEYFromString(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewRecordDNSKEYFromString() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewRecordDNSKEYFromString() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRecordDNSKEYString(t *testing.T) {
	tests := []struct {
		name  string
		input RecordDNSKEY
		want  string
	}{
		{
			name: "RSASHA1 key",
			input: NewRecordDNSKEY(
				256,
				3,
				5,
				[]byte{'a', 'b', 'c', 'd', 'e', 'f'},
			),
			want: "256 3 5 YWJjZGVm",
		},
		{
			name: "RSASHA256 key",
			input: NewRecordDNSKEY(
				257,
				3,
				8,
				[]byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05},
			),
			want: "257 3 8 AAECAwQF",
		},
		{
			name: "ECDSAP256SHA256 key",
			input: NewRecordDNSKEY(
				256,
				3,
				13,
				[]byte{0xFF, 0xFE, 0xFD, 0xFC},
			),
			want: "256 3 13 //79/A",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.input.String()
			if got != tt.want {
				t.Errorf("RecordDNSKEY.String() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestRecordDNSKEYType(t *testing.T) {
	dnskey := NewRecordDNSKEY(256, 3, 5, []byte{0xAA, 0xBB})
	if dnskey.Type() != TYPE_DNSKEY {
		t.Errorf("RecordDNSKEY.Type() = %v, want %v", dnskey.Type(), TYPE_DNSKEY)
	}
}

func TestRecordDNSKEYCanonicalWireFormat(t *testing.T) {
	dnskey := NewRecordDNSKEY(
		256,
		3,
		5,
		[]byte{0xAA, 0xBB, 0xCC, 0xDD},
	)
	want := []byte{0x01, 0x00, 0x03, 0x05, 0xAA, 0xBB, 0xCC, 0xDD}

	got := dnskey.CanonicalWireFormat()
	if !bytes.Equal(got, want) {
		t.Errorf("RecordDNSKEY.CanonicalWireFormat() = %v, want %v", got, want)
	}
}

func TestRecordDNSKEYRoundTrip(t *testing.T) {
	original := NewRecordDNSKEY(
		256,
		3,
		8,
		[]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A},
	)

	// Serialize to canonical wire format
	wire := original.CanonicalWireFormat()

	// Parse back
	parsed, end, err := ParseRecordDNSKEY(wire, 0)
	if err != nil {
		t.Fatalf("ParseRecordDNSKEY() error = %v", err)
	}
	if end != uint32(len(wire)) {
		t.Errorf("round trip end pos = %v, want %v", end, len(wire))
	}
	if !reflect.DeepEqual(parsed, original) {
		t.Errorf("round trip got = %v, want %v", parsed, original)
	}
}

func TestRecordDNSKEYAppendWireFormat(t *testing.T) {
	dnskey := NewRecordDNSKEY(
		256,
		3,
		5,
		[]byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF},
	)
	db := NewNameCompressionDB()

	var w WireFormat
	size := dnskey.AppendWireFormat(&w, db)
	// 2 (flags) + 1 (protocol) + 1 (algorithm) + 6 (public key) = 10
	if size != 10 {
		t.Errorf("AppendWireFormat() size = %v, want 10", size)
	}

	// Parse back from what we wrote
	got, pos, err := ParseRecordDNSKEY(w, 0)
	if err != nil {
		t.Fatalf("ParseRecordDNSKEY() error = %v", err)
	}
	if pos != size {
		t.Errorf("ParseRecordDNSKEY() pos = %v, want %v", pos, size)
	}
	if !reflect.DeepEqual(got, dnskey) {
		t.Errorf("ParseRecordDNSKEY() got = %v, want %v", got, dnskey)
	}
}

func TestRecordDNSKEYFromStringRoundTrip(t *testing.T) {
	original := "256 3 5 aWJjZGVmZg"

	parsed, err := NewRecordDNSKEYFromString(original)
	if err != nil {
		t.Fatalf("NewRecordDNSKEYFromString() error = %v", err)
	}

	// Convert back to string
	got := parsed.String()
	if got != original {
		t.Errorf("round trip got = %q, want %q", got, original)
	}
}

func TestNewRecordDNSKEY(t *testing.T) {
	dnskey := NewRecordDNSKEY(512, 3, 13, []byte{0x01, 0x02, 0x03})

	if dnskey.Flags != 512 {
		t.Errorf("Flags = %v, want 512", dnskey.Flags)
	}
	if dnskey.Protocol != 3 {
		t.Errorf("Protocol = %v, want 3", dnskey.Protocol)
	}
	if dnskey.Algorithm != 13 {
		t.Errorf("Algorithm = %v, want 13", dnskey.Algorithm)
	}
	if !bytes.Equal(dnskey.PublicKey, []byte{0x01, 0x02, 0x03}) {
		t.Errorf("PublicKey = %v, want %v", dnskey.PublicKey, []byte{0x01, 0x02, 0x03})
	}
}
