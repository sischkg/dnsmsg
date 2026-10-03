package dnsmsg

import (
	"bytes"
	"reflect"
	"testing"
)

func TestParseRecordDS(t *testing.T) {
	tests := []struct {
		name    string
		input   []byte
		begin   uint32
		want    RecordDS
		wantPos uint32
		wantErr bool
	}{
		{
			name:  "valid DS record with SHA-1",
			input: []byte{0x03, 0xE8, 0x05, 0x01, 0x49, 0x54, 0x13, 0x37, 0x25, 0x9A, 0x9C, 0x70, 0x7B, 0x38, 0x9E, 0x22, 0xD1, 0x82, 0x2C, 0x82},
			begin: 0,
			want: NewRecordDS(
				1000,
				5,
				1,
				[]byte{0x49, 0x54, 0x13, 0x37, 0x25, 0x9A, 0x9C, 0x70, 0x7B, 0x38, 0x9E, 0x22, 0xD1, 0x82, 0x2C, 0x82},
			),
			wantPos: 20,
			wantErr: false,
		},
		{
			name:  "valid DS record with SHA-256",
			input: []byte{0x03, 0xE8, 0x08, 0x02, 0x49, 0x54, 0x13, 0x37, 0x25, 0x9A, 0x9C, 0x70, 0x7B, 0x38, 0x9E, 0x22, 0xD1, 0x82, 0x2C, 0x82, 0x49, 0x54, 0x13, 0x37, 0x25, 0x9A, 0x9C, 0x70, 0x7B, 0x38, 0x9E, 0x22, 0xD1, 0x82, 0x2C, 0x82, 0x49, 0x54, 0x13, 0x37, 0x25, 0x9A},
			begin: 0,
			want: NewRecordDS(
				1000,
				8,
				2,
				[]byte{0x49, 0x54, 0x13, 0x37, 0x25, 0x9A, 0x9C, 0x70, 0x7B, 0x38, 0x9E, 0x22, 0xD1, 0x82, 0x2C, 0x82, 0x49, 0x54, 0x13, 0x37, 0x25, 0x9A, 0x9C, 0x70, 0x7B, 0x38, 0x9E, 0x22, 0xD1, 0x82, 0x2C, 0x82, 0x49, 0x54, 0x13, 0x37, 0x25, 0x9A},
			),
			wantPos: 42,
			wantErr: false,
		},
		{
			name:    "truncated input - missing key tag",
			input:   []byte{0x03},
			begin:   0,
			want:    RecordDS{},
			wantErr: true,
		},
		{
			name:    "truncated input - missing algorithm",
			input:   []byte{0x03, 0xE8, 0x05},
			begin:   0,
			want:    RecordDS{},
			wantErr: true,
		},
		{
			name:    "truncated input - missing digest type",
			input:   []byte{0x03, 0xE8, 0x05, 0x01},
			begin:   0,
			want:    RecordDS{},
			wantErr: true,
		},
		{
			name:    "out of bounds begin",
			input:   []byte{0x03, 0xE8, 0x05, 0x01, 0x49},
			begin:   10,
			want:    RecordDS{},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, pos, err := ParseRecordDS(tt.input, tt.begin)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseRecordDS() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ParseRecordDS() got = %v, want %v", got, tt.want)
			}
			if pos != tt.wantPos {
				t.Errorf("ParseRecordDS() pos = %v, want %v", pos, tt.wantPos)
			}
		})
	}
}

func TestNewRecordDSFromString(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    RecordDS
		wantErr bool
	}{
		{
			name:  "valid DS record SHA-1",
			input: "1000 5 1 4954:1337:259a:9c70:7b38:9e22:d182:2c82",
			want: NewRecordDS(
				1000,
				5,
				1,
				[]byte{0x49, 0x54, 0x13, 0x37, 0x25, 0x9A, 0x9C, 0x70, 0x7B, 0x38, 0x9E, 0x22, 0xD1, 0x82, 0x2C, 0x82},
			),
			wantErr: false,
		},
		{
			name:  "valid DS record SHA-256 without colons",
			input: "256 8 2 49541337259a9c707b389e22d1822c8249541337259a9c707b389e22d1822c8249541337259a",
			want: NewRecordDS(
				256,
				8,
				2,
				[]byte{0x49, 0x54, 0x13, 0x37, 0x25, 0x9A, 0x9C, 0x70, 0x7B, 0x38, 0x9E, 0x22, 0xD1, 0x82, 0x2C, 0x82, 0x49, 0x54, 0x13, 0x37, 0x25, 0x9A, 0x9C, 0x70, 0x7B, 0x38, 0x9E, 0x22, 0xD1, 0x82, 0x2C, 0x82, 0x49, 0x54, 0x13, 0x37, 0x25, 0x9A},
			),
			wantErr: false,
		},
		{
			name:  "valid DS record with uppercase hex",
			input: "512 14 4 4954:1337:259A:9C70",
			want: NewRecordDS(
				512,
				14,
				4,
				[]byte{0x49, 0x54, 0x13, 0x37, 0x25, 0x9A, 0x9C, 0x70},
			),
			wantErr: false,
		},
		{
			name:    "invalid format - missing fields",
			input:   "1000 5",
			want:    RecordDS{},
			wantErr: true,
		},
		{
			name:    "invalid format - non-numeric key tag",
			input:   "abc 5 1 49541337",
			want:    RecordDS{},
			wantErr: true,
		},
		{
			name:    "invalid format - non-hex digest",
			input:   "1000 5 1 xyz",
			want:    RecordDS{},
			wantErr: true,
		},
		{
			name:    "invalid format - odd number of hex digits",
			input:   "1000 5 1 495",
			want:    RecordDS{},
			wantErr: true,
		},
		{
			name:    "invalid format - empty string",
			input:   "",
			want:    RecordDS{},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewRecordDSFromString(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewRecordDSFromString() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewRecordDSFromString() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRecordDSString(t *testing.T) {
	tests := []struct {
		name  string
		input RecordDS
		want  string
	}{
		{
			name: "SHA-1 digest",
			input: NewRecordDS(
				1000,
				5,
				1,
				[]byte{0x49, 0x54, 0x13, 0x37, 0x25, 0x9A, 0x9C, 0x70, 0x7B, 0x38, 0x9E, 0x22, 0xD1, 0x82, 0x2C, 0x82},
			),
			want: "1000 5 1 49541337259a9c707b389e22d1822c82",
		},
		{
			name: "SHA-256 digest",
			input: NewRecordDS(
				256,
				8,
				2,
				[]byte{0x00, 0x01, 0x02, 0xFF},
			),
			want: "256 8 2 000102ff",
		},
		{
			name: "single byte digest",
			input: NewRecordDS(
				1,
				1,
				1,
				[]byte{0xAB},
			),
			want: "1 1 1 ab",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.input.String()
			if got != tt.want {
				t.Errorf("RecordDS.String() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestRecordDSType(t *testing.T) {
	ds := NewRecordDS(1000, 5, 1, []byte{0x00})
	if ds.Type() != TYPE_DS {
		t.Errorf("RecordDS.Type() = %v, want %v", ds.Type(), TYPE_DS)
	}
}

func TestRecordDSCanonicalWireFormat(t *testing.T) {
	ds := NewRecordDS(
		1000,
		5,
		1,
		[]byte{0x49, 0x54, 0x13, 0x37},
	)
	want := []byte{0x03, 0xE8, 0x05, 0x01, 0x49, 0x54, 0x13, 0x37}

	got := ds.CanonicalWireFormat()
	if !bytes.Equal(got, want) {
		t.Errorf("RecordDS.CanonicalWireFormat() = %v, want %v", got, want)
	}
}

func TestRecordDSRoundTrip(t *testing.T) {
	original := NewRecordDS(
		1000,
		5,
		1,
		[]byte{0x49, 0x54, 0x13, 0x37, 0x25, 0x9A, 0x9C, 0x70, 0x7B, 0x38, 0x9E, 0x22, 0xD1, 0x82, 0x2C, 0x82},
	)

	// Serialize to canonical wire format
	wire := original.CanonicalWireFormat()

	// Parse back
	parsed, end, err := ParseRecordDS(wire, 0)
	if err != nil {
		t.Fatalf("ParseRecordDS() error = %v", err)
	}
	if end != uint32(len(wire)) {
		t.Errorf("round trip end pos = %v, want %v", end, len(wire))
	}
	if !reflect.DeepEqual(parsed, original) {
		t.Errorf("round trip got = %v, want %v", parsed, original)
	}
}

func TestRecordDSAppendWireFormat(t *testing.T) {
	ds := NewRecordDS(
		1000,
		5,
		1,
		[]byte{0x49, 0x54, 0x13, 0x37, 0x25, 0x9A, 0x9C, 0x70, 0x7B, 0x38, 0x9E, 0x22, 0xD1, 0x82, 0x2C, 0x82},
	)
	db := NewNameCompressionDB()

	var w WireFormat
	size := ds.AppendWireFormat(&w, db)
	// 2 (keyTag) + 1 (algorithm) + 1 (digestType) + 16 (digest) = 20
	if size != 20 {
		t.Errorf("AppendWireFormat() size = %v, want 20", size)
	}

	// Parse back from what we wrote
	got, pos, err := ParseRecordDS(w, 0)
	if err != nil {
		t.Fatalf("ParseRecordDS() error = %v", err)
	}
	if pos != size {
		t.Errorf("ParseRecordDS() pos = %v, want %v", pos, size)
	}
	if !reflect.DeepEqual(got, ds) {
		t.Errorf("ParseRecordDS() got = %v, want %v", got, ds)
	}
}

func TestRecordDSFromStringRoundTrip(t *testing.T) {
	input := "1000 5 1 4954:1337:259a:9c70:7b38:9e22:d182:2c82"
	want := "1000 5 1 49541337259a9c707b389e22d1822c82"

	// Parse from string
	ds, err := NewRecordDSFromString(input)
	if err != nil {
		t.Fatalf("NewRecordDSFromString() error = %v", err)
	}

	// Convert to string
	output := ds.String()
	if output != want {
		t.Errorf("round trip string = %q, want %q", output, want)
	}
}

func TestNewRecordDS(t *testing.T) {
	ds := NewRecordDS(256, 8, 2, []byte{0x01, 0x02, 0x03})

	if ds.KeyTag != 256 {
		t.Errorf("KeyTag = %v, want 256", ds.KeyTag)
	}
	if ds.Algorithm != 8 {
		t.Errorf("Algorithm = %v, want 8", ds.Algorithm)
	}
	if ds.DigestType != 2 {
		t.Errorf("DigestType = %v, want 2", ds.DigestType)
	}
	if !bytes.Equal(ds.Digest, []byte{0x01, 0x02, 0x03}) {
		t.Errorf("Digest = %v, want [0x01, 0x02, 0x03]", ds.Digest)
	}
}

func TestDigestTypeConstants(t *testing.T) {
	if DigestTypeSHA1 != 1 {
		t.Errorf("DigestTypeSHA1 = %v, want 1", DigestTypeSHA1)
	}
	if DigestTypeSHA256 != 2 {
		t.Errorf("DigestTypeSHA256 = %v, want 2", DigestTypeSHA256)
	}
	if DigestTypeGOST94 != 3 {
		t.Errorf("DigestTypeGOST94 = %v, want 3", DigestTypeGOST94)
	}
	if DigestTypeSHA384 != 4 {
		t.Errorf("DigestTypeSHA384 = %v, want 4", DigestTypeSHA384)
	}
}
