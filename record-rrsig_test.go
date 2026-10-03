package dnsmsg

import (
	"bytes"
	"reflect"
	"testing"
)

// buildRRSIGWire builds the wire format for an RRSIG RDATA with given fields.
func buildRRSIGWire(t *testing.T, typeCovered uint16, algorithm, labels uint8, origTTL, expiration, inception uint32, keyTag uint16, signersName Domainname, signature []byte) WireFormat {
	t.Helper()
	var w WireFormat
	w.AppendUInt16(typeCovered)
	w.AppendUInt8(algorithm)
	w.AppendUInt8(labels)
	w.AppendUInt32(origTTL)
	w.AppendUInt32(expiration)
	w.AppendUInt32(inception)
	w.AppendUInt16(keyTag)
	w.AppendDomainname(signersName, nil)
	w.AppendBytes(signature)
	return w
}

func TestParseRecordRRSIG(t *testing.T) {
	signersName := Domainname{{'n', 's', '1'}, {'e', 'x', 'a', 'm', 'p', 'l', 'e'}, {'c', 'o', 'm'}}
	signature := []byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x01, 0x02}

	tests := []struct {
		name    string
		input   []byte
		begin   uint32
		want    RecordRRSIG
		wantPos uint32
		wantErr bool
	}{
		{
			name: "standard RRSIG record with TYPE_A",
			input: func() []byte {
				return buildRRSIGWire(t, 1, 5, 3, 3600, 1700000000, 1690000000, 12345, signersName, signature)
			}(),
			begin:   0,
			want:    NewRecordRRSIG(1, 5, 3, 3600, 1700000000, 1690000000, 12345, signersName, signature),
			wantPos: 43, // 18 (fixed) + 17 (ns1.example.com) + 8 (signature)
			wantErr: false,
		},
		{
			name: "RRSIG record with TYPE_NS and 16-byte signature",
			input: func() []byte {
				sig := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10}
				return buildRRSIGWire(t, 2, 8, 2, 7200, 1710000000, 1700000000, 512, signersName, sig)
			}(),
			begin:   0,
			want: NewRecordRRSIG(2, 8, 2, 7200, 1710000000, 1700000000, 512, signersName,
				[]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10}),
			wantPos: 51, // 18 + 17 + 16
			wantErr: false,
		},
		{
			name: "RRSIG with root signers name",
			input: func() []byte {
				root := Domainname{}
				sig := []byte{0xDE, 0xAD, 0xBE, 0xEF}
				return buildRRSIGWire(t, 6, 5, 1, 600, 1700000000, 1690000000, 256, root, sig)
			}(),
			begin:   0,
			want:    NewRecordRRSIG(6, 5, 1, 600, 1700000000, 1690000000, 256, Domainname{}, []byte{0xDE, 0xAD, 0xBE, 0xEF}),
			wantPos: 23, // 18 + 1 (root) + 4
			wantErr: false,
		},
		{
			name:    "truncated input - missing type-covered",
			input:   []byte{0x00},
			begin:   0,
			want:    RecordRRSIG{},
			wantErr: true,
		},
		{
			name:    "truncated input - missing algorithm",
			input:   []byte{0x00, 0x01},
			begin:   0,
			want:    RecordRRSIG{},
			wantErr: true,
		},
		{
			name:    "truncated input - missing key-tag",
			input:   []byte{0x00, 0x01, 0x05, 0x03, 0x00, 0x00, 0x0E, 0x10, 0x65, 0x53, 0xF1, 0x00, 0x64, 0xBB, 0x5A, 0x80, 0x30},
			begin:   0,
			want:    RecordRRSIG{},
			wantErr: true,
		},
		{
			name:    "truncated input - missing signers name",
			input:   []byte{0x00, 0x01, 0x05, 0x03, 0x00, 0x00, 0x0E, 0x10, 0x65, 0x53, 0xF1, 0x00, 0x64, 0xBB, 0x5A, 0x80, 0x30, 0x39},
			begin:   0,
			want:    RecordRRSIG{},
			wantErr: true,
		},
		{
			name:    "truncated input - empty signature",
			input:   []byte{0x00, 0x01, 0x05, 0x03, 0x00, 0x00, 0x0E, 0x10, 0x65, 0x53, 0xF1, 0x00, 0x64, 0xBB, 0x5A, 0x80, 0x30, 0x39, 0x00},
			begin:   0,
			want:    RecordRRSIG{},
			wantErr: true,
		},
		{
			name:    "out of bounds begin",
			begin:   100,
			input:   buildRRSIGWire(t, 1, 5, 3, 3600, 1700000000, 1690000000, 12345, signersName, signature),
			want:    RecordRRSIG{},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, pos, err := ParseRecordRRSIG(tt.input, tt.begin)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseRecordRRSIG() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if !reflect.DeepEqual(got, tt.want) {
					t.Errorf("ParseRecordRRSIG() got = %+v, want %+v", got, tt.want)
				}
				if pos != tt.wantPos {
					t.Errorf("ParseRecordRRSIG() pos = %v, want %v", pos, tt.wantPos)
				}
			}
		})
	}
}

func TestNewRecordRRSIGFromString(t *testing.T) {
	signersName := Domainname{{'n', 's', '1'}, {'e', 'x', 'a', 'm', 'p', 'l', 'e'}, {'c', 'o', 'm'}}
	signature := []byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x01, 0x02}

	tests := []struct {
		name    string
		input   string
		want    RecordRRSIG
		wantErr bool
	}{
		{
			name:    "valid RRSIG with numeric type-covered (A=1)",
			input:   "1 5 3 3600 1700000000 1690000000 12345 ns1.example.com. qrvM3e7/AQI",
			want:    NewRecordRRSIG(1, 5, 3, 3600, 1700000000, 1690000000, 12345, signersName, signature),
			wantErr: false,
		},
		{
			name:    "valid RRSIG with named type-covered (NS)",
			input:   "NS 8 2 7200 1710000000 1700000000 512 ns1.example.com. AQIDBAUGBwgJCgsMDQ4PEA",
			want:    NewRecordRRSIG(2, 8, 2, 7200, 1710000000, 1700000000, 512, signersName, []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10}),
			wantErr: false,
		},
		{
			name:    "valid RRSIG with root signers name",
			input:   "6 5 1 600 1700000000 1690000000 256 . 3q2+7w",
			want:    NewRecordRRSIG(6, 5, 1, 600, 1700000000, 1690000000, 256, Domainname{}, []byte{0xDE, 0xAD, 0xBE, 0xEF}),
			wantErr: false,
		},
		{
			name:    "valid RRSIG with TYPE48 (DNSKEY)",
			input:   "TYPE48 5 3 3600 1700000000 1690000000 12345 ns1.example.com. qrvM3e7/AQI",
			want:    NewRecordRRSIG(48, 5, 3, 3600, 1700000000, 1690000000, 12345, signersName, signature),
			wantErr: false,
		},
		{
			name:    "invalid format - missing fields",
			input:   "1 5 3",
			want:    RecordRRSIG{},
			wantErr: true,
		},
		{
			name:    "invalid format - non-numeric algorithm",
			input:   "1 abc 3 3600 1700000000 1690000000 12345 ns1.example.com. qrvM3e7/AQI",
			want:    RecordRRSIG{},
			wantErr: true,
		},
		{
			name:    "invalid format - non-numeric labels",
			input:   "1 5 xyz 3600 1700000000 1690000000 12345 ns1.example.com. qrvM3e7/AQI",
			want:    RecordRRSIG{},
			wantErr: true,
		},
		{
			name:    "invalid format - non-numeric orig-ttl",
			input:   "1 5 3 abc 1700000000 1690000000 12345 ns1.example.com. qrvM3e7/AQI",
			want:    RecordRRSIG{},
			wantErr: true,
		},
		{
			name:    "invalid format - non-numeric key-tag",
			input:   "1 5 3 3600 1700000000 1690000000 abc ns1.example.com. qrvM3e7/AQI",
			want:    RecordRRSIG{},
			wantErr: true,
		},
		{
			name:    "invalid format - invalid base64 signature",
			input:   "1 5 3 3600 1700000000 1690000000 12345 ns1.example.com. !!!invalid!!!",
			want:    RecordRRSIG{},
			wantErr: true,
		},
		{
			name:    "invalid format - empty string",
			input:   "",
			want:    RecordRRSIG{},
			wantErr: true,
		},
		{
			name:    "invalid format - extra spaces",
			input:   "1  5 3 3600 1700000000 1690000000 12345 ns1.example.com. qrvM3e7/AQI",
			want:    RecordRRSIG{},
			wantErr: true,
		},
		{
			name:    "invalid format - invalid signers name",
			input:   "1 5 3 3600 1700000000 1690000000 12345 ns1..example.com. qrvM3e7/AQI",
			want:    RecordRRSIG{},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewRecordRRSIGFromString(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewRecordRRSIGFromString() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewRecordRRSIGFromString() got = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestRecordRRSIGString(t *testing.T) {
	signersName := Domainname{{'n', 's', '1'}, {'e', 'x', 'a', 'm', 'p', 'l', 'e'}, {'c', 'o', 'm'}}

	tests := []struct {
		name  string
		input RecordRRSIG
		want  string
	}{
		{
			name:  "standard RRSIG with TYPE_A",
			input: NewRecordRRSIG(1, 5, 3, 3600, 1700000000, 1690000000, 12345, signersName, []byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x01, 0x02}),
			want:  "A 5 3 3600 1700000000 1690000000 12345 ns1.example.com. qrvM3e7/AQI",
		},
		{
			name:  "RRSIG with TYPE_NS",
			input: NewRecordRRSIG(2, 8, 2, 7200, 1710000000, 1700000000, 512, signersName, []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10}),
			want:  "NS 8 2 7200 1710000000 1700000000 512 ns1.example.com. AQIDBAUGBwgJCgsMDQ4PEA",
		},
		{
			name:  "RRSIG with root signers name",
			input: NewRecordRRSIG(6, 5, 1, 600, 1700000000, 1690000000, 256, Domainname{}, []byte{0xDE, 0xAD, 0xBE, 0xEF}),
			want:  "SOA 5 1 600 1700000000 1690000000 256 . 3q2+7w",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.input.String()
			if got != tt.want {
				t.Errorf("RecordRRSIG.String() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestRecordRRSIGType(t *testing.T) {
	rrsig := NewRecordRRSIG(1, 5, 3, 3600, 1700000000, 1690000000, 12345, Domainname{}, []byte{0xAA})
	if rrsig.Type() != TYPE_RRSIG {
		t.Errorf("RecordRRSIG.Type() = %v, want %v", rrsig.Type(), TYPE_RRSIG)
	}
}

func TestRecordRRSIGCanonicalWireFormat(t *testing.T) {
	signersName := Domainname{{'N', 'S', '1'}, {'E', 'X', 'A', 'M', 'P', 'L', 'E'}, {'C', 'O', 'M'}}
	rrsig := NewRecordRRSIG(
		1, 5, 3, 3600, 1700000000, 1690000000, 12345,
		signersName,
		[]byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x01, 0x02},
	)
	want := []byte{
		// TypeCovered = 1
		0x00, 0x01,
		// Algorithm = 5, Labels = 3
		0x05, 0x03,
		// OrigTTL = 3600
		0x00, 0x00, 0x0E, 0x10,
		// Expiration = 1700000000
		0x65, 0x53, 0xF1, 0x00,
		// Inception = 1690000000
		0x64, 0xBB, 0x5A, 0x80,
		// KeyTag = 12345
		0x30, 0x39,
		// SignersName: ns1.example.com (lowercase, canonical)
		3, 'n', 's', '1', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0,
		// Signature
		0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x01, 0x02,
	}

	got := rrsig.CanonicalWireFormat()
	if !bytes.Equal(got, want) {
		t.Errorf("RecordRRSIG.CanonicalWireFormat() = %v, want %v", got, want)
	}
}

func TestRecordRRSIGRoundTrip(t *testing.T) {
	signersName := Domainname{{'n', 's', '1'}, {'e', 'x', 'a', 'm', 'p', 'l', 'e'}, {'c', 'o', 'm'}}
	original := NewRecordRRSIG(
		46, 8, 4, 86400, 1710000000, 1700000000, 9876,
		signersName,
		[]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A},
	)

	// Serialize to canonical wire format
	wire := original.CanonicalWireFormat()

	// Parse back
	parsed, end, err := ParseRecordRRSIG(wire, 0)
	if err != nil {
		t.Fatalf("ParseRecordRRSIG() error = %v", err)
	}
	if end != uint32(len(wire)) {
		t.Errorf("round trip end pos = %v, want %v", end, len(wire))
	}
	if !reflect.DeepEqual(parsed, original) {
		t.Errorf("round trip got = %+v, want %+v", parsed, original)
	}
}

func TestRecordRRSIGAppendWireFormat(t *testing.T) {
	signersName := Domainname{{'n', 's', '1'}, {'e', 'x', 'a', 'm', 'p', 'l', 'e'}, {'c', 'o', 'm'}}
	rrsig := NewRecordRRSIG(
		1, 5, 3, 3600, 1700000000, 1690000000, 12345,
		signersName,
		[]byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x01, 0x02},
	)
	db := NewNameCompressionDB()

	var w WireFormat
	size := rrsig.AppendWireFormat(&w, db)
	// 18 (fixed) + 17 (ns1.example.com) + 8 (signature) = 43
	if size != 43 {
		t.Errorf("AppendWireFormat() size = %v, want 43", size)
	}

	// Parse back from what we wrote
	got, pos, err := ParseRecordRRSIG(w, 0)
	if err != nil {
		t.Fatalf("ParseRecordRRSIG() error = %v", err)
	}
	if pos != size {
		t.Errorf("ParseRecordRRSIG() pos = %v, want %v", pos, size)
	}
	if !reflect.DeepEqual(got, rrsig) {
		t.Errorf("AppendWireFormat -> ParseRecordRRSIG round trip: got = %+v, want %+v", got, rrsig)
	}
}

func TestRecordRRSIGFromStringRoundTrip(t *testing.T) {
	input := "A 5 3 3600 1700000000 1690000000 12345 ns1.example.com. qrvM3e7/AQI"

	parsed, err := NewRecordRRSIGFromString(input)
	if err != nil {
		t.Fatalf("NewRecordRRSIGFromString() error = %v", err)
	}

	// Convert back to string
	got := parsed.String()
	if got != input {
		t.Errorf("round trip got = %q, want %q", got, input)
	}
}

func TestNewRecordRRSIG(t *testing.T) {
	signersName := Domainname{{'n', 's'}, {'d', 'n', 's'}}
	rrsig := NewRecordRRSIG(
		46, 13, 4, 86400, 1710000000, 1700000000, 1234,
		signersName,
		[]byte{0xFF, 0xEE, 0xDD},
	)

	if rrsig.TypeCovered != 46 {
		t.Errorf("TypeCovered = %v, want 46", rrsig.TypeCovered)
	}
	if rrsig.Algorithm != 13 {
		t.Errorf("Algorithm = %v, want 13", rrsig.Algorithm)
	}
	if rrsig.Labels != 4 {
		t.Errorf("Labels = %v, want 4", rrsig.Labels)
	}
	if rrsig.OrigTTL != 86400 {
		t.Errorf("OrigTTL = %v, want 86400", rrsig.OrigTTL)
	}
	if rrsig.Expiration != 1710000000 {
		t.Errorf("Expiration = %v, want 1710000000", rrsig.Expiration)
	}
	if rrsig.Inception != 1700000000 {
		t.Errorf("Inception = %v, want 1700000000", rrsig.Inception)
	}
	if rrsig.KeyTag != 1234 {
		t.Errorf("KeyTag = %v, want 1234", rrsig.KeyTag)
	}
	if !bytes.Equal(rrsig.Signature, []byte{0xFF, 0xEE, 0xDD}) {
		t.Errorf("Signature = %v, want %v", rrsig.Signature, []byte{0xFF, 0xEE, 0xDD})
	}
}

// Test that using compression DB results in shorter wire format for the signers name
func TestRecordRRSIGCompression(t *testing.T) {
	signersName := Domainname{{'n', 's', '1'}, {'e', 'x', 'a', 'm', 'p', 'l', 'e'}, {'c', 'o', 'm'}}
	rrsig1 := NewRecordRRSIG(
		1, 5, 3, 3600, 1700000000, 1690000000, 12345,
		signersName,
		[]byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x01, 0x02},
	)
	rrsig2 := NewRecordRRSIG(
		2, 8, 2, 7200, 1710000000, 1700000000, 512,
		signersName,
		[]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08},
	)

	db := NewNameCompressionDB()

	// Build uncompressed wire format for each record to verify sizes
	var w1, w2 WireFormat
	sizeNoCompress1 := rrsig1.AppendWireFormat(&w1, nil)
	sizeNoCompress2 := rrsig2.AppendWireFormat(&w2, nil)

	// Build with compression: the second RRSIG should be shorter
	db.Reset()
	var w WireFormat
	size1 := rrsig1.AppendWireFormat(&w, db)
	size2 := rrsig2.AppendWireFormat(&w, db)

	// First record should be the same size as uncompressed
	if size1 != sizeNoCompress1 {
		t.Errorf("first AppendWireFormat size = %v, want %v", size1, sizeNoCompress1)
	}
	// Second record should be shorter due to compression of signers name
	if size2 >= sizeNoCompress2 {
		t.Errorf("compressed second RRSIG size (%d) should be smaller than uncompressed (%d)", size2, sizeNoCompress2)
	}

	// Parse using uncompressed wire format (RRSIG signature has no explicit length field,
	// so parsing compressed RRSIG concatenated with other data is unreliable without RDLEN)
	got1, _, err := ParseRecordRRSIG(w1, 0)
	if err != nil {
		t.Fatalf("ParseRecordRRSIG() first error = %v", err)
	}
	if !reflect.DeepEqual(got1, rrsig1) {
		t.Errorf("first parsed RRSIG mismatch: got %+v, want %+v", got1, rrsig1)
	}

	got2, _, err := ParseRecordRRSIG(w2, 0)
	if err != nil {
		t.Fatalf("ParseRecordRRSIG() second error = %v", err)
	}
	if !reflect.DeepEqual(got2, rrsig2) {
		t.Errorf("second parsed RRSIG mismatch: got %+v, want %+v", got2, rrsig2)
	}
}
