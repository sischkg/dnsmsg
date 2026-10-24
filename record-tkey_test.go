package dnsmsg

import (
	"bytes"
	"reflect"
	"testing"
)

// gssAPI is the wire format of "gss-api.", the algorithm name used by most of
// the tests below.
var gssAPI = []byte{
	0x07, 'g', 's', 's', '-', 'a', 'p', 'i', 0x00,
}

func TestParseRecordTKEY(t *testing.T) {
	tests := []struct {
		name    string
		input   []byte
		begin   uint32
		end     uint32
		want    RecordTKEY
		wantPos uint32
		wantErr bool
	}{
		{
			name: "valid TKEY record",
			input: []byte{
				0x07, 'g', 's', 's', '-', 'a', 'p', 'i', 0x00,
				0x65, 0x53, 0xF1, 0x00,
				0x65, 0x53, 0xF6, 0x00,
				0x00, 0x01,
				0x00, 0x00,
				0x00, 0x04,
				0xAA, 0xBB, 0xCC, 0xDD,
				0x00, 0x00,
			},
			begin: 0,
			want: RecordTKEY{
				Algorithm:  testDomainName(t, "gss-api."),
				Inception:  1700000000,
				Expiration: 1700001280,
				Mode:       TKEYModeServerAssignment,
				Error:      TKEYErrorNoError,
				KeyData:    []byte{0xAA, 0xBB, 0xCC, 0xDD},
				OtherData:  []byte{},
			},
			wantPos: 29,
		},
		{
			name: "record at nonzero begin",
			input: []byte{
				0xFF, 0xFF, 0xFF,
				0x00,
				0x65, 0x53, 0xF1, 0x00,
				0x65, 0x53, 0xF6, 0x00,
				0x00, 0x04,
				0x00, 0x00,
				0x00, 0x00,
				0x00, 0x00,
			},
			begin: 3,
			want: RecordTKEY{
				Algorithm:  testDomainName(t, "."),
				Inception:  1700000000,
				Expiration: 1700001280,
				Mode:       TKEYModeResolverAssignment,
				Error:      TKEYErrorNoError,
				KeyData:    []byte{},
				OtherData:  []byte{},
			},
			wantPos: 20,
		},
		{
			name: "record with other data",
			input: []byte{
				0x07, 'g', 's', 's', '-', 'a', 'p', 'i', 0x00,
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x03,
				0x00, 0x15,
				0x00, 0x02,
				0x11, 0x22,
				0x00, 0x03,
				0xDE, 0xAD, 0xBE,
			},
			begin: 0,
			want: RecordTKEY{
				Algorithm: testDomainName(t, "gss-api."),
				Mode:      TKEYModeGSSAPI,
				Error:     TKEYErrorBadAlg,
				KeyData:   []byte{0x11, 0x22},
				OtherData: []byte{0xDE, 0xAD, 0xBE},
			},
			wantPos: 30,
		},
		{
			name: "algorithm name with a compression pointer",
			input: []byte{
				0x07, 'g', 's', 's', '-', 'a', 'p', 'i', 0x00,
				0xC0, 0x00,
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x04,
				0x00, 0x14,
				0x00, 0x00,
				0x00, 0x00,
			},
			begin: 9,
			want: RecordTKEY{
				Algorithm: testDomainName(t, "gss-api."),
				Mode:      TKEYModeResolverAssignment,
				Error:     TKEYErrorBadName,
				KeyData:   []byte{},
				OtherData: []byte{},
			},
			wantPos: 27,
		},
		{
			name: "truncated record",
			input: []byte{
				0x07, 'g', 's', 's', '-', 'a', 'p', 'i', 0x00,
				0x65, 0x53, 0xF1, 0x00,
				0x65, 0x53, 0xF5, 0x00,
				0x00, 0x01,
			},
			begin:   0,
			wantErr: true,
		},
		{
			name: "key data exceeds RDATA",
			input: []byte{
				0x00,
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x01,
				0x00, 0x00,
				0x00, 0x08,
				0xAA, 0xBB,
			},
			begin:   0,
			wantErr: true,
		},
		{
			name: "other data exceeds RDATA",
			input: []byte{
				0x00,
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x01,
				0x00, 0x00,
				0x00, 0x00,
				0x00, 0x04,
				0xAA,
			},
			begin:   0,
			wantErr: true,
		},
		{
			name: "RDATA not filled",
			input: []byte{
				0x00,
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x01,
				0x00, 0x00,
				0x00, 0x00,
				0x00, 0x00,
				0xAA, 0xBB,
			},
			begin:   0,
			wantErr: true,
		},
		{
			name: "end beyond the message",
			input: []byte{
				0x00,
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x01,
				0x00, 0x00,
				0x00, 0x00,
				0x00, 0x00,
			},
			begin:   0,
			end:     20,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			end := tt.end
			if end == 0 {
				end = uint32(len(tt.input))
			}
			w := WireFormat(tt.input)

			got, pos, err := ParseRecordTKEY(w, tt.begin, end)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ParseRecordTKEY() error = %v, wantErr = %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if pos != tt.wantPos {
				t.Errorf("ParseRecordTKEY() pos = %v, want %v", pos, tt.wantPos)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ParseRecordTKEY() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNewRecordTKEYFromString(t *testing.T) {
	tests := []struct {
		input      string
		want       RecordTKEY
		wantString string
	}{
		{
			input: "gss-api. 1700000000 1700001280 SERVER-ASSIGNMENT NOERROR qrvM3Q",
			want: RecordTKEY{
				Algorithm:  testDomainName(t, "gss-api."),
				Inception:  1700000000,
				Expiration: 1700001280,
				Mode:       TKEYModeServerAssignment,
				Error:      TKEYErrorNoError,
				KeyData:    []byte{0xAA, 0xBB, 0xCC, 0xDD},
			},
			wantString: "gss-api. 1700000000 1700001280 SERVER-ASSIGNMENT NOERROR qrvM3Q",
		},
		{
			input: ". 0 0 4 20 ESI 3q2+",
			want: RecordTKEY{
				Algorithm: testDomainName(t, "."),
				Mode:      TKEYModeResolverAssignment,
				Error:     TKEYErrorBadName,
				KeyData:   []byte{0x11, 0x22},
				OtherData: []byte{0xDE, 0xAD, 0xBE},
			},
			wantString: ". 0 0 RESOLVER-ASSIGNMENT BADNAME ESI 3q2+",
		},
		{
			input: "gss-api. 0 0 KEY-DELETION BADALG ",
			want: RecordTKEY{
				Algorithm: testDomainName(t, "gss-api."),
				Mode:      TKEYModeKeyDeletion,
				Error:     TKEYErrorBadAlg,
				KeyData:   []byte{},
			},
			wantString: "gss-api. 0 0 KEY-DELETION BADALG ",
		},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, err := NewRecordTKEYFromString(tt.input)
			if err != nil {
				t.Fatalf("NewRecordTKEYFromString(%q) error = %v", tt.input, err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewRecordTKEYFromString(%q) got = %v, want %v", tt.input, got, tt.want)
			}
			if s := got.String(); s != tt.wantString {
				t.Errorf("String() = %q, want %q", s, tt.wantString)
			}
		})
	}
}

func TestNewRecordTKEYFromStringErrors(t *testing.T) {
	tests := []struct {
		input string
	}{
		{input: ""},
		{input: "gss-api."},
		{input: "gss-api. 1700000000"},
		{input: "gss-api. 1700000000 1700001280"},
		{input: "gss-api. 1700000000 1700001280 SERVER-ASSIGNMENT"},
		{input: "gss-api. notanumber 1700001280 SERVER-ASSIGNMENT NOERROR qrvM3Q"},
		{input: "gss-api. 1700000000 4294967296 SERVER-ASSIGNMENT NOERROR qrvM3Q"},
		{input: "gss-api. 1700000000 1700001280 NO-SUCH-MODE NOERROR qrvM3Q"},
		{input: "gss-api. 1700000000 1700001280 SERVER-ASSIGNMENT NO-SUCH-ERROR qrvM3Q"},
		{input: "gss-api. 1700000000 1700001280 SERVER-ASSIGNMENT NOERROR not base64!"},
		{input: "gss-api. 1700000000 1700001280 SERVER-ASSIGNMENT NOERROR qrvM3Q not base64!"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			if _, err := NewRecordTKEYFromString(tt.input); err == nil {
				t.Errorf("NewRecordTKEYFromString(%q) error = nil, want an error", tt.input)
			}
		})
	}
}

func TestRecordTKEYString(t *testing.T) {
	tests := []struct {
		name string
		r    RecordTKEY
		want string
	}{
		{
			name: "server assignment",
			r: RecordTKEY{
				Algorithm:  testDomainName(t, "gss-api."),
				Inception:  1700000000,
				Expiration: 1700001280,
				Mode:       TKEYModeServerAssignment,
				KeyData:    []byte{0xAA, 0xBB, 0xCC, 0xDD},
			},
			want: "gss-api. 1700000000 1700001280 SERVER-ASSIGNMENT NOERROR qrvM3Q",
		},
		{
			name: "unassigned mode and unnamed error",
			r: RecordTKEY{
				Algorithm: testDomainName(t, "."),
				Mode:      63934,
				Error:     99,
			},
			want: ". 0 0 63934 ERROR99 ",
		},
		{
			name: "other data",
			r: RecordTKEY{
				Algorithm: testDomainName(t, "gss-api."),
				Mode:      TKEYModeGSSAPI,
				Error:     TKEYErrorBadMode,
				OtherData: []byte{0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01},
			},
			want: "gss-api. 0 0 GSS-API BADMODE  3q2+7wAB",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.r.String(); got != tt.want {
				t.Errorf("String() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestTKEYModeString(t *testing.T) {
	tests := []struct {
		mode uint16
		want string
	}{
		{mode: TKEYModeReserved, want: "0"},
		{mode: TKEYModeServerAssignment, want: "SERVER-ASSIGNMENT"},
		{mode: TKEYModeDHExchange, want: "DH-EXCHANGE"},
		{mode: TKEYModeGSSAPI, want: "GSS-API"},
		{mode: TKEYModeResolverAssignment, want: "RESOLVER-ASSIGNMENT"},
		{mode: TKEYModeKeyDeletion, want: "KEY-DELETION"},
		{mode: 6, want: "6"},
		{mode: 63934, want: "63934"},
		{mode: 65535, want: "65535"},
	}

	for _, tt := range tests {
		if got := TKEYModeString(tt.mode); got != tt.want {
			t.Errorf("TKEYModeString(%d) = %q, want %q", tt.mode, got, tt.want)
		}
	}
}

func TestNewTKEYMode(t *testing.T) {
	tests := []struct {
		input   string
		want    uint16
		wantErr bool
	}{
		{input: "SERVER-ASSIGNMENT", want: TKEYModeServerAssignment},
		{input: "DH-EXCHANGE", want: TKEYModeDHExchange},
		{input: "GSS-API", want: TKEYModeGSSAPI},
		{input: "RESOLVER-ASSIGNMENT", want: TKEYModeResolverAssignment},
		{input: "KEY-DELETION", want: TKEYModeKeyDeletion},
		{input: "0", want: 0},
		{input: "65535", want: 65535},
		{input: "server-assignment", wantErr: true},
		{input: "NO-SUCH-MODE", wantErr: true},
		{input: "65536", wantErr: true},
		{input: "", wantErr: true},
	}

	for _, tt := range tests {
		got, err := NewTKEYMode(tt.input)
		if (err != nil) != tt.wantErr {
			t.Errorf("NewTKEYMode(%q) error = %v, wantErr = %v", tt.input, err, tt.wantErr)
		}
		if err == nil && got != tt.want {
			t.Errorf("NewTKEYMode(%q) = %d, want %d", tt.input, got, tt.want)
		}
	}
}

func TestTKEYErrorString(t *testing.T) {
	tests := []struct {
		code uint16
		want string
	}{
		{code: TKEYErrorNoError, want: "NOERROR"},
		{code: TKEYErrorFormErr, want: "FORMERR"},
		{code: TKEYErrorServFail, want: "SERVFAIL"},
		{code: TKEYErrorNameError, want: "NXDOMAIN"},
		{code: TKEYErrorNotImpl, want: "NOTIMP"},
		{code: TKEYErrorRefused, want: "REFUSED"},
		{code: TKEYErrorBadSig, want: "BADSIG"},
		{code: TKEYErrorBadKey, want: "BADKEY"},
		{code: TKEYErrorBadTime, want: "BADTIME"},
		{code: TKEYErrorBadMode, want: "BADMODE"},
		{code: TKEYErrorBadName, want: "BADNAME"},
		{code: TKEYErrorBadAlg, want: "BADALG"},
		{code: 15, want: "ERROR15"},
		{code: 99, want: "ERROR99"},
	}

	for _, tt := range tests {
		if got := TKEYErrorString(tt.code); got != tt.want {
			t.Errorf("TKEYErrorString(%d) = %q, want %q", tt.code, got, tt.want)
		}
	}
}

func TestNewTKEYError(t *testing.T) {
	tests := []struct {
		input   string
		want    uint16
		wantErr bool
	}{
		{input: "NOERROR", want: TKEYErrorNoError},
		{input: "FORMERR", want: TKEYErrorFormErr},
		{input: "NXDOMAIN", want: TKEYErrorNameError},
		{input: "BADMODE", want: TKEYErrorBadMode},
		{input: "BADNAME", want: TKEYErrorBadName},
		{input: "BADALG", want: TKEYErrorBadAlg},
		{input: "ERROR99", want: 99},
		{input: "ERROR65535", want: 65535},
		{input: "0", want: 0},
		{input: "65535", want: 65535},
		{input: "noerror", wantErr: true},
		{input: "NO-SUCH-ERROR", wantErr: true},
		{input: "ERROR", wantErr: true},
		{input: "ERROR65536", wantErr: true},
		{input: "65536", wantErr: true},
		{input: "", wantErr: true},
	}

	for _, tt := range tests {
		got, err := NewTKEYError(tt.input)
		if (err != nil) != tt.wantErr {
			t.Errorf("NewTKEYError(%q) error = %v, wantErr = %v", tt.input, err, tt.wantErr)
		}
		if err == nil && got != tt.want {
			t.Errorf("NewTKEYError(%q) = %d, want %d", tt.input, got, tt.want)
		}
	}
}

func TestNewRecordTKEY(t *testing.T) {
	algorithm := testDomainName(t, "gss-api.")
	keyData := []byte{0xAA, 0xBB, 0xCC, 0xDD}
	otherData := []byte{0x01, 0x02}

	tkey, err := NewRecordTKEY(algorithm, 1700000000, 1700001280, TKEYModeGSSAPI, TKEYErrorBadKey, keyData, otherData)
	if err != nil {
		t.Fatalf("NewRecordTKEY() error = %v", err)
	}
	if tkey.Algorithm.String() != "gss-api." {
		t.Errorf("Algorithm = %q, want %q", tkey.Algorithm.String(), "gss-api.")
	}
	if tkey.Inception != 1700000000 || tkey.Expiration != 1700001280 {
		t.Errorf("Inception, Expiration = %d, %d, want 1700000000, 1700001280", tkey.Inception, tkey.Expiration)
	}
	if tkey.Mode != TKEYModeGSSAPI || tkey.Error != TKEYErrorBadKey {
		t.Errorf("Mode, Error = %d, %d, want %d, %d", tkey.Mode, tkey.Error, TKEYModeGSSAPI, TKEYErrorBadKey)
	}
	if !bytes.Equal(tkey.KeyData, keyData) || !bytes.Equal(tkey.OtherData, otherData) {
		t.Errorf("KeyData, OtherData = %v, %v, want %v, %v", tkey.KeyData, tkey.OtherData, keyData, otherData)
	}

	if _, err := NewRecordTKEY(algorithm, 0, 0, 0, 0, make([]byte, 1<<16), nil); err == nil {
		t.Error("NewRecordTKEY() error = nil for key data of 65536 octets, want an error")
	}
	if _, err := NewRecordTKEY(algorithm, 0, 0, 0, 0, nil, make([]byte, 1<<16)); err == nil {
		t.Error("NewRecordTKEY() error = nil for other data of 65536 octets, want an error")
	}
}

func TestRecordTKEYWireFormatRoundTrip(t *testing.T) {
	original := RecordTKEY{
		Algorithm:  testDomainName(t, "GSS-API.Example."),
		Inception:  1700000000,
		Expiration: 1700001280,
		Mode:       TKEYModeGSSAPI,
		Error:      TKEYErrorBadMode,
		KeyData:    []byte{0xAA, 0xBB, 0xCC, 0xDD},
		OtherData:  []byte{0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01},
	}

	// The algorithm name must be written in full even though an unrelated name
	// is available for compression.
	db := NewNameCompressionDB()
	db.AddDomainName(testDomainName(t, "example."), 12)

	var w WireFormat
	size := original.AppendWireFormat(&w, db)
	if size != uint32(len(w)) {
		t.Errorf("AppendWireFormat() size = %v, want %v", size, len(w))
	}

	got, pos, err := ParseRecordTKEY(w, 0, uint32(len(w)))
	if err != nil {
		t.Fatalf("ParseRecordTKEY() error = %v", err)
	}
	if pos != size {
		t.Errorf("ParseRecordTKEY() pos = %v, want %v", pos, size)
	}
	if !reflect.DeepEqual(got, original) {
		t.Errorf("ParseRecordTKEY() got = %v, want %v", got, original)
	}

	// The name is uncompressed, so the record begins with the name itself.
	if !bytes.HasPrefix(w, []byte{
		0x07, 'G', 'S', 'S', '-', 'A', 'P', 'I',
		0x07, 'E', 'x', 'a', 'm', 'p', 'l', 'e', 0x00,
	}) {
		t.Errorf("AppendWireFormat() wrote a compressed or damaged algorithm name: %v", w)
	}

	canonical := original.CanonicalWireFormat()
	var cw WireFormat
	cSize := original.AppendCanonicalWireFormat(&cw)
	if cSize != uint32(len(cw)) {
		t.Errorf("AppendCanonicalWireFormat() size = %v, want %v", cSize, len(cw))
	}
	if !bytes.Equal(canonical, cw) {
		t.Errorf("CanonicalWireFormat() = %v, want %v", canonical, cw)
	}
	if !bytes.HasPrefix(cw, []byte{
		0x07, 'g', 's', 's', '-', 'a', 'p', 'i',
		0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x00,
	}) {
		t.Errorf("AppendCanonicalWireFormat() did not lower-case the algorithm name: %v", cw)
	}
	if bytes.Equal(canonical, w) {
		t.Errorf("CanonicalWireFormat() is not lower-cased: %v", canonical)
	}
}

func TestParseResourceRecordTKEY(t *testing.T) {
	// A TKEY record in a message: CLASS is ANY and TTL is zero.
	var w WireFormat
	w.AppendDomainName(testDomainName(t, "example.com."), nil)
	w.AppendUInt16(uint16(TYPE_TKEY))
	w.AppendUInt16(uint16(CLASS_ANY))
	w.AppendUInt32(0)
	rdataLen := uint32(len(gssAPI)) + 4 + 4 + 2 + 2 + 2 + 4 + 2 + 3
	w.AppendUInt16(uint16(rdataLen))
	w.AppendBytes(gssAPI)
	w.AppendUInt32(1700000000)
	w.AppendUInt32(1700001280)
	w.AppendUInt16(TKEYModeServerAssignment)
	w.AppendUInt16(TKEYErrorNoError)
	w.AppendUInt16(4)
	w.AppendBytes([]byte{0xAA, 0xBB, 0xCC, 0xDD})
	w.AppendUInt16(3)
	w.AppendBytes([]byte{0xDE, 0xAD, 0xBE})

	rr, pos, err := ParseResourceRecord(w, 0)
	if err != nil {
		t.Fatalf("ParseResourceRecord() error = %v", err)
	}
	if pos != uint32(len(w)) {
		t.Errorf("ParseResourceRecord() pos = %v, want %v", pos, len(w))
	}
	if rr.Class != CLASS_ANY {
		t.Errorf("Class = %v, want CLASS_ANY", rr.Class)
	}
	if rr.Type != TYPE_TKEY {
		t.Errorf("Type = %v, want TYPE_TKEY", rr.Type)
	}
	if rr.TTL != 0 {
		t.Errorf("TTL = %v, want 0", rr.TTL)
	}
	tkey, ok := rr.RData.(RecordTKEY)
	if !ok {
		t.Fatalf("RData = %T, want RecordTKEY", rr.RData)
	}
	if tkey.String() != "gss-api. 1700000000 1700001280 SERVER-ASSIGNMENT NOERROR qrvM3Q 3q2+" {
		t.Errorf("RData.String() = %q", tkey.String())
	}

	// The record type name and the TKEY type code round-trip.
	if TYPE_TKEY.String() != "TKEY" {
		t.Errorf("TYPE_TKEY.String() = %q, want %q", TYPE_TKEY.String(), "TKEY")
	}
	if n, err := NewType("TKEY"); err != nil || n != TYPE_TKEY {
		t.Errorf("NewType(%q) = %v, %v, want TYPE_TKEY, nil", "TKEY", n, err)
	}
}
