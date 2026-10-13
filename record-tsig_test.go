package dnsmsg

import (
	"bytes"
	"reflect"
	"testing"
)

// hmacSHA256 is the wire format of "hmac-sha256.", the algorithm name used by
// most of the tests below.
var hmacSHA256 = []byte{
	0x0b, 'h', 'm', 'a', 'c', '-', 's', 'h', 'a', '2', '5', '6', 0x00,
}

func TestParseRecordTSIG(t *testing.T) {
	tests := []struct {
		name    string
		input   []byte
		begin   uint32
		end     uint32
		want    RecordTSIG
		wantPos uint32
		wantErr bool
	}{
		{
			name: "valid TSIG record",
			input: []byte{
				0x0b, 'h', 'm', 'a', 'c', '-', 's', 'h', 'a', '2', '5', '6', 0x00,
				0x00, 0x00, 0x65, 0x53, 0xF1, 0x00,
				0x01, 0x2C,
				0x00, 0x04,
				0xAA, 0xBB, 0xCC, 0xDD,
				0x04, 0xD2,
				0x00, 0x00,
				0x00, 0x00,
			},
			begin: 0,
			end:   0,
			want: RecordTSIG{
				Algorithm:  testDomainName(t, "hmac-sha256."),
				TimeSigned: 1700000000,
				Fudge:      300,
				MAC:        []byte{0xAA, 0xBB, 0xCC, 0xDD},
				OriginalID: 1234,
				Error:      TSIGErrorNoError,
				OtherData:  []byte{},
			},
			wantPos: 33,
			wantErr: false,
		},
		{
			name: "valid TSIG record with BADTRUNC and other data",
			input: []byte{
				0x0b, 'h', 'm', 'a', 'c', '-', 's', 'h', 'a', '2', '5', '6', 0x00,
				0x00, 0x00, 0x65, 0x53, 0xF1, 0x00,
				0x01, 0x2C,
				0x00, 0x04,
				0xAA, 0xBB, 0xCC, 0xDD,
				0x04, 0xD2,
				0x00, 0x16,
				0x00, 0x06,
				0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01,
			},
			begin: 0,
			end:   0,
			want: RecordTSIG{
				Algorithm:  testDomainName(t, "hmac-sha256."),
				TimeSigned: 1700000000,
				Fudge:      300,
				MAC:        []byte{0xAA, 0xBB, 0xCC, 0xDD},
				OriginalID: 1234,
				Error:      TSIGErrorBadTrunc,
				OtherData:  []byte{0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01},
			},
			wantPos: 39,
			wantErr: false,
		},
		{
			name: "valid TSIG record with an empty MAC",
			input: []byte{
				0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00,
				0x00, 0x00,
				0x00, 0x00,
				0x00, 0x00,
				0x00, 0x00,
			},
			begin: 0,
			end:   0,
			want: RecordTSIG{
				Algorithm:  NewRootDomainName(),
				TimeSigned: 0,
				Fudge:      0,
				MAC:        []byte{},
				OriginalID: 0,
				Error:      TSIGErrorNoError,
				OtherData:  []byte{},
			},
			wantPos: 17,
			wantErr: false,
		},
		{
			name: "algorithm name read from a compression pointer",
			input: []byte{
				0x03, 'n', 's', '1', 0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x00,
				0xC0, 0x00,
				0x00, 0x00, 0x65, 0x53, 0xF1, 0x00,
				0x01, 0x2C,
				0x00, 0x04,
				0xAA, 0xBB, 0xCC, 0xDD,
				0x04, 0xD2,
				0x00, 0x00,
				0x00, 0x00,
			},
			begin: 13,
			end:   0,
			want: RecordTSIG{
				Algorithm:  testDomainName(t, "ns1.example."),
				TimeSigned: 1700000000,
				Fudge:      300,
				MAC:        []byte{0xAA, 0xBB, 0xCC, 0xDD},
				OriginalID: 1234,
				Error:      TSIGErrorNoError,
				OtherData:  []byte{},
			},
			wantPos: 35,
			wantErr: false,
		},
		{
			name: "TSIG record at a nonzero begin",
			input: []byte{
				0xFF, 0xFF, 0xFF,
				0x0b, 'h', 'm', 'a', 'c', '-', 's', 'h', 'a', '2', '5', '6', 0x00,
				0x00, 0x00, 0x65, 0x53, 0xF1, 0x00,
				0x01, 0x2C,
				0x00, 0x04,
				0xAA, 0xBB, 0xCC, 0xDD,
				0x04, 0xD2,
				0x00, 0x00,
				0x00, 0x00,
				0xFF, 0xFF, 0xFF,
			},
			begin: 3,
			end:   36,
			want: RecordTSIG{
				Algorithm:  testDomainName(t, "hmac-sha256."),
				TimeSigned: 1700000000,
				Fudge:      300,
				MAC:        []byte{0xAA, 0xBB, 0xCC, 0xDD},
				OriginalID: 1234,
				Error:      TSIGErrorNoError,
				OtherData:  []byte{},
			},
			wantPos: 36,
			wantErr: false,
		},
		{
			name:    "RDATA shorter than the shortest TSIG record",
			input:   []byte{0x01, 0x00, 0x00, 0x00},
			begin:   0,
			end:     4,
			want:    RecordTSIG{},
			wantPos: 0,
			wantErr: true,
		},
		{
			name:    "end beyond the end of the message",
			input:   []byte{0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			begin:   0,
			end:     9,
			want:    RecordTSIG{},
			wantPos: 0,
			wantErr: true,
		},
		{
			name:    "unterminated algorithm name",
			input:   []byte{0x0b, 'h', 'm', 'a', 'c', '-', 's', 'h', 'a', '2', '5', '6', 0x05, 'x', 'y', 'z', 'w', 'v'},
			begin:   0,
			end:     0,
			want:    RecordTSIG{},
			wantPos: 0,
			wantErr: true,
		},
		{
			name:    "truncated before the time signed",
			input:   []byte{0x0b, 'h', 'm', 'a', 'c', '-', 's', 'h', 'a', '2', '5', '6', 0x00, 0x00, 0x00, 0x00, 0x65, 0x52},
			begin:   0,
			end:     0,
			want:    RecordTSIG{},
			wantPos: 0,
			wantErr: true,
		},
		{
			name:    "truncated before the MAC size",
			input:   []byte{0x0b, 'h', 'm', 'a', 'c', '-', 's', 'h', 'a', '2', '5', '6', 0x00, 0x00, 0x00, 0x65, 0x53, 0xF1, 0x00, 0x01, 0x2C},
			begin:   0,
			end:     0,
			want:    RecordTSIG{},
			wantPos: 0,
			wantErr: true,
		},
		{
			name:    "MAC truncated by the end of the RDATA",
			input:   []byte{0x0b, 'h', 'm', 'a', 'c', '-', 's', 'h', 'a', '2', '5', '6', 0x00, 0x00, 0x00, 0x65, 0x53, 0xF1, 0x00, 0x01, 0x2C, 0x00, 0x04, 0xAA, 0xBB},
			begin:   0,
			end:     0,
			want:    RecordTSIG{},
			wantPos: 0,
			wantErr: true,
		},
		{
			name:    "MAC length exceeds the RDATA",
			input:   []byte{0x0b, 'h', 'm', 'a', 'c', '-', 's', 'h', 'a', '2', '5', '6', 0x00, 0x00, 0x00, 0x65, 0x53, 0xF1, 0x00, 0x01, 0x2C, 0xFF, 0xFF},
			begin:   0,
			end:     0,
			want:    RecordTSIG{},
			wantPos: 0,
			wantErr: true,
		},
		{
			name:    "truncated before the other data length",
			input:   []byte{0x0b, 'h', 'm', 'a', 'c', '-', 's', 'h', 'a', '2', '5', '6', 0x00, 0x00, 0x00, 0x65, 0x53, 0xF1, 0x00, 0x01, 0x2C, 0x00, 0x04, 0xAA, 0xBB, 0xCC, 0xDD, 0x04, 0xD2, 0x00, 0x00},
			begin:   0,
			end:     0,
			want:    RecordTSIG{},
			wantPos: 0,
			wantErr: true,
		},
		{
			name:    "other data length exceeds the RDATA",
			input:   []byte{0x0b, 'h', 'm', 'a', 'c', '-', 's', 'h', 'a', '2', '5', '6', 0x00, 0x00, 0x00, 0x65, 0x53, 0xF1, 0x00, 0x01, 0x2C, 0x00, 0x04, 0xAA, 0xBB, 0xCC, 0xDD, 0x04, 0xD2, 0x00, 0x07, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06},
			begin:   0,
			end:     0,
			want:    RecordTSIG{},
			wantPos: 0,
			wantErr: true,
		},
		{
			name:    "octets left over after the other data",
			input:   []byte{0x0b, 'h', 'm', 'a', 'c', '-', 's', 'h', 'a', '2', '5', '6', 0x00, 0x00, 0x00, 0x65, 0x53, 0xF1, 0x00, 0x01, 0x2C, 0x00, 0x04, 0xAA, 0xBB, 0xCC, 0xDD, 0x04, 0xD2, 0x00, 0x00, 0xFF},
			begin:   0,
			end:     0,
			want:    RecordTSIG{},
			wantPos: 0,
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

			got, pos, err := ParseRecordTSIG(w, tt.begin, end)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ParseRecordTSIG() error = %v, wantErr = %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if pos != tt.wantPos {
				t.Errorf("ParseRecordTSIG() pos = %v, want %v", pos, tt.wantPos)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ParseRecordTSIG() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRecordTSIGWireFormatRoundTrip(t *testing.T) {
	original := RecordTSIG{
		Algorithm:  testDomainName(t, "HMAC-SHA256.Example."),
		TimeSigned: 1700000000,
		Fudge:      300,
		MAC:        []byte{0xAA, 0xBB, 0xCC, 0xDD},
		OriginalID: 1234,
		Error:      TSIGErrorBadTime,
		OtherData:  []byte{0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01},
	}

	// The algorithm name must be written in full even though an unrelated
	// name is available for compression.
	db := NewNameCompressionDB()
	db.AddDomainName(testDomainName(t, "example."), 12)

	var w WireFormat
	size := original.AppendWireFormat(&w, db)
	if size != uint32(len(w)) {
		t.Errorf("AppendWireFormat() size = %v, want %v", size, len(w))
	}

	got, pos, err := ParseRecordTSIG(w, 0, uint32(len(w)))
	if err != nil {
		t.Fatalf("ParseRecordTSIG() error = %v", err)
	}
	if pos != size {
		t.Errorf("ParseRecordTSIG() pos = %v, want %v", pos, size)
	}
	if !reflect.DeepEqual(got, original) {
		t.Errorf("ParseRecordTSIG() got = %v, want %v", got, original)
	}

	// The name is uncompressed, so the record begins with the name itself.
	if !bytes.HasPrefix(w, []byte{
		0x0b, 'H', 'M', 'A', 'C', '-', 'S', 'H', 'A', '2', '5', '6',
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
		0x0b, 'h', 'm', 'a', 'c', '-', 's', 'h', 'a', '2', '5', '6',
		0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x00,
	}) {
		t.Errorf("AppendCanonicalWireFormat() did not lower-case the algorithm name: %v", cw)
	}
	if bytes.Equal(canonical, w) {
		t.Errorf("CanonicalWireFormat() is not lower-cased: %v", canonical)
	}
}

func TestRecordTSIGStringRoundTrip(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "record without other data",
			input: "hmac-sha256. 1700000000 300 qrsM3w 1234 NOERROR",
			want:  "hmac-sha256. 1700000000 300 qrsM3w 1234 NOERROR",
		},
		{
			name:  "record with other data and a named error",
			input: "hmac-sha256. 1700000000 300 qrsM3w 1234 BADTRUNC deadbeef0001",
			want:  "hmac-sha256. 1700000000 300 qrsM3w 1234 BADTRUNC deadbeef0001",
		},
		{
			name:  "error given as a number",
			input: "hmac-sha256. 1700000000 300 qrsM3w 1234 17",
			want:  "hmac-sha256. 1700000000 300 qrsM3w 1234 BADKEY",
		},
		{
			name:  "error the specification does not name",
			input: "hmac-sha256. 1700000000 300 qrsM3w 1234 ERROR99",
			want:  "hmac-sha256. 1700000000 300 qrsM3w 1234 ERROR99",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tsig, err := NewRecordTSIGFromString(tt.input)
			if err != nil {
				t.Fatalf("NewRecordTSIGFromString(%q) error = %v", tt.input, err)
			}
			if got := tsig.String(); got != tt.want {
				t.Errorf("String() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestNewRecordTSIG(t *testing.T) {
	algorithm := testDomainName(t, "hmac-sha256.")
	mac := []byte{0xAA, 0xBB, 0xCC, 0xDD}
	otherData := []byte{0x01, 0x02}

	tsig, err := NewRecordTSIG(algorithm, 1700000000, 300, mac, 1234, TSIGErrorBadSig, otherData)
	if err != nil {
		t.Fatalf("NewRecordTSIG() error = %v", err)
	}
	if tsig.Type() != TYPE_TSIG {
		t.Errorf("Type() = %v, want TYPE_TSIG", tsig.Type())
	}
	if !reflect.DeepEqual(tsig.Algorithm, algorithm) {
		t.Errorf("Algorithm = %v, want %v", tsig.Algorithm, algorithm)
	}
	if tsig.TimeSigned != 1700000000 {
		t.Errorf("TimeSigned = %v, want 1700000000", tsig.TimeSigned)
	}
	if tsig.Fudge != 300 {
		t.Errorf("Fudge = %v, want 300", tsig.Fudge)
	}
	if !bytes.Equal(tsig.MAC, mac) {
		t.Errorf("MAC = %v, want %v", tsig.MAC, mac)
	}
	if tsig.OriginalID != 1234 {
		t.Errorf("OriginalID = %v, want 1234", tsig.OriginalID)
	}
	if tsig.Error != TSIGErrorBadSig {
		t.Errorf("Error = %v, want TSIGErrorBadSig", tsig.Error)
	}
	if !bytes.Equal(tsig.OtherData, otherData) {
		t.Errorf("OtherData = %v, want %v", tsig.OtherData, otherData)
	}

	// The largest value the 48 bit Time Signed field holds is accepted.
	if _, err := NewRecordTSIG(algorithm, 1<<48-1, 0, mac, 0, TSIGErrorNoError, nil); err != nil {
		t.Errorf("NewRecordTSIG(2^48-1) error = %v", err)
	}

	if _, err := NewRecordTSIG(algorithm, 1<<48, 0, mac, 0, TSIGErrorNoError, nil); err == nil {
		t.Error("NewRecordTSIG(2^48) error = nil, want an error")
	}

	if _, err := NewRecordTSIG(algorithm, 0, 0, make([]byte, 1<<16), 0, TSIGErrorNoError, nil); err == nil {
		t.Error("NewRecordTSIG() with a 65536 octet MAC: error = nil, want an error")
	}

	if _, err := NewRecordTSIG(algorithm, 0, 0, mac, 0, TSIGErrorNoError, make([]byte, 1<<16)); err == nil {
		t.Error("NewRecordTSIG() with a 65536 octet other data: error = nil, want an error")
	}
}

func TestNewRecordTSIGFromString(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{name: "valid record", input: "hmac-sha256. 1700000000 300 qrsM3w 1234 NOERROR", wantErr: false},
		{name: "empty algorithm name", input: " 1700000000 300 qrsM3w 1234 NOERROR", wantErr: true},
		{name: "time signed too large", input: "hmac-sha256. 281474976710656 300 qrsM3w 1234 NOERROR", wantErr: true},
		{name: "fudge too large", input: "hmac-sha256. 1700000000 65536 qrsM3w 1234 NOERROR", wantErr: true},
		{name: "MAC with base64 padding", input: "hmac-sha256. 1700000000 300 qrsM3w== 1234 NOERROR", wantErr: true},
		{name: "original id too large", input: "hmac-sha256. 1700000000 300 qrsM3w 65536 NOERROR", wantErr: true},
		{name: "unknown error name", input: "hmac-sha256. 1700000000 300 qrsM3w 1234 NOTANERROR", wantErr: true},
		{name: "error number too large", input: "hmac-sha256. 1700000000 300 qrsM3w 1234 65536", wantErr: true},
		{name: "odd length other data", input: "hmac-sha256. 1700000000 300 qrsM3w 1234 NOERROR 0abc5", wantErr: true},
		{name: "non hex other data", input: "hmac-sha256. 1700000000 300 qrsM3w 1234 NOERROR zz", wantErr: true},
		{name: "missing fields", input: "hmac-sha256. 1700000000 300", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewRecordTSIGFromString(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewRecordTSIGFromString(%q) error = %v, wantErr = %v", tt.input, err, tt.wantErr)
			}
		})
	}
}

func TestTSIGErrorString(t *testing.T) {
	tests := []struct {
		code uint16
		want string
	}{
		{TSIGErrorNoError, "NOERROR"},
		{TSIGErrorBadSig, "BADSIG"},
		{TSIGErrorBadKey, "BADKEY"},
		{TSIGErrorBadTime, "BADTIME"},
		{TSIGErrorBadMode, "BADMODE"},
		{TSIGErrorBadName, "BADNAME"},
		{TSIGErrorBadAlg, "BADALG"},
		{TSIGErrorBadTrunc, "BADTRUNC"},
		{1, "ERROR1"},
		{15, "ERROR15"},
		{23, "ERROR23"},
		{65535, "ERROR65535"},
	}

	for _, tt := range tests {
		if got := TSIGErrorString(tt.code); got != tt.want {
			t.Errorf("TSIGErrorString(%d) = %q, want %q", tt.code, got, tt.want)
		}
	}
}

func TestNewTSIGError(t *testing.T) {
	tests := []struct {
		input   string
		want    uint16
		wantErr bool
	}{
		{"NOERROR", TSIGErrorNoError, false},
		{"BADSIG", TSIGErrorBadSig, false},
		{"BADKEY", TSIGErrorBadKey, false},
		{"BADTIME", TSIGErrorBadTime, false},
		{"BADMODE", TSIGErrorBadMode, false},
		{"BADNAME", TSIGErrorBadName, false},
		{"BADALG", TSIGErrorBadAlg, false},
		{"BADTRUNC", TSIGErrorBadTrunc, false},
		{"0", 0, false},
		{"16", 16, false},
		{"65535", 65535, false},
		{"NOTANERROR", 0, true},
		{"-1", 0, true},
		{"65536", 0, true},
	}

	for _, tt := range tests {
		got, err := NewTSIGError(tt.input)
		if (err != nil) != tt.wantErr {
			t.Errorf("NewTSIGError(%q) error = %v, wantErr = %v", tt.input, err, tt.wantErr)
			continue
		}
		if tt.wantErr {
			continue
		}
		if got != tt.want {
			t.Errorf("NewTSIGError(%q) = %d, want %d", tt.input, got, tt.want)
		}
		// Every named code round trips through TSIGErrorString.
		if name := TSIGErrorString(got); name != "" {
			back, err := NewTSIGError(name)
			if err != nil || back != got {
				t.Errorf("NewTSIGError(TSIGErrorString(%d)) = %d, %v, want %d, nil", got, back, err, got)
			}
		}
	}
}

func TestTSIGErrorConstants(t *testing.T) {
	// RFC 8945 Section 5 assigns these extended RCODEs.
	if TSIGErrorNoError != 0 {
		t.Errorf("TSIGErrorNoError = %d, want 0", TSIGErrorNoError)
	}
	if TSIGErrorBadSig != 16 {
		t.Errorf("TSIGErrorBadSig = %d, want 16", TSIGErrorBadSig)
	}
	if TSIGErrorBadKey != 17 {
		t.Errorf("TSIGErrorBadKey = %d, want 17", TSIGErrorBadKey)
	}
	if TSIGErrorBadTime != 18 {
		t.Errorf("TSIGErrorBadTime = %d, want 18", TSIGErrorBadTime)
	}
	if TSIGErrorBadMode != 19 {
		t.Errorf("TSIGErrorBadMode = %d, want 19", TSIGErrorBadMode)
	}
	if TSIGErrorBadName != 20 {
		t.Errorf("TSIGErrorBadName = %d, want 20", TSIGErrorBadName)
	}
	if TSIGErrorBadAlg != 21 {
		t.Errorf("TSIGErrorBadAlg = %d, want 21", TSIGErrorBadAlg)
	}
	if TSIGErrorBadTrunc != 22 {
		t.Errorf("TSIGErrorBadTrunc = %d, want 22", TSIGErrorBadTrunc)
	}
}

func TestParseResourceRecordTSIG(t *testing.T) {
	// A TSIG record in a message: CLASS is ANY and TTL is zero.
	var w WireFormat
	w.AppendDomainName(testDomainName(t, "example.com."), nil)
	w.AppendUInt16(uint16(TYPE_TSIG))
	w.AppendUInt16(uint16(CLASS_ANY))
	w.AppendUInt32(0)
	rdataLen := uint32(len(hmacSHA256)) + 6 + 2 + 2 + 4 + 2 + 2 + 2 + 0
	w.AppendUInt16(uint16(rdataLen))
	w.AppendBytes(hmacSHA256)
	w.AppendUInt48(1700000000)
	w.AppendUInt16(300)
	w.AppendUInt16(4)
	w.AppendBytes([]byte{0xAA, 0xBB, 0xCC, 0xDD})
	w.AppendUInt16(1234)
	w.AppendUInt16(TSIGErrorNoError)
	w.AppendUInt16(0)

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
	if rr.Type != TYPE_TSIG {
		t.Errorf("Type = %v, want TYPE_TSIG", rr.Type)
	}
	if rr.TTL != 0 {
		t.Errorf("TTL = %v, want 0", rr.TTL)
	}
	tsig, ok := rr.RData.(RecordTSIG)
	if !ok {
		t.Fatalf("RData = %T, want RecordTSIG", rr.RData)
	}
	want := RecordTSIG{
		Algorithm:  testDomainName(t, "hmac-sha256."),
		TimeSigned: 1700000000,
		Fudge:      300,
		MAC:        []byte{0xAA, 0xBB, 0xCC, 0xDD},
		OriginalID: 1234,
		Error:      TSIGErrorNoError,
		OtherData:  []byte{},
	}
	if !reflect.DeepEqual(tsig, want) {
		t.Errorf("RData = %v, want %v", tsig, want)
	}
}
