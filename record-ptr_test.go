package dnsmsg

import (
	"bytes"
	"encoding/json"
	"reflect"
	"testing"
)

func TestParseRecordPTR(t *testing.T) {
	tests := []struct {
		name    string
		input   []byte
		begin   uint32
		want    RecordPTR
		wantPos uint32
		wantErr bool
	}{
		{
			name:    "simple PTR record",
			input:   []byte{3, 'w', 'w', 'w', 3, 'e', 'x', 'a', 3, 'c', 'o', 'm', 0},
			begin:   0,
			want:    NewRecordPTR(testDomainName(t, "www.exa.com")),
			wantPos: 13,
			wantErr: false,
		},
		{
			name:    "fully qualified domain",
			input:   []byte{3, 'w', 'w', 'w', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0},
			begin:   0,
			want:    NewRecordPTR(testDomainName(t, "www.example.com")),
			wantPos: 17,
			wantErr: false,
		},
		{
			name:    "root domain",
			input:   []byte{0},
			begin:   0,
			want:    NewRecordPTR(NewRootDomainName()),
			wantPos: 1,
			wantErr: false,
		},
		{
			name:    "truncated input",
			input:   []byte{3, 'w', 'w', 'w'},
			begin:   0,
			want:    RecordPTR{},
			wantErr: true,
		},
		{
			name:    "out of bounds",
			input:   []byte{1, 'a'},
			begin:   10,
			want:    RecordPTR{},
			wantPos: 10,
			wantErr: true,
		},
		{
			name: "with compression pointer",
			// pos 0: www.example.com; pos 17: 0xC0 0x00 (points to pos 0)
			input:   []byte{3, 'w', 'w', 'w', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, 0xC0, 0x00},
			begin:   17,
			want:    NewRecordPTR(testDomainName(t, "www.example.com")),
			wantPos: 19,
			wantErr: false,
		},
		{
			name: "compression pointer to an out of bounds offset",
			// pos 0: 0xC0 0x30 points to offset 48, beyond the message
			input:   []byte{0xC0, 0x30},
			begin:   0,
			want:    RecordPTR{},
			wantPos: 2,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, pos, err := ParseRecordPTR(tt.input, tt.begin)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseRecordPTR() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ParseRecordPTR() got = %v, want %v", got, tt.want)
			}
			if pos != tt.wantPos {
				t.Errorf("ParseRecordPTR() pos = %v, want %v", pos, tt.wantPos)
			}
		})
	}
}

func TestNewRecordPTRFromString(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    RecordPTR
		wantErr bool
	}{
		{
			name:    "simple pointed-to name",
			input:   "www.example.com.",
			want:    NewRecordPTR(testDomainName(t, "www.example.com")),
			wantErr: false,
		},
		{
			name:    "root domain",
			input:   ".",
			want:    NewRecordPTR(NewRootDomainName()),
			wantErr: false,
		},
		{
			name:    "invalid domain with consecutive dots",
			input:   "www..example.com.",
			want:    RecordPTR{},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewRecordPTRFromString(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewRecordPTRFromString() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewRecordPTRFromString() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRecordPTRString(t *testing.T) {
	tests := []struct {
		name  string
		input RecordPTR
		want  string
	}{
		{
			name:  "simple pointed-to name",
			input: NewRecordPTR(testDomainName(t, "www.example.com")),
			want:  "www.example.com.",
		},
		{
			name:  "root domain",
			input: NewRecordPTR(NewRootDomainName()),
			want:  ".",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.input.String()
			if got != tt.want {
				t.Errorf("RecordPTR.String() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestRecordPTRType(t *testing.T) {
	ptr := NewRecordPTR(testDomainName(t, "www"))
	if ptr.Type() != TYPE_PTR {
		t.Errorf("RecordPTR.Type() = %v, want %v", ptr.Type(), TYPE_PTR)
	}
	if TYPE_PTR.String() != "PTR" {
		t.Errorf("TYPE_PTR.String() = %q, want %q", TYPE_PTR.String(), "PTR")
	}
	if TYPE_PTR != ResourceType(12) {
		t.Errorf("TYPE_PTR = %v, want 12", TYPE_PTR)
	}
	typ, err := NewType("PTR")
	if err != nil {
		t.Errorf("NewType(\"PTR\"): %v", err)
		return
	}
	if typ != TYPE_PTR {
		t.Errorf("NewType(\"PTR\") = %v, want %v", typ, TYPE_PTR)
	}
}

func TestRecordPTRCanonicalWireFormat(t *testing.T) {
	// Test that canonical wire format is lowercase
	ptr := NewRecordPTR(testDomainName(t, "WWW.EXAMPLE.COM"))
	want := []byte{3, 'w', 'w', 'w', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0}

	got := ptr.CanonicalWireFormat()
	if !bytes.Equal(got, want) {
		t.Errorf("RecordPTR.CanonicalWireFormat() = %v, want %v", got, want)
	}
}

func TestRecordPTRRoundTrip(t *testing.T) {
	original := NewRecordPTR(testDomainName(t, "www.example.com"))

	// Serialize to canonical wire format
	wire := original.CanonicalWireFormat()

	// Parse back
	parsed, end, err := ParseRecordPTR(wire, 0)
	if err != nil {
		t.Fatalf("ParseRecordPTR() error = %v", err)
	}
	if end != uint32(len(wire)) {
		t.Errorf("round trip end pos = %v, want %v", end, len(wire))
	}
	if !reflect.DeepEqual(parsed, original) {
		t.Errorf("round trip got = %v, want %v", parsed, original)
	}
}

func TestRecordPTRAppendWireFormat(t *testing.T) {
	ptr := NewRecordPTR(testDomainName(t, "www.example.com"))
	db := NewNameCompressionDB()

	var w WireFormat
	size := ptr.AppendWireFormat(&w, db)
	if size != 17 {
		t.Errorf("AppendWireFormat() size = %v, want 17", size)
	}

	// Parse back from what we wrote
	got, pos, err := ParseRecordPTR(w, 0)
	if err != nil {
		t.Fatalf("ParseRecordPTR() error = %v", err)
	}
	if pos != size {
		t.Errorf("AppendWireFormat() pos = %v, want %v", pos, size)
	}
	if !reflect.DeepEqual(got, ptr) {
		t.Errorf("AppendWireFormat -> ParseRecordPTR round trip: got = %v, want %v", got, ptr)
	}
}

// TestRecordPTRAppendWireFormatCompression verifies that the suffix
// registered earlier in the same wire format is replaced with a compression
// pointer when the PTR is written, and that the compressed name is read back
// as the full name.  RFC 1035 Section 3.3 allows the domain name in the
// RDATA of a PTR record to be compressed.
func TestRecordPTRAppendWireFormatCompression(t *testing.T) {
	var w WireFormat
	db := NewNameCompressionDB()

	// pos 0: example.com (13 bytes)
	if size := w.AppendDomainName(testDomainName(t, "example.com"), db); size != 13 {
		t.Fatalf("AppendDomainName(example.com) size = %v, want 13", size)
	}

	ptr := NewRecordPTR(testDomainName(t, "sub.example.com"))
	size := ptr.AppendWireFormat(&w, db)
	// "sub" (4 bytes) + compression pointer to pos 0 (2 bytes)
	if size != 6 {
		t.Errorf("AppendWireFormat() size = %v, want 6", size)
	}

	got, pos, err := ParseRecordPTR(w, 13)
	if err != nil {
		t.Fatalf("ParseRecordPTR() error = %v", err)
	}
	if pos != w.Size() {
		t.Errorf("ParseRecordPTR() pos = %v, want %v", pos, w.Size())
	}
	if !reflect.DeepEqual(got, ptr) {
		t.Errorf("ParseRecordPTR() got = %v, want %v", got, ptr)
	}
}

func TestRecordPTRAppendCanonicalWireFormat(t *testing.T) {
	ptr := NewRecordPTR(testDomainName(t, "WWW.EXAMPLE.COM"))

	var w WireFormat
	size := ptr.AppendCanonicalWireFormat(&w)
	if size != 17 {
		t.Errorf("AppendCanonicalWireFormat() size = %v, want 17", size)
	}

	parsed, pos, err := ParseRecordPTR(w, 0)
	if err != nil {
		t.Fatalf("ParseRecordPTR() error = %v", err)
	}
	if pos != size {
		t.Errorf("AppendCanonicalWireFormat() pos = %v, want %v", pos, size)
	}
	if !reflect.DeepEqual(parsed, NewRecordPTR(testDomainName(t, "www.example.com"))) {
		t.Errorf("AppendCanonicalWireFormat -> ParseRecordPTR round trip: got = %v", parsed)
	}
}

// TestResourceRecordPTR verifies that a PTR record is read from and written
// to a message wire format through ParseResourceRecord and
// AppendResourceRecord.
func TestResourceRecordPTR(t *testing.T) {
	rr := ResourceRecord{
		Name:  testDomainName(t, "1.0.0.127.in-addr.arpa"),
		Class: CLASS_IN,
		Type:  TYPE_PTR,
		TTL:   3600,
		RData: NewRecordPTR(testDomainName(t, "localhost.example.com")),
	}

	var w WireFormat
	db := NewNameCompressionDB()
	size := AppendResourceRecord(&w, rr, db)
	if size == 0 {
		t.Fatal("AppendResourceRecord() size = 0")
	}

	got, end, err := ParseResourceRecord(w, 0)
	if err != nil {
		t.Fatalf("ParseResourceRecord() error = %v", err)
	}
	if end != w.Size() {
		t.Errorf("ParseResourceRecord() end = %v, want %v", end, w.Size())
	}
	if got.Name.String() != rr.Name.String() || got.Class != rr.Class || got.Type != rr.Type || got.TTL != rr.TTL {
		t.Errorf("ParseResourceRecord() header = %v %v %v %d, want %v %v %v %d",
			got.Name, got.Class, got.Type, got.TTL, rr.Name, rr.Class, rr.Type, rr.TTL)
	}
	rdata, ok := got.RData.(RecordPTR)
	if !ok {
		t.Fatalf("ParseResourceRecord() RData = %T, want RecordPTR", got.RData)
	}
	if !reflect.DeepEqual(rdata, NewRecordPTR(testDomainName(t, "localhost.example.com"))) {
		t.Errorf("ParseResourceRecord() RData = %v, want %v", rdata, rr.RData)
	}
}

// TestRecordPTRJSON verifies the JSON form of a PTR record: the pointed-to
// name is exported as its presentation-format string.
func TestRecordPTRJSON(t *testing.T) {
	ptr := NewRecordPTR(testDomainName(t, "www.example.com"))

	data, err := json.Marshal(ptr)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	want := `{"PTR":"www.example.com."}`
	if string(data) != want {
		t.Errorf("json.Marshal() = %q, want %q", string(data), want)
	}

	var got RecordPTR
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	if !reflect.DeepEqual(got, ptr) {
		t.Errorf("json.Unmarshal() = %v, want %v", got, ptr)
	}

	var invalid RecordPTR
	if err := json.Unmarshal([]byte(`{"PTR":"www..example.com."}`), &invalid); err == nil {
		t.Error("json.Unmarshal() error = nil, want an error")
	}
}
