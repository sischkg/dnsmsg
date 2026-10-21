package dnsmsg

import (
	"bytes"
	"encoding/json"
	"reflect"
	"testing"
)

func TestParseRecordDNAME(t *testing.T) {
	tests := []struct {
		name    string
		input   []byte
		begin   uint32
		want    RecordDNAME
		wantPos uint32
		wantErr bool
	}{
		{
			name:    "simple DNAME record",
			input:   []byte{3, 'w', 'w', 'w', 3, 'e', 'x', 'a', 3, 'c', 'o', 'm', 0},
			begin:   0,
			want:    NewRecordDNAME(testDomainName(t, "www.exa.com")),
			wantPos: 13,
			wantErr: false,
		},
		{
			name:    "fully qualified domain",
			input:   []byte{3, 'w', 'w', 'w', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0},
			begin:   0,
			want:    NewRecordDNAME(testDomainName(t, "www.example.com")),
			wantPos: 17,
			wantErr: false,
		},
		{
			name:    "root domain",
			input:   []byte{0},
			begin:   0,
			want:    NewRecordDNAME(NewRootDomainName()),
			wantPos: 1,
			wantErr: false,
		},
		{
			name:    "truncated input",
			input:   []byte{3, 'w', 'w', 'w'},
			begin:   0,
			want:    RecordDNAME{},
			wantErr: true,
		},
		{
			name:    "out of bounds",
			input:   []byte{1, 'a'},
			begin:   10,
			want:    RecordDNAME{},
			wantPos: 10,
			wantErr: true,
		},
		{
			name: "with compression pointer",
			// pos 0: www.example.com; pos 17: 0xC0 0x00 (points to pos 0)
			input:   []byte{3, 'w', 'w', 'w', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, 0xC0, 0x00},
			begin:   17,
			want:    NewRecordDNAME(testDomainName(t, "www.example.com")),
			wantPos: 19,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, pos, err := ParseRecordDNAME(tt.input, tt.begin)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseRecordDNAME() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ParseRecordDNAME() got = %v, want %v", got, tt.want)
			}
			if pos != tt.wantPos {
				t.Errorf("ParseRecordDNAME() pos = %v, want %v", pos, tt.wantPos)
			}
		})
	}
}

func TestNewRecordDNAMEFromString(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    RecordDNAME
		wantErr bool
	}{
		{
			name:    "simple target name",
			input:   "www.example.com.",
			want:    NewRecordDNAME(testDomainName(t, "www.example.com")),
			wantErr: false,
		},
		{
			name:    "root domain",
			input:   ".",
			want:    NewRecordDNAME(NewRootDomainName()),
			wantErr: false,
		},
		{
			name:    "invalid domain with consecutive dots",
			input:   "www..example.com.",
			want:    RecordDNAME{},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewRecordDNAMEFromString(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewRecordDNAMEFromString() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewRecordDNAMEFromString() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRecordDNAMEString(t *testing.T) {
	tests := []struct {
		name  string
		input RecordDNAME
		want  string
	}{
		{
			name:  "simple target name",
			input: NewRecordDNAME(testDomainName(t, "www.example.com")),
			want:  "www.example.com.",
		},
		{
			name:  "root domain",
			input: NewRecordDNAME(NewRootDomainName()),
			want:  ".",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.input.String()
			if got != tt.want {
				t.Errorf("RecordDNAME.String() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestRecordDNAMEType(t *testing.T) {
	dname := NewRecordDNAME(testDomainName(t, "www"))
	if dname.Type() != TYPE_DNAME {
		t.Errorf("RecordDNAME.Type() = %v, want %v", dname.Type(), TYPE_DNAME)
	}
	if TYPE_DNAME.String() != "DNAME" {
		t.Errorf("TYPE_DNAME.String() = %q, want %q", TYPE_DNAME.String(), "DNAME")
	}
	typ, err := NewType("DNAME")
	if err != nil {
		t.Errorf("NewType(\"DNAME\"): %v", err)
		return
	}
	if typ != TYPE_DNAME {
		t.Errorf("NewType(\"DNAME\") = %v, want %v", typ, TYPE_DNAME)
	}
}

func TestRecordDNAMECanonicalWireFormat(t *testing.T) {
	// Test that canonical wire format is lowercase
	dname := NewRecordDNAME(testDomainName(t, "WWW.EXAMPLE.COM"))
	want := []byte{3, 'w', 'w', 'w', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0}

	got := dname.CanonicalWireFormat()
	if !bytes.Equal(got, want) {
		t.Errorf("RecordDNAME.CanonicalWireFormat() = %v, want %v", got, want)
	}
}

func TestRecordDNAMERoundTrip(t *testing.T) {
	original := NewRecordDNAME(testDomainName(t, "www.example.com"))

	// Serialize to canonical wire format
	wire := original.CanonicalWireFormat()

	// Parse back
	parsed, end, err := ParseRecordDNAME(wire, 0)
	if err != nil {
		t.Fatalf("ParseRecordDNAME() error = %v", err)
	}
	if end != uint32(len(wire)) {
		t.Errorf("round trip end pos = %v, want %v", end, len(wire))
	}
	if !reflect.DeepEqual(parsed, original) {
		t.Errorf("round trip got = %v, want %v", parsed, original)
	}
}

func TestRecordDNAMEAppendWireFormat(t *testing.T) {
	dname := NewRecordDNAME(testDomainName(t, "www.example.com"))
	db := NewNameCompressionDB()

	var w WireFormat
	size := dname.AppendWireFormat(&w, db)
	if size != 17 {
		t.Errorf("AppendWireFormat() size = %v, want 17", size)
	}

	// Parse back from what we wrote
	got, pos, err := ParseRecordDNAME(w, 0)
	if err != nil {
		t.Fatalf("ParseRecordDNAME() error = %v", err)
	}
	if pos != size {
		t.Errorf("AppendWireFormat() pos = %v, want %v", pos, size)
	}
	if !reflect.DeepEqual(got, dname) {
		t.Errorf("AppendWireFormat -> ParseRecordDNAME round trip: got = %v, want %v", got, dname)
	}
}

// TestRecordDNAMEAppendWireFormatCompression verifies that the suffix
// registered earlier in the same wire format is replaced with a compression
// pointer when the DNAME is written, and that the compressed name is read
// back as the full name.
func TestRecordDNAMEAppendWireFormatCompression(t *testing.T) {
	var w WireFormat
	db := NewNameCompressionDB()

	// pos 0: example.com (13 bytes)
	if size := w.AppendDomainName(testDomainName(t, "example.com"), db); size != 13 {
		t.Fatalf("AppendDomainName(example.com) size = %v, want 13", size)
	}

	dname := NewRecordDNAME(testDomainName(t, "sub.example.com"))
	size := dname.AppendWireFormat(&w, db)
	// "sub" (4 bytes) + compression pointer to pos 0 (2 bytes)
	if size != 6 {
		t.Errorf("AppendWireFormat() size = %v, want 6", size)
	}

	got, pos, err := ParseRecordDNAME(w, 13)
	if err != nil {
		t.Fatalf("ParseRecordDNAME() error = %v", err)
	}
	if pos != w.Size() {
		t.Errorf("ParseRecordDNAME() pos = %v, want %v", pos, w.Size())
	}
	if !reflect.DeepEqual(got, dname) {
		t.Errorf("ParseRecordDNAME() got = %v, want %v", got, dname)
	}
}

func TestRecordDNAMEAppendCanonicalWireFormat(t *testing.T) {
	dname := NewRecordDNAME(testDomainName(t, "WWW.EXAMPLE.COM"))

	var w WireFormat
	size := dname.AppendCanonicalWireFormat(&w)
	if size != 17 {
		t.Errorf("AppendCanonicalWireFormat() size = %v, want 17", size)
	}

	parsed, pos, err := ParseRecordDNAME(w, 0)
	if err != nil {
		t.Fatalf("ParseRecordDNAME() error = %v", err)
	}
	if pos != size {
		t.Errorf("AppendCanonicalWireFormat() pos = %v, want %v", pos, size)
	}
	if !reflect.DeepEqual(parsed, NewRecordDNAME(testDomainName(t, "www.example.com"))) {
		t.Errorf("AppendCanonicalWireFormat -> ParseRecordDNAME round trip: got = %v", parsed)
	}
}

// TestResourceRecordDNAME verifies that a DNAME record is read from and
// written to a message wire format through ParseResourceRecord and
// AppendResourceRecord.
func TestResourceRecordDNAME(t *testing.T) {
	rr := ResourceRecord{
		Name:  testDomainName(t, "sub.example.com"),
		Class: CLASS_IN,
		Type:  TYPE_DNAME,
		TTL:   3600,
		RData: NewRecordDNAME(testDomainName(t, "sub.other.example.com")),
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
	rdata, ok := got.RData.(RecordDNAME)
	if !ok {
		t.Fatalf("ParseResourceRecord() RData = %T, want RecordDNAME", got.RData)
	}
	if !reflect.DeepEqual(rdata, NewRecordDNAME(testDomainName(t, "sub.other.example.com"))) {
		t.Errorf("ParseResourceRecord() RData = %v, want %v", rdata, rr.RData)
	}
}

// TestRecordDNAMEJSON verifies the JSON form of a DNAME record: the target
// name is exported as its presentation-format string.
func TestRecordDNAMEJSON(t *testing.T) {
	dname := NewRecordDNAME(testDomainName(t, "www.example.com"))

	data, err := json.Marshal(dname)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	want := `{"DNAME":"www.example.com."}`
	if string(data) != want {
		t.Errorf("json.Marshal() = %q, want %q", string(data), want)
	}

	var got RecordDNAME
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	if !reflect.DeepEqual(got, dname) {
		t.Errorf("json.Unmarshal() = %v, want %v", got, dname)
	}

	var invalid RecordDNAME
	if err := json.Unmarshal([]byte(`{"DNAME":"www..example.com."}`), &invalid); err == nil {
		t.Error("json.Unmarshal() error = nil, want an error")
	}
}
