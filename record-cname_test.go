package dnsmsg

import (
	"bytes"
	"encoding/json"
	"reflect"
	"testing"
)

func TestParseRecordCNAME(t *testing.T) {
	tests := []struct {
		name    string
		input   []byte
		begin   uint32
		want    RecordCNAME
		wantPos uint32
		wantErr bool
	}{
		{
			name:    "simple CNAME record",
			input:   []byte{3, 'w', 'w', 'w', 3, 'e', 'x', 'a', 3, 'c', 'o', 'm', 0},
			begin:   0,
			want:    NewRecordCNAME(testDomainName(t, "www.exa.com")),
			wantPos: 13,
			wantErr: false,
		},
		{
			name:    "fully qualified domain",
			input:   []byte{3, 'w', 'w', 'w', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0},
			begin:   0,
			want:    NewRecordCNAME(testDomainName(t, "www.example.com")),
			wantPos: 17,
			wantErr: false,
		},
		{
			name:    "root domain",
			input:   []byte{0},
			begin:   0,
			want:    NewRecordCNAME(NewRootDomainName()),
			wantPos: 1,
			wantErr: false,
		},
		{
			name:    "truncated input",
			input:   []byte{3, 'w', 'w', 'w'},
			begin:   0,
			want:    RecordCNAME{},
			wantErr: true,
		},
		{
			name:    "out of bounds",
			input:   []byte{1, 'a'},
			begin:   10,
			want:    RecordCNAME{},
			wantPos: 10,
			wantErr: true,
		},
		{
			name: "with compression pointer",
			// pos 0: www.example.com; pos 17: 0xC0 0x00 (points to pos 0)
			input:   []byte{3, 'w', 'w', 'w', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, 0xC0, 0x00},
			begin:   17,
			want:    NewRecordCNAME(testDomainName(t, "www.example.com")),
			wantPos: 19,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, pos, err := ParseRecordCNAME(tt.input, tt.begin)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseRecordCNAME() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ParseRecordCNAME() got = %v, want %v", got, tt.want)
			}
			if pos != tt.wantPos {
				t.Errorf("ParseRecordCNAME() pos = %v, want %v", pos, tt.wantPos)
			}
		})
	}
}

func TestNewRecordCNAMEFromString(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    RecordCNAME
		wantErr bool
	}{
		{
			name:    "simple canonical name",
			input:   "www.example.com.",
			want:    NewRecordCNAME(testDomainName(t, "www.example.com")),
			wantErr: false,
		},
		{
			name:    "root domain",
			input:   ".",
			want:    NewRecordCNAME(NewRootDomainName()),
			wantErr: false,
		},
		{
			name:    "invalid domain with consecutive dots",
			input:   "www..example.com.",
			want:    RecordCNAME{},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewRecordCNAMEFromString(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewRecordCNAMEFromString() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewRecordCNAMEFromString() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRecordCNAMEString(t *testing.T) {
	tests := []struct {
		name  string
		input RecordCNAME
		want  string
	}{
		{
			name:  "simple canonical name",
			input: NewRecordCNAME(testDomainName(t, "www.example.com")),
			want:  "www.example.com.",
		},
		{
			name:  "root domain",
			input: NewRecordCNAME(NewRootDomainName()),
			want:  ".",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.input.String()
			if got != tt.want {
				t.Errorf("RecordCNAME.String() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestRecordCNAMEType(t *testing.T) {
	cname := NewRecordCNAME(testDomainName(t, "www"))
	if cname.Type() != TYPE_CNAME {
		t.Errorf("RecordCNAME.Type() = %v, want %v", cname.Type(), TYPE_CNAME)
	}
	if TYPE_CNAME.String() != "CNAME" {
		t.Errorf("TYPE_CNAME.String() = %q, want %q", TYPE_CNAME.String(), "CNAME")
	}
	typ, err := NewType("CNAME")
	if err != nil {
		t.Errorf("NewType(\"CNAME\"): %v", err)
		return
	}
	if typ != TYPE_CNAME {
		t.Errorf("NewType(\"CNAME\") = %v, want %v", typ, TYPE_CNAME)
	}
}

func TestRecordCNAMECanonicalWireFormat(t *testing.T) {
	// Test that canonical wire format is lowercase
	cname := NewRecordCNAME(testDomainName(t, "WWW.EXAMPLE.COM"))
	want := []byte{3, 'w', 'w', 'w', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0}

	got := cname.CanonicalWireFormat()
	if !bytes.Equal(got, want) {
		t.Errorf("RecordCNAME.CanonicalWireFormat() = %v, want %v", got, want)
	}
}

func TestRecordCNAMERoundTrip(t *testing.T) {
	original := NewRecordCNAME(testDomainName(t, "www.example.com"))

	// Serialize to canonical wire format
	wire := original.CanonicalWireFormat()

	// Parse back
	parsed, end, err := ParseRecordCNAME(wire, 0)
	if err != nil {
		t.Fatalf("ParseRecordCNAME() error = %v", err)
	}
	if end != uint32(len(wire)) {
		t.Errorf("round trip end pos = %v, want %v", end, len(wire))
	}
	if !reflect.DeepEqual(parsed, original) {
		t.Errorf("round trip got = %v, want %v", parsed, original)
	}
}

func TestRecordCNAMEAppendWireFormat(t *testing.T) {
	cname := NewRecordCNAME(testDomainName(t, "www.example.com"))
	db := NewNameCompressionDB()

	var w WireFormat
	size := cname.AppendWireFormat(&w, db)
	if size != 17 {
		t.Errorf("AppendWireFormat() size = %v, want 17", size)
	}

	// Parse back from what we wrote
	got, pos, err := ParseRecordCNAME(w, 0)
	if err != nil {
		t.Fatalf("ParseRecordCNAME() error = %v", err)
	}
	if pos != size {
		t.Errorf("AppendWireFormat() pos = %v, want %v", pos, size)
	}
	if !reflect.DeepEqual(got, cname) {
		t.Errorf("AppendWireFormat -> ParseRecordCNAME round trip: got = %v, want %v", got, cname)
	}
}

func TestRecordCNAMEAppendCanonicalWireFormat(t *testing.T) {
	cname := NewRecordCNAME(testDomainName(t, "WWW.EXAMPLE.COM"))

	var w WireFormat
	size := cname.AppendCanonicalWireFormat(&w)
	if size != 17 {
		t.Errorf("AppendCanonicalWireFormat() size = %v, want 17", size)
	}

	parsed, pos, err := ParseRecordCNAME(w, 0)
	if err != nil {
		t.Fatalf("ParseRecordCNAME() error = %v", err)
	}
	if pos != size {
		t.Errorf("AppendCanonicalWireFormat() pos = %v, want %v", pos, size)
	}
	if !reflect.DeepEqual(parsed, NewRecordCNAME(testDomainName(t, "www.example.com"))) {
		t.Errorf("AppendCanonicalWireFormat -> ParseRecordCNAME round trip: got = %v", parsed)
	}
}

// TestResourceRecordCNAME verifies that a CNAME record is read from and
// written to a message wire format through ParseResourceRecord and
// AppendResourceRecord.
func TestResourceRecordCNAME(t *testing.T) {
	rr := ResourceRecord{
		Name:  testDomainName(t, "alias.example.com"),
		Class: CLASS_IN,
		Type:  TYPE_CNAME,
		TTL:   3600,
		RData: NewRecordCNAME(testDomainName(t, "www.example.com")),
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
	rdata, ok := got.RData.(RecordCNAME)
	if !ok {
		t.Fatalf("ParseResourceRecord() RData = %T, want RecordCNAME", got.RData)
	}
	if !reflect.DeepEqual(rdata, NewRecordCNAME(testDomainName(t, "www.example.com"))) {
		t.Errorf("ParseResourceRecord() RData = %v, want %v", rdata, rr.RData)
	}
}

// TestRecordCNAMEJSON verifies the JSON form of a CNAME record: the canonical
// name is exported as its presentation-format string.
func TestRecordCNAMEJSON(t *testing.T) {
	cname := NewRecordCNAME(testDomainName(t, "www.example.com"))

	data, err := json.Marshal(cname)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	want := `{"CNAME":"www.example.com."}`
	if string(data) != want {
		t.Errorf("json.Marshal() = %q, want %q", string(data), want)
	}

	var got RecordCNAME
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	if !reflect.DeepEqual(got, cname) {
		t.Errorf("json.Unmarshal() = %v, want %v", got, cname)
	}

	var invalid RecordCNAME
	if err := json.Unmarshal([]byte(`{"CNAME":"www..example.com."}`), &invalid); err == nil {
		t.Error("json.Unmarshal() error = nil, want an error")
	}
}
