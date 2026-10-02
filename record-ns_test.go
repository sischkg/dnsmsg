package dnsmsg

import (
	"bytes"
	"reflect"
	"testing"
)

func TestParseRecordNS(t *testing.T) {
	tests := []struct {
		name    string
		input   []byte
		begin   uint32
		want    RecordNS
		wantPos uint32
		wantErr bool
	}{
		{
			name:    "simple NS record",
			input:   []byte{3, 'n', 's', '1', 3, 'e', 'x', 'a', 3, 'c', 'o', 'm', 0},
			begin:   0,
			want:    NewRecordNS(Domainname{{'n', 's', '1'}, {'e', 'x', 'a'}, {'c', 'o', 'm'}}),
			wantPos: 13,
			wantErr: false,
		},
		{
			name:    "fully qualified domain",
			input:   []byte{3, 'w', 'w', 'w', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0},
			begin:   0,
			want:    NewRecordNS(Domainname{{'w', 'w', 'w'}, {'e', 'x', 'a', 'm', 'p', 'l', 'e'}, {'c', 'o', 'm'}}),
			wantPos: 17,
			wantErr: false,
		},
		{
			name:    "truncated input",
			input:   []byte{3, 'w', 'w', 'w'},
			begin:   0,
			want:    RecordNS{},
			wantErr: true,
		},
		{
			name:    "out of bounds",
			input:   []byte{1, 'a'},
			begin:   10,
			want:    RecordNS{},
			wantPos: 10,
			wantErr: true,
		},
		{
			name: "with compression pointer",
			// pos 0: www.example.com; pos 17: 0xC0 0x00 (points to pos 0)
			input:   []byte{3, 'w', 'w', 'w', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, 0xC0, 0x00},
			begin:   17,
			want:    NewRecordNS(Domainname{{'w', 'w', 'w'}, {'e', 'x', 'a', 'm', 'p', 'l', 'e'}, {'c', 'o', 'm'}}),
			wantPos: 19,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, pos, err := ParseRecordNS(tt.input, tt.begin)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseRecordNS() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ParseRecordNS() got = %v, want %v", got, tt.want)
			}
			if pos != tt.wantPos {
				t.Errorf("ParseRecordNS() pos = %v, want %v", pos, tt.wantPos)
			}
		})
	}
}

func TestNewRecordNSFromString(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    RecordNS
		wantErr bool
	}{
		{
			name:    "simple nameserver",
			input:   "ns1.example.com.",
			want:    NewRecordNS(Domainname{{'n', 's', '1'}, {'e', 'x', 'a', 'm', 'p', 'l', 'e'}, {'c', 'o', 'm'}, {}}),
			wantErr: false,
		},
		{
			name:    "root domain",
			input:   ".",
			want:    NewRecordNS(Domainname{}),
			wantErr: false,
		},
		{
			name:    "invalid domain with consecutive dots",
			input:   "ns1..example.com.",
			want:    RecordNS{},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewRecordNSFromString(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewRecordNSFromString() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewRecordNSFromString() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRecordNSString(t *testing.T) {
	tests := []struct {
		name  string
		input RecordNS
		want  string
	}{
		{
			name:  "simple nameserver",
			input: NewRecordNS(Domainname{{'n', 's', '1'}, {'e', 'x', 'a', 'm', 'p', 'l', 'e'}, {'c', 'o', 'm'}}),
			want:  "ns1.example.com.",
		},
		{
			name:  "root domain",
			input: NewRecordNS(Domainname{{}}),
			want:  ".",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.input.String()
			if got != tt.want {
				t.Errorf("RecordNS.String() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestRecordNSType(t *testing.T) {
	ns := NewRecordNS(Domainname{{'n', 's', '1'}})
	if ns.Type() != TYPE_NS {
		t.Errorf("RecordNS.Type() = %v, want %v", ns.Type(), TYPE_NS)
	}
}

func TestRecordNSCanonicalWireFormat(t *testing.T) {
	// Test that canonical wire format is lowercase
	ns := NewRecordNS(Domainname{{'N', 'S', '1'}, {'E', 'X', 'A', 'M', 'P', 'L', 'E'}, {'C', 'O', 'M'}})
	want := []byte{3, 'n', 's', '1', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0}

	got := ns.CanonicalWireFormat()
	if !bytes.Equal(got, want) {
		t.Errorf("RecordNS.CanonicalWireFormat() = %v, want %v", got, want)
	}
}

func TestRecordNSRoundTrip(t *testing.T) {
	original := NewRecordNS(Domainname{{'n', 's', '1'}, {'e', 'x', 'a', 'm', 'p', 'l', 'e'}, {'c', 'o', 'm'}})

	// Serialize to canonical wire format
	wire := original.CanonicalWireFormat()

	// Parse back
	parsed, end, err := ParseRecordNS(wire, 0)
	if err != nil {
		t.Fatalf("ParseRecordNS() error = %v", err)
	}
	if end != uint32(len(wire)) {
		t.Errorf("round trip end pos = %v, want %v", end, len(wire))
	}
	if !reflect.DeepEqual(parsed, original) {
		t.Errorf("round trip got = %v, want %v", parsed, original)
	}
}

func TestRecordNSAppendWireFormat(t *testing.T) {
	ns := NewRecordNS(Domainname{{'n', 's', '1'}, {'e', 'x', 'a', 'm', 'p', 'l', 'e'}, {'c', 'o', 'm'}})
	db := NewNameCompressionDB()

	var w WireFormat
	size := ns.AppendWireFormat(&w, db)
	if size != 17 {
		t.Errorf("AppendWireFormat() size = %v, want 17", size)
	}

	// Parse back from what we wrote
	got, pos, err := ParseRecordNS(w, 0)
	if err != nil {
		t.Fatalf("ParseRecordNS() error = %v", err)
	}
	if pos != size {
		t.Errorf("ParseRecordNS() pos = %v, want %v", pos, size)
	}
	if !reflect.DeepEqual(got, ns) {
		t.Errorf("AppendWireFormat -> ParseRecordNS round trip: got = %v, want %v", got, ns)
	}
}
