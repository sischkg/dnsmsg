package dnsmsg

import (
	"bytes"
	"reflect"
	"testing"
)

func TestParseRecordNSEC(t *testing.T) {
	// example.org. as a domain name: \x07example\x03org\x00
	exampleOrg := []byte{0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x03, 'o', 'r', 'g', 0x00}

	tests := []struct {
		name    string
		input   []byte
		begin   uint32
		end     uint32
		want    RecordNSEC
		wantPos uint32
		wantErr bool
	}{
		{
			name:  "valid NSEC record with A and NS",
			input: append(
				exampleOrg,
				0x00, // type bitmap window 0
				0x01, // bitmap length 1 octet
				0x60, // bitmap: type A (bit 6) and NS (bit 5)
			),
			begin: 0,
			want: RecordNSEC{
				NextDomainName: mustDomainName(t, "example.org"),
				Types:          []ResourceType{TYPE_A, TYPE_NS},
			},
			wantPos: 16,
			wantErr: false,
		},
		{
			name:  "valid NSEC record spanning two type bitmap windows",
			input: append(
				exampleOrg,
				// window 0: type A (offset 1) -> length 1, bitmap 0x40
				0x00, 0x01, 0x40,
				// window 1: type 300 (offset 44) -> length 6, bitmap octet 5 bit 3 = 0x08
				0x01, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08,
			),
			begin: 0,
			want: RecordNSEC{
				NextDomainName: mustDomainName(t, "example.org"),
				Types:          []ResourceType{TYPE_A, ResourceType(300)},
			},
			wantPos: 13 + 3 + 8,
			wantErr: false,
		},
		{
			name:  "valid NSEC record with empty type bit maps",
			input: exampleOrg,
			begin: 0,
			end:   uint32(len(exampleOrg)),
			want: RecordNSEC{
				NextDomainName: mustDomainName(t, "example.org"),
				Types:          []ResourceType{},
			},
			wantPos: uint32(len(exampleOrg)),
			wantErr: false,
		},
		{
			name:  "valid NSEC record with root next domain name",
			input: append(
				[]byte{0x00}, // root domain name
				0x00, 0x01, 0x40, // type bitmap: type A
			),
			begin: 0,
			want: RecordNSEC{
				NextDomainName: NewRootDomainName(),
				Types:          []ResourceType{TYPE_A},
			},
			wantPos: 4,
			wantErr: false,
		},
		{
			name:    "truncated input - missing next domain name",
			input:   []byte{0x07, 'e', 'x'},
			begin:   0,
			want:    RecordNSEC{},
			wantErr: true,
		},
		{
			name:    "truncated input - missing type bitmap window header",
			input:   append(exampleOrg, 0x00),
			begin:   0,
			end:   uint32(len(exampleOrg) + 1),
			want:    RecordNSEC{},
			wantErr: true,
		},
		{
			name:    "invalid type bitmap length zero",
			input:   append(exampleOrg, 0x00, 0x00),
			begin:   0,
			end:   uint32(len(exampleOrg) + 2),
			want:    RecordNSEC{},
			wantErr: true,
		},
		{
			name:    "invalid type bitmap length over 32",
			input:   append(exampleOrg, 0x00, 0x21),
			begin:   0,
			end:   uint32(len(exampleOrg) + 2),
			want:    RecordNSEC{},
			wantErr: true,
		},
		{
			name:    "type bitmap extends beyond record",
			input:   append(exampleOrg, 0x00, 0x02, 0x60),
			begin:   0,
			end:   uint32(len(exampleOrg) + 2),
			want:    RecordNSEC{},
			wantErr: true,
		},
		{
			name:    "out of bounds begin",
			input:   exampleOrg,
			begin:   100,
			want:    RecordNSEC{},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			end := tt.end
			if end == 0 {
				end = uint32(len(tt.input))
			}
			got, pos, err := ParseRecordNSEC(tt.input, tt.begin, end)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseRecordNSEC() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ParseRecordNSEC() got = %v, want %v", got, tt.want)
			}
			if pos != tt.wantPos {
				t.Errorf("ParseRecordNSEC() pos = %v, want %v", pos, tt.wantPos)
			}
		})
	}
}

func TestNewRecordNSECFromString(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    RecordNSEC
		wantErr bool
	}{
		{
			name:  "valid NSEC string with type names",
			input: "example.org A NS",
			want: RecordNSEC{
				NextDomainName: mustDomainName(t, "example.org"),
				Types:          []ResourceType{TYPE_A, TYPE_NS},
			},
			wantErr: false,
		},
		{
			name:  "valid NSEC string with numeric type codes",
			input: "example.org 1 2",
			want: RecordNSEC{
				NextDomainName: mustDomainName(t, "example.org"),
				Types:          []ResourceType{TYPE_A, TYPE_NS},
			},
			wantErr: false,
		},
		{
			name:  "valid NSEC string with TYPE prefix",
			input: "example.org TYPE1 TYPE2",
			want: RecordNSEC{
				NextDomainName: mustDomainName(t, "example.org"),
				Types:          []ResourceType{TYPE_A, TYPE_NS},
			},
			wantErr: false,
		},
		{
			name:    "invalid format - missing fields",
			input:   "example.org",
			want:    RecordNSEC{},
			wantErr: true,
		},
		{
			name:    "invalid format - empty string",
			input:   "",
			want:    RecordNSEC{},
			wantErr: true,
		},
		{
			name:    "invalid format - unknown type name",
			input:   "example.org FOO",
			want:    RecordNSEC{},
			wantErr: true,
		},
		{
			name:    "invalid format - invalid domain name",
			input:   "example..org A",
			want:    RecordNSEC{},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewRecordNSECFromString(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewRecordNSECFromString() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewRecordNSECFromString() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRecordNSECString(t *testing.T) {
	tests := []struct {
		name  string
		input RecordNSEC
		want  string
	}{
		{
			name: "A and NS types",
			input: RecordNSEC{
				NextDomainName: mustDomainName(t, "example.org"),
				Types:          []ResourceType{TYPE_A, TYPE_NS},
			},
			want: "example.org. A NS",
		},
		{
			name: "single type",
			input: RecordNSEC{
				NextDomainName: mustDomainName(t, "example.org"),
				Types:          []ResourceType{TYPE_SOA},
			},
			want: "example.org. SOA",
		},
		{
			name: "numeric-only type",
			input: RecordNSEC{
				NextDomainName: mustDomainName(t, "example.org"),
				Types:          []ResourceType{ResourceType(300)},
			},
			want: "example.org. TYPE300",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.input.String()
			if got != tt.want {
				t.Errorf("RecordNSEC.String() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestRecordNSECType(t *testing.T) {
	nsec := NewRecordNSEC(mustDomainName(t, "example.org"), []ResourceType{TYPE_A})
	if nsec.Type() != TYPE_NSEC {
		t.Errorf("RecordNSEC.Type() = %v, want %v", nsec.Type(), TYPE_NSEC)
	}
}

func TestRecordNSECCanonicalWireFormat(t *testing.T) {
	nsec := NewRecordNSEC(
		mustDomainName(t, "example.org"),
		[]ResourceType{TYPE_A, TYPE_NS},
	)
	want := []byte{
		0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x03, 'o', 'r', 'g', 0x00,
		0x00, 0x01, 0x60,
	}

	got := nsec.CanonicalWireFormat()
	if !bytes.Equal(got, want) {
		t.Errorf("RecordNSEC.CanonicalWireFormat() = %v, want %v", got, want)
	}
}

func TestRecordNSECRoundTrip(t *testing.T) {
	original := NewRecordNSEC(
		mustDomainName(t, "example.org"),
		[]ResourceType{TYPE_A, TYPE_NS, ResourceType(300)},
	)

	wire := original.CanonicalWireFormat()
	parsed, end, err := ParseRecordNSEC(wire, 0, uint32(len(wire)))
	if err != nil {
		t.Fatalf("ParseRecordNSEC() error = %v", err)
	}
	if end != uint32(len(wire)) {
		t.Errorf("round trip end pos = %v, want %v", end, len(wire))
	}
	if !reflect.DeepEqual(parsed, original) {
		t.Errorf("round trip got = %v, want %v", parsed, original)
	}
}

func TestRecordNSECAppendWireFormat(t *testing.T) {
	nsec := NewRecordNSEC(
		mustDomainName(t, "example.org"),
		[]ResourceType{TYPE_A, TYPE_NS},
	)
	db := NewNameCompressionDB()

	var w WireFormat
	size := nsec.AppendWireFormat(&w, db)

	want := []byte{
		0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x03, 'o', 'r', 'g', 0x00,
		0x00, 0x01, 0x60,
	}
	if size != uint32(len(want)) {
		t.Errorf("AppendWireFormat() size = %v, want %d", size, len(want))
	}
	if !bytes.Equal(w, want) {
		t.Errorf("AppendWireFormat() = %v, want %v", w, want)
	}

	// Parse back from what we wrote
	got, pos, err := ParseRecordNSEC(w, 0, uint32(len(w)))
	if err != nil {
		t.Fatalf("ParseRecordNSEC() error = %v", err)
	}
	if pos != size {
		t.Errorf("ParseRecordNSEC() pos = %v, want %v", pos, size)
	}
	if !reflect.DeepEqual(got, nsec) {
		t.Errorf("ParseRecordNSEC() got = %v, want %v", got, nsec)
	}
}

func TestRecordNSECFromStringRoundTrip(t *testing.T) {
	input := "example.org A NS"
	want := "example.org. A NS"

	nsec, err := NewRecordNSECFromString(input)
	if err != nil {
		t.Fatalf("NewRecordNSECFromString() error = %v", err)
	}

	output := nsec.String()
	if output != want {
		t.Errorf("round trip string = %q, want %q", output, want)
	}
}

func TestNewRecordNSEC(t *testing.T) {
	next := mustDomainName(t, "example.org")
	types := []ResourceType{TYPE_NS, TYPE_A} // unsorted input
	nsec := NewRecordNSEC(next, types)

	if !nsec.NextDomainName.Equal(next) {
		t.Errorf("NextDomainName = %v, want %v", nsec.NextDomainName, next)
	}
	wantTypes := []ResourceType{TYPE_A, TYPE_NS} // sorted
	if !reflect.DeepEqual(nsec.Types, wantTypes) {
		t.Errorf("Types = %v, want %v", nsec.Types, wantTypes)
	}
}

func TestRecordNSECMarshalJSON(t *testing.T) {
	nsec := NewRecordNSEC(
		mustDomainName(t, "example.org"),
		[]ResourceType{TYPE_A, TYPE_NS},
	)
	data, err := nsec.MarshalJSON()
	if err != nil {
		t.Fatalf("RecordNSEC.MarshalJSON() error = %v", err)
	}
	var decoded RecordNSEC
	if err := decoded.UnmarshalJSON(data); err != nil {
		t.Fatalf("RecordNSEC.UnmarshalJSON() error = %v", err)
	}
	if !reflect.DeepEqual(decoded, nsec) {
		t.Errorf("JSON round trip got = %v, want %v", decoded, nsec)
	}
}

func TestTypeBitmapCrossesWindowBoundary(t *testing.T) {
	// Types {A(1), TYPE300(300)} span windows 0 and 1.
	nsec := NewRecordNSEC(
		mustDomainName(t, "example.org"),
		[]ResourceType{TYPE_A, ResourceType(300)},
	)
	wire := nsec.CanonicalWireFormat()
	parsed, end, err := ParseRecordNSEC(wire, 0, uint32(len(wire)))
	if err != nil {
		t.Fatalf("ParseRecordNSEC() error = %v", err)
	}
	if end != uint32(len(wire)) {
		t.Errorf("end pos = %v, want %v", end, len(wire))
	}
	if !reflect.DeepEqual(parsed.Types, []ResourceType{TYPE_A, ResourceType(300)}) {
		t.Errorf("parsed types = %v, want [A TYPE300]", parsed.Types)
	}
}

// mustDomainName is a test helper that panics on error.
func mustDomainName(t *testing.T, name string) DomainName {
	t.Helper()
	d, err := NewDomainNameFromString(name)
	if err != nil {
		t.Fatalf("NewDomainNameFromString(%q): %v", name, err)
	}
	return d
}
