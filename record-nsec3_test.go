package dnsmsg

import (
	"bytes"
	"reflect"
	"testing"
)

func TestParseRecordNSEC3(t *testing.T) {
	// Salt = 0x1122, Next Hashed Name = 0x334455 (label length 3 + 3 bytes)
	// Hash Alg = 1 (SHA-1), Flags = 0, Iterations = 10, Salt Length = 2
	// Hash Length = 3, Type Bitmap: window 0, length 1, bitmap 0x60 (A + NS)
	base := []byte{
		0x01, // hash algorithm: SHA-1
		0x00, // flags
		0x00, 0x0a, // iterations: 10
		0x02, // salt length: 2
		0x11, 0x22, // salt
		0x03, // hash length: 3
		0x03, 0x33, 0x44, 0x55, // next hashed name: label length 3 + 3 bytes
		0x00, 0x01, 0x60, // type bitmap: window 0, length 1, A + NS
	}

	tests := []struct {
		name    string
		input   []byte
		begin   uint32
		end     uint32
		want    RecordNSEC3
		wantPos uint32
		wantErr bool
	}{
		{
			name:  "valid NSEC3 record",
			input: base,
			begin: 0,
			want: RecordNSEC3{
				HashAlgorithm:  HashAlgorithmSHA1,
				Flags:          0,
				Iterations:     10,
				Salt:           []byte{0x11, 0x22},
				NextHashedName: []byte{0x33, 0x44, 0x55},
				Types:          []ResourceType{TYPE_A, TYPE_NS},
			},
			wantPos: uint32(len(base)),
			wantErr: false,
		},
		{
			name:  "valid NSEC3 record with opt-out flag",
			input: append(
				[]byte{0x01, 0x01, 0x00, 0x05}, // hash alg SHA-1, flag opt-out, iterations 5
				0x00, // salt length 0
				0x00, // hash length 0
				// next hashed name: label length 0 + 0 bytes
				0x00,
				// no type bit maps
			),
			begin: 0,
			want: RecordNSEC3{
				HashAlgorithm:  HashAlgorithmSHA1,
				Flags:          FlagOptOut,
				Iterations:     5,
				Salt:           []byte{},
				NextHashedName: []byte{},
				Types:          []ResourceType{},
			},
			wantPos: 7,
			wantErr: false,
		},
		{
			name:  "valid NSEC3 record with salt and iterations",
			input: append(
				[]byte{0x01, 0x00, 0x00, 0x64}, // hash alg SHA-1, flags 0, iterations 100
				0x04, // salt length 4
				0xaa, 0xbb, 0xcc, 0xdd, // salt
				0x02, // hash length 2
				0x02, 0x12, 0x34, // next hashed name: label length 2 + 2 bytes
				0x00, 0x01, 0x40, // type bitmap: window 0, length 1, type A
			),
			begin: 0,
			want: RecordNSEC3{
				HashAlgorithm:  HashAlgorithmSHA1,
				Flags:          0,
				Iterations:     100,
				Salt:           []byte{0xaa, 0xbb, 0xcc, 0xdd},
				NextHashedName: []byte{0x12, 0x34},
				Types:          []ResourceType{TYPE_A},
			},
			wantPos: 16,
			wantErr: false,
		},
		{
			name:    "truncated input - missing hash algorithm",
			input:   []byte{},
			begin:   0,
			want:    RecordNSEC3{},
			wantErr: true,
		},
		{
			name:    "truncated input - missing flags",
			input:   []byte{0x01},
			begin:   0,
			want:    RecordNSEC3{},
			wantErr: true,
		},
		{
			name:    "truncated input - missing iterations",
			input:   []byte{0x01, 0x00},
			begin:   0,
			want:    RecordNSEC3{},
			wantErr: true,
		},
		{
			name:    "truncated input - missing salt length",
			input:   []byte{0x01, 0x00, 0x00, 0x0a},
			begin:   0,
			want:    RecordNSEC3{},
			wantErr: true,
		},
		{
			name:    "salt extends beyond record",
			input:   []byte{0x01, 0x00, 0x00, 0x0a, 0x03, 0xaa, 0xbb},
			begin:   0,
			end:   7,
			want:    RecordNSEC3{},
			wantErr: true,
		},
		{
			name:    "hash length label mismatch",
			input:   []byte{0x01, 0x00, 0x00, 0x0a, 0x00, 0x03, 0x02, 0x12, 0x34},
			begin:   0,
			want:    RecordNSEC3{},
			wantErr: true,
		},
		{
			name:    "next hashed name extends beyond record",
			input:   []byte{0x01, 0x00, 0x00, 0x0a, 0x00, 0x03, 0x03, 0x12},
			begin:   0,
			end:   9,
			want:    RecordNSEC3{},
			wantErr: true,
		},
		{
			name:    "out of bounds begin",
			input:   base,
			begin:   100,
			want:    RecordNSEC3{},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			end := tt.end
			if end == 0 {
				end = uint32(len(tt.input))
			}
			got, pos, err := ParseRecordNSEC3(tt.input, tt.begin, end)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseRecordNSEC3() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr {
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ParseRecordNSEC3() got = %v, want %v", got, tt.want)
			}
			if pos != tt.wantPos {
				t.Errorf("ParseRecordNSEC3() pos = %v, want %v", pos, tt.wantPos)
			}
		})
	}
}

func TestNewRecordNSEC3FromString(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    RecordNSEC3
		wantErr bool
	}{
		{
			name:  "valid NSEC3 string",
			input: "1 0 10 1122 334455 A NS",
			want: RecordNSEC3{
				HashAlgorithm:  HashAlgorithmSHA1,
				Flags:          0,
				Iterations:     10,
				Salt:           []byte{0x11, 0x22},
				NextHashedName: []byte{0x33, 0x44, 0x55},
				Types:          []ResourceType{TYPE_A, TYPE_NS},
			},
			wantErr: false,
		},
		{
			name:  "valid NSEC3 string with numeric type",
			input: "1 0 10 1122 334455 1 2",
			want: RecordNSEC3{
				HashAlgorithm:  HashAlgorithmSHA1,
				Flags:          0,
				Iterations:     10,
				Salt:           []byte{0x11, 0x22},
				NextHashedName: []byte{0x33, 0x44, 0x55},
				Types:          []ResourceType{TYPE_A, TYPE_NS},
			},
			wantErr: false,
		},
		{
			name:    "invalid format - too few fields",
			input:   "1 0 10 1122",
			want:    RecordNSEC3{},
			wantErr: true,
		},
		{
			name:    "invalid format - empty string",
			input:   "",
			want:    RecordNSEC3{},
			wantErr: true,
		},
		{
			name:    "invalid format - non-numeric hash algorithm",
			input:   "sha1 0 10 1122 334455 A",
			want:    RecordNSEC3{},
			wantErr: true,
		},
		{
			name:    "invalid format - invalid salt hex",
			input:   "1 0 10 zz 334455 A",
			want:    RecordNSEC3{},
			wantErr: true,
		},
		{
			name:    "invalid format - unknown type",
			input:   "1 0 10 1122 334455 FOO",
			want:    RecordNSEC3{},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewRecordNSEC3FromString(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewRecordNSEC3FromString() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewRecordNSEC3FromString() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRecordNSEC3String(t *testing.T) {
	tests := []struct {
		name  string
		input RecordNSEC3
		want  string
	}{
		{
			name: "A and NS types",
			input: RecordNSEC3{
				HashAlgorithm:  HashAlgorithmSHA1,
				Flags:          0,
				Iterations:     10,
				Salt:           []byte{0x11, 0x22},
				NextHashedName: []byte{0x33, 0x44, 0x55},
				Types:          []ResourceType{TYPE_A, TYPE_NS},
			},
			want: "1 0 10 1122 334455 A NS",
		},
		{
			name: "opt-out flag with empty salt and types",
			input: RecordNSEC3{
				HashAlgorithm:  HashAlgorithmSHA1,
				Flags:          FlagOptOut,
				Iterations:     5,
				Salt:           []byte{},
				NextHashedName: []byte{},
				Types:          []ResourceType{},
			},
			want: "1 1 5   ",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.input.String()
			if got != tt.want {
				t.Errorf("RecordNSEC3.String() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestRecordNSEC3Type(t *testing.T) {
	nsec3 := NewRecordNSEC3(1, 0, 10, []byte{0x11}, []byte{0x22}, []ResourceType{TYPE_A})
	if nsec3.Type() != TYPE_NSEC3 {
		t.Errorf("RecordNSEC3.Type() = %v, want %v", nsec3.Type(), TYPE_NSEC3)
	}
}

func TestRecordNSEC3CanonicalWireFormat(t *testing.T) {
	nsec3 := NewRecordNSEC3(
		HashAlgorithmSHA1,
		0,
		10,
		[]byte{0x11, 0x22},
		[]byte{0x33, 0x44, 0x55},
		[]ResourceType{TYPE_A, TYPE_NS},
	)
	want := []byte{
		0x01, // hash algorithm
		0x00, // flags
		0x00, 0x0a, // iterations: 10
		0x02, // salt length
		0x11, 0x22, // salt
		0x03, // hash length
		0x03, 0x33, 0x44, 0x55, // label length 3 + 3 bytes
		0x00, 0x01, 0x60, // type bitmap: window 0, length 1, A + NS
	}

	got := nsec3.CanonicalWireFormat()
	if !bytes.Equal(got, want) {
		t.Errorf("RecordNSEC3.CanonicalWireFormat() = %v, want %v", got, want)
	}
}

func TestRecordNSEC3RoundTrip(t *testing.T) {
	original := NewRecordNSEC3(
		HashAlgorithmSHA1,
		0,
		10,
		[]byte{0x11, 0x22},
		[]byte{0x33, 0x44, 0x55},
		[]ResourceType{TYPE_A, TYPE_NS},
	)

	wire := original.CanonicalWireFormat()
	parsed, end, err := ParseRecordNSEC3(wire, 0, uint32(len(wire)))
	if err != nil {
		t.Fatalf("ParseRecordNSEC3() error = %v", err)
	}
	if end != uint32(len(wire)) {
		t.Errorf("round trip end pos = %v, want %v", end, len(wire))
	}
	if !reflect.DeepEqual(parsed, original) {
		t.Errorf("round trip got = %v, want %v", parsed, original)
	}
}

func TestRecordNSEC3AppendWireFormat(t *testing.T) {
	nsec3 := NewRecordNSEC3(
		HashAlgorithmSHA1,
		0,
		10,
		[]byte{0x11, 0x22},
		[]byte{0x33, 0x44, 0x55},
		[]ResourceType{TYPE_A, TYPE_NS},
	)
	db := NewNameCompressionDB()

	var w WireFormat
	size := nsec3.AppendWireFormat(&w, db)

	want := []byte{
		0x01, 0x00, 0x00, 0x0a, 0x02, 0x11, 0x22,
		0x03, 0x03, 0x33, 0x44, 0x55,
		0x00, 0x01, 0x60,
	}
	if size != uint32(len(want)) {
		t.Errorf("AppendWireFormat() size = %v, want %d", size, len(want))
	}
	if !bytes.Equal(w, want) {
		t.Errorf("AppendWireFormat() = %v, want %v", w, want)
	}

	// Parse back from what we wrote
	got, pos, err := ParseRecordNSEC3(w, 0, uint32(len(w)))
	if err != nil {
		t.Fatalf("ParseRecordNSEC3() error = %v", err)
	}
	if pos != size {
		t.Errorf("ParseRecordNSEC3() pos = %v, want %v", pos, size)
	}
	if !reflect.DeepEqual(got, nsec3) {
		t.Errorf("ParseRecordNSEC3() got = %v, want %v", got, nsec3)
	}
}

func TestRecordNSEC3FromStringRoundTrip(t *testing.T) {
	input := "1 0 10 1122 334455 A NS"
	want := "1 0 10 1122 334455 A NS"

	nsec3, err := NewRecordNSEC3FromString(input)
	if err != nil {
		t.Fatalf("NewRecordNSEC3FromString() error = %v", err)
	}

	output := nsec3.String()
	if output != want {
		t.Errorf("round trip string = %q, want %q", output, want)
	}
}

func TestNewRecordNSEC3(t *testing.T) {
	types := []ResourceType{TYPE_NS, TYPE_A} // unsorted input
	nsec3 := NewRecordNSEC3(1, 0, 10, []byte{0x11}, []byte{0x22}, types)

	if nsec3.HashAlgorithm != 1 {
		t.Errorf("HashAlgorithm = %v, want 1", nsec3.HashAlgorithm)
	}
	if nsec3.Iterations != 10 {
		t.Errorf("Iterations = %v, want 10", nsec3.Iterations)
	}
	if !bytes.Equal(nsec3.Salt, []byte{0x11}) {
		t.Errorf("Salt = %v, want [0x11]", nsec3.Salt)
	}
	if !bytes.Equal(nsec3.NextHashedName, []byte{0x22}) {
		t.Errorf("NextHashedName = %v, want [0x22]", nsec3.NextHashedName)
	}
	wantTypes := []ResourceType{TYPE_A, TYPE_NS} // sorted
	if !reflect.DeepEqual(nsec3.Types, wantTypes) {
		t.Errorf("Types = %v, want %v", nsec3.Types, wantTypes)
	}
}

func TestRecordNSEC3MarshalJSON(t *testing.T) {
	nsec3 := NewRecordNSEC3(
		HashAlgorithmSHA1,
		0,
		10,
		[]byte{0x11, 0x22},
		[]byte{0x33, 0x44, 0x55},
		[]ResourceType{TYPE_A, TYPE_NS},
	)
	data, err := nsec3.MarshalJSON()
	if err != nil {
		t.Fatalf("RecordNSEC3.MarshalJSON() error = %v", err)
	}
	var decoded RecordNSEC3
	if err := decoded.UnmarshalJSON(data); err != nil {
		t.Fatalf("RecordNSEC3.UnmarshalJSON() error = %v", err)
	}
	if !reflect.DeepEqual(decoded, nsec3) {
		t.Errorf("JSON round trip got = %v, want %v", decoded, nsec3)
	}
}

func TestNSEC3FlagOptOut(t *testing.T) {
	if FlagOptOut != 0x01 {
		t.Errorf("FlagOptOut = %v, want 0x01", FlagOptOut)
	}
}

func TestNSEC3HashAlgorithmSHA1(t *testing.T) {
	if HashAlgorithmSHA1 != 1 {
		t.Errorf("HashAlgorithmSHA1 = %v, want 1", HashAlgorithmSHA1)
	}
}
