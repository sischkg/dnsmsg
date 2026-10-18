package dnsmsg

import (
	"bytes"
	"reflect"
	"testing"
)

func TestParseRecordNSEC3PARAM(t *testing.T) {
	// Salt = 0x1122, Type Bitmap: window 0, length 1, bitmap 0x60 (A + NS)
	base := []byte{
		0x01, // hash algorithm: SHA-1
		0x00, // flags
		0x00, 0x0a, // iterations: 10
		0x02, // salt length: 2
		0x11, 0x22, // salt
		0x00, 0x01, 0x60, // type bitmap: window 0, length 1, A + NS
	}

	tests := []struct {
		name    string
		input   []byte
		begin   uint32
		end     uint32
		want    RecordNSEC3PARAM
		wantPos uint32
		wantErr bool
	}{
		{
			name:  "valid NSEC3PARAM record",
			input: base,
			begin: 0,
			want: RecordNSEC3PARAM{
				HashAlgorithm: HashAlgorithmSHA1,
				Flags:         0,
				Iterations:    10,
				Salt:          []byte{0x11, 0x22},
				Types:         []ResourceType{TYPE_A, TYPE_NS},
			},
			wantPos: uint32(len(base)),
			wantErr: false,
		},
		{
			name:  "valid NSEC3PARAM record with opt-out flag",
			input: append(
				[]byte{0x01, 0x01, 0x00, 0x05}, // hash alg SHA-1, flag opt-out, iterations 5
				0x00, // salt length 0
				// no type bit maps
			),
			begin: 0,
			want: RecordNSEC3PARAM{
				HashAlgorithm: HashAlgorithmSHA1,
				Flags:         FlagOptOut,
				Iterations:    5,
				Salt:          []byte{},
				Types:         []ResourceType{},
			},
			wantPos: 5,
			wantErr: false,
		},
		{
			name:  "valid NSEC3PARAM record with salt and iterations",
			input: append(
				[]byte{0x01, 0x00, 0x00, 0x64}, // hash alg SHA-1, flags 0, iterations 100
				0x04, // salt length 4
				0xaa, 0xbb, 0xcc, 0xdd, // salt
				0x00, 0x01, 0x40, // type bitmap: window 0, length 1, type A
			),
			begin: 0,
			want: RecordNSEC3PARAM{
				HashAlgorithm: HashAlgorithmSHA1,
				Flags:         0,
				Iterations:    100,
				Salt:          []byte{0xaa, 0xbb, 0xcc, 0xdd},
				Types:         []ResourceType{TYPE_A},
			},
			wantPos: 12,
			wantErr: false,
		},
		{
			name:    "truncated input - missing hash algorithm",
			input:   []byte{},
			begin:   0,
			want:    RecordNSEC3PARAM{},
			wantErr: true,
		},
		{
			name:    "truncated input - missing flags",
			input:   []byte{0x01},
			begin:   0,
			want:    RecordNSEC3PARAM{},
			wantErr: true,
		},
		{
			name:    "truncated input - missing iterations",
			input:   []byte{0x01, 0x00},
			begin:   0,
			want:    RecordNSEC3PARAM{},
			wantErr: true,
		},
		{
			name:    "truncated input - missing salt length",
			input:   []byte{0x01, 0x00, 0x00, 0x0a},
			begin:   0,
			want:    RecordNSEC3PARAM{},
			wantErr: true,
		},
		{
			name:    "salt extends beyond record",
			input:   []byte{0x01, 0x00, 0x00, 0x0a, 0x03, 0xaa, 0xbb},
			begin:   0,
			end:   7,
			want:    RecordNSEC3PARAM{},
			wantErr: true,
		},
		{
			name:    "out of bounds begin",
			input:   base,
			begin:   100,
			want:    RecordNSEC3PARAM{},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			end := tt.end
			if end == 0 {
				end = uint32(len(tt.input))
			}
			got, pos, err := ParseRecordNSEC3PARAM(tt.input, tt.begin, end)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseRecordNSEC3PARAM() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr {
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ParseRecordNSEC3PARAM() got = %v, want %v", got, tt.want)
			}
			if pos != tt.wantPos {
				t.Errorf("ParseRecordNSEC3PARAM() pos = %v, want %v", pos, tt.wantPos)
			}
		})
	}
}

func TestNewRecordNSEC3PARAMFromString(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    RecordNSEC3PARAM
		wantErr bool
	}{
		{
			name:  "valid NSEC3PARAM string",
			input: "1 0 10 1122 A NS",
			want: RecordNSEC3PARAM{
				HashAlgorithm: HashAlgorithmSHA1,
				Flags:         0,
				Iterations:    10,
				Salt:          []byte{0x11, 0x22},
				Types:         []ResourceType{TYPE_A, TYPE_NS},
			},
			wantErr: false,
		},
		{
			name:  "valid NSEC3PARAM string with numeric type",
			input: "1 0 10 1122 1 2",
			want: RecordNSEC3PARAM{
				HashAlgorithm: HashAlgorithmSHA1,
				Flags:         0,
				Iterations:    10,
				Salt:          []byte{0x11, 0x22},
				Types:         []ResourceType{TYPE_A, TYPE_NS},
			},
			wantErr: false,
		},
		{
			name:    "invalid format - too few fields",
			input:   "1 0 10 1122",
			want:    RecordNSEC3PARAM{},
			wantErr: true,
		},
		{
			name:    "invalid format - empty string",
			input:   "",
			want:    RecordNSEC3PARAM{},
			wantErr: true,
		},
		{
			name:    "invalid format - non-numeric hash algorithm",
			input:   "sha1 0 10 1122 A",
			want:    RecordNSEC3PARAM{},
			wantErr: true,
		},
		{
			name:    "invalid format - invalid salt hex",
			input:   "1 0 10 zz A",
			want:    RecordNSEC3PARAM{},
			wantErr: true,
		},
		{
			name:    "invalid format - unknown type",
			input:   "1 0 10 1122 FOO",
			want:    RecordNSEC3PARAM{},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewRecordNSEC3PARAMFromString(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewRecordNSEC3PARAMFromString() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewRecordNSEC3PARAMFromString() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRecordNSEC3PARAMString(t *testing.T) {
	tests := []struct {
		name  string
		input RecordNSEC3PARAM
		want  string
	}{
		{
			name: "A and NS types",
			input: RecordNSEC3PARAM{
				HashAlgorithm: HashAlgorithmSHA1,
				Flags:         0,
				Iterations:    10,
				Salt:          []byte{0x11, 0x22},
				Types:         []ResourceType{TYPE_A, TYPE_NS},
			},
			want: "1 0 10 1122 A NS",
		},
		{
			name: "opt-out flag with empty salt and types",
			input: RecordNSEC3PARAM{
				HashAlgorithm: HashAlgorithmSHA1,
				Flags:         FlagOptOut,
				Iterations:    5,
				Salt:          []byte{},
				Types:         []ResourceType{},
			},
			want: "1 1 5  ",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.input.String()
			if got != tt.want {
				t.Errorf("RecordNSEC3PARAM.String() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestRecordNSEC3PARAMType(t *testing.T) {
	nsec3param := NewRecordNSEC3PARAM(1, 0, 10, []byte{0x11}, []ResourceType{TYPE_A})
	if nsec3param.Type() != TYPE_NSEC3PARAM {
		t.Errorf("RecordNSEC3PARAM.Type() = %v, want %v", nsec3param.Type(), TYPE_NSEC3PARAM)
	}
}

func TestRecordNSEC3PARAMCanonicalWireFormat(t *testing.T) {
	nsec3param := NewRecordNSEC3PARAM(
		HashAlgorithmSHA1,
		0,
		10,
		[]byte{0x11, 0x22},
		[]ResourceType{TYPE_A, TYPE_NS},
	)
	want := []byte{
		0x01, // hash algorithm
		0x00, // flags
		0x00, 0x0a, // iterations: 10
		0x02, // salt length
		0x11, 0x22, // salt
		0x00, 0x01, 0x60, // type bitmap: window 0, length 1, A + NS
	}

	got := nsec3param.CanonicalWireFormat()
	if !bytes.Equal(got, want) {
		t.Errorf("RecordNSEC3PARAM.CanonicalWireFormat() = %v, want %v", got, want)
	}
}

func TestRecordNSEC3PARAMRoundTrip(t *testing.T) {
	original := NewRecordNSEC3PARAM(
		HashAlgorithmSHA1,
		0,
		10,
		[]byte{0x11, 0x22},
		[]ResourceType{TYPE_A, TYPE_NS},
	)

	wire := original.CanonicalWireFormat()
	parsed, end, err := ParseRecordNSEC3PARAM(wire, 0, uint32(len(wire)))
	if err != nil {
		t.Fatalf("ParseRecordNSEC3PARAM() error = %v", err)
	}
	if end != uint32(len(wire)) {
		t.Errorf("round trip end pos = %v, want %v", end, len(wire))
	}
	if !reflect.DeepEqual(parsed, original) {
		t.Errorf("round trip got = %v, want %v", parsed, original)
	}
}

func TestRecordNSEC3PARAMAppendWireFormat(t *testing.T) {
	nsec3param := NewRecordNSEC3PARAM(
		HashAlgorithmSHA1,
		0,
		10,
		[]byte{0x11, 0x22},
		[]ResourceType{TYPE_A, TYPE_NS},
	)
	db := NewNameCompressionDB()

	var w WireFormat
	size := nsec3param.AppendWireFormat(&w, db)

	want := []byte{
		0x01, 0x00, 0x00, 0x0a, 0x02, 0x11, 0x22,
		0x00, 0x01, 0x60,
	}
	if size != uint32(len(want)) {
		t.Errorf("AppendWireFormat() size = %v, want %d", size, len(want))
	}
	if !bytes.Equal(w, want) {
		t.Errorf("AppendWireFormat() = %v, want %v", w, want)
	}

	// Parse back from what we wrote
	got, pos, err := ParseRecordNSEC3PARAM(w, 0, uint32(len(w)))
	if err != nil {
		t.Fatalf("ParseRecordNSEC3PARAM() error = %v", err)
	}
	if pos != size {
		t.Errorf("ParseRecordNSEC3PARAM() pos = %v, want %v", pos, size)
	}
	if !reflect.DeepEqual(got, nsec3param) {
		t.Errorf("ParseRecordNSEC3PARAM() got = %v, want %v", got, nsec3param)
	}
}

func TestRecordNSEC3PARAMFromStringRoundTrip(t *testing.T) {
	input := "1 0 10 1122 A NS"
	want := "1 0 10 1122 A NS"

	nsec3param, err := NewRecordNSEC3PARAMFromString(input)
	if err != nil {
		t.Fatalf("NewRecordNSEC3PARAMFromString() error = %v", err)
	}

	output := nsec3param.String()
	if output != want {
		t.Errorf("round trip string = %q, want %q", output, want)
	}
}

func TestNewRecordNSEC3PARAM(t *testing.T) {
	types := []ResourceType{TYPE_NS, TYPE_A} // unsorted input
	nsec3param := NewRecordNSEC3PARAM(1, 0, 10, []byte{0x11}, types)

	if nsec3param.HashAlgorithm != 1 {
		t.Errorf("HashAlgorithm = %v, want 1", nsec3param.HashAlgorithm)
	}
	if nsec3param.Iterations != 10 {
		t.Errorf("Iterations = %v, want 10", nsec3param.Iterations)
	}
	if !bytes.Equal(nsec3param.Salt, []byte{0x11}) {
		t.Errorf("Salt = %v, want [0x11]", nsec3param.Salt)
	}
	wantTypes := []ResourceType{TYPE_A, TYPE_NS} // sorted
	if !reflect.DeepEqual(nsec3param.Types, wantTypes) {
		t.Errorf("Types = %v, want %v", nsec3param.Types, wantTypes)
	}
}

func TestRecordNSEC3PARAMMarshalJSON(t *testing.T) {
	nsec3param := NewRecordNSEC3PARAM(
		HashAlgorithmSHA1,
		0,
		10,
		[]byte{0x11, 0x22},
		[]ResourceType{TYPE_A, TYPE_NS},
	)
	data, err := nsec3param.MarshalJSON()
	if err != nil {
		t.Fatalf("RecordNSEC3PARAM.MarshalJSON() error = %v", err)
	}
	var decoded RecordNSEC3PARAM
	if err := decoded.UnmarshalJSON(data); err != nil {
		t.Fatalf("RecordNSEC3PARAM.UnmarshalJSON() error = %v", err)
	}
	if !reflect.DeepEqual(decoded, nsec3param) {
		t.Errorf("JSON round trip got = %v, want %v", decoded, nsec3param)
	}
}
