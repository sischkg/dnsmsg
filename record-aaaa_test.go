package dnsmsg

import (
	"reflect"
	"testing"
)

func TestParseRecordAAAA(t *testing.T) {
	tests := []struct {
		name    string
		input   []byte
		begin   uint32
		want    RecordAAAA
		wantPos uint32
		wantErr bool
	}{
		{
			name:    "loopback IPv6",
			input:   []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
			begin:   0,
			want:    NewRecordAAAA([16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}),
			wantPos: 16,
			wantErr: false,
		},
		{
			name:    "fully specified IPv6",
			input:   []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0x0d, 0x47, 0x00, 0xbb},
			begin:   0,
			want:    NewRecordAAAA([16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0x0d, 0x47, 0x00, 0xbb}),
			wantPos: 16,
			wantErr: false,
		},
		{
			name:    "truncated input",
			input:   []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
			begin:   0,
			want:    RecordAAAA{},
			wantErr: true,
		},
		{
			name:    "out of bounds begin offset",
			input:   []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
			begin:   10,
			want:    RecordAAAA{},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, pos, err := ParseRecordAAAA(tt.input, tt.begin)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseRecordAAAA() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ParseRecordAAAA() got = %v, want %v", got, tt.want)
			}
			if pos != tt.wantPos {
				t.Errorf("ParseRecordAAAA() pos = %v, want %v", pos, tt.wantPos)
			}
		})
	}
}

func TestNewRecordAAAAFromString(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    RecordAAAA
		wantErr bool
	}{
		{
			name:    "loopback",
			input:   "0000:0000:0000:0000:0000:0000:0000:0001",
			want:    NewRecordAAAA([16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}),
			wantErr: false,
		},
		{
			name:    "compressed IPv6",
			input:   "2001:db8::d47:0bb",
			want:    NewRecordAAAA([16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0x0d, 0x47, 0x00, 0xbb}),
			wantErr: false,
		},
		{
			name:    "IPv4 address",
			input:   "192.168.1.1",
			want:    RecordAAAA{},
			wantErr: true,
		},
		{
			name:    "invalid address",
			input:   "gggg::1",
			want:    RecordAAAA{},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewRecordAAAAFromString(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewRecordAAAAFromString() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewRecordAAAAFromString() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRecordAAAAString(t *testing.T) {
	tests := []struct {
		name  string
		input RecordAAAA
		want  string
	}{
		{
			name:  "loopback",
			input: NewRecordAAAA([16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}),
			want:  "::1",
		},
		{
			name:  "global unicast",
			input: NewRecordAAAA([16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0x0d, 0x47, 0x00, 0xbb}),
			want:  "2001:db8::d47:bb",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.input.String()
			if got != tt.want {
				t.Errorf("RecordAAAA.String() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestRecordAAAAType(t *testing.T) {
	aaaa := NewRecordAAAA([16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1})
	if aaaa.Type() != TYPE_AAAA {
		t.Errorf("RecordAAAA.Type() = %v, want %v", aaaa.Type(), TYPE_AAAA)
	}
}

func TestRecordAAAARoundTrip(t *testing.T) {
	original := NewRecordAAAA([16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0x0d, 0x47, 0x00, 0xbb})

	wire := original.CanonicalWireFormat()
	parsed, end, err := ParseRecordAAAA(wire, 0)
	if err != nil {
		t.Fatalf("ParseRecordAAAA() error = %v", err)
	}
	if end != uint32(len(wire)) {
		t.Errorf("round trip end pos = %v, want %v", end, len(wire))
	}
	if !reflect.DeepEqual(parsed, original) {
		t.Errorf("round trip got = %v, want %v", parsed, original)
	}
}

func TestRecordAAAAAppendWireFormat(t *testing.T) {
	aaaa := NewRecordAAAA([16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1})
	db := NewNameCompressionDB()

	var w WireFormat
	size := aaaa.AppendWireFormat(&w, db)
	if size != 16 {
		t.Errorf("AppendWireFormat() size = %v, want 16", size)
	}

	got, pos, err := ParseRecordAAAA(w, 0)
	if err != nil {
		t.Fatalf("ParseRecordAAAA() error = %v", err)
	}
	if pos != size {
		t.Errorf("ParseRecordAAAA() pos = %v, want %v", pos, size)
	}
	if !reflect.DeepEqual(got, aaaa) {
		t.Errorf("round trip got = %v, want %v", got, aaaa)
	}
}
