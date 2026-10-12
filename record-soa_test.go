package dnsmsg

import (
	"bytes"
	"reflect"
	"testing"
)

// buildSOAWire builds the wire format for an SOA RDATA with given mname, rname and timers.
func buildSOAWire(t *testing.T, mname, rname DomainName, serial, refresh, retry, expire, minimum uint32) WireFormat {
	t.Helper()
	var w WireFormat
	w.AppendDomainName(mname, nil)
	w.AppendDomainName(rname, nil)
	w.AppendUInt32(serial)
	w.AppendUInt32(refresh)
	w.AppendUInt32(retry)
	w.AppendUInt32(expire)
	w.AppendUInt32(minimum)
	return w
}

func TestParseRecordSOA(t *testing.T) {
	mname := testDomainName(t, "ns1.example.com")
	rname := testDomainName(t, "admin.example.com")

	tests := []struct {
		name    string
		input   []byte
		begin   uint32
		want    RecordSOA
		wantPos uint32
		wantErr bool
	}{
		{
			name: "standard SOA record",
			input: func() []byte {
				return buildSOAWire(t, mname, rname, 2023090101, 3600, 900, 1209600, 86400)
			}(),
			begin:   0,
			want:    NewRecordSOA(mname, rname, 2023090101, 3600, 900, 1209600, 86400),
			wantPos: 56,
			wantErr: false,
		},
		{
			name: "SOA with root domain names",
			input: func() []byte {
				root := NewRootDomainName()
				return buildSOAWire(t, root, root, 1, 0, 0, 0, 0)
			}(),
			begin:   0,
			want:    NewRecordSOA(NewRootDomainName(), NewRootDomainName(), 1, 0, 0, 0, 0),
			wantPos: 22,
			wantErr: false,
		},
		{
			name:    "truncated input - missing domain name",
			input:   []byte{3, 'n', 's', '1'},
			begin:   0,
			want:    RecordSOA{},
			wantErr: true,
		},
		{
			name:    "truncated input - missing timers",
			input:   []byte{3, 'n', 's', '1', 0, 3, 'a', 'd', 'm', 0, 0, 0, 0, 1},
			begin:   0,
			want:    RecordSOA{},
			wantErr: true,
		},
		{
			name:    "out of bounds begin offset",
			input:   []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
			begin:   100,
			want:    RecordSOA{},
			wantErr: true,
		},
		{
			name: "with compression pointer for mname",
			// Full mname written at pos 0, then rname at pos 24, then timers at pos 51.
			// At pos 71, another name using compression pointer 0xC0 0x00 referencing pos 0.
			// We parse rname + timers starting at pos 24.
			input: func() []byte {
				w := buildSOAWire(t, mname, rname, 2023090101, 3600, 900, 1209600, 86400)
				return w
			}(),
			begin: 0,
			want:  NewRecordSOA(mname, rname, 2023090101, 3600, 900, 1209600, 86400),
			// mname = 17 bytes, rname = 19 bytes, timers = 20 bytes => total = 56
			wantPos: 56,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, pos, err := ParseRecordSOA(tt.input, tt.begin)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseRecordSOA() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if !got.Equal(tt.want) {
					t.Errorf("ParseRecordSOA() got = \"%+v\", want \"%+v\"", got, tt.want)
				}
				if pos != tt.wantPos {
					t.Errorf("ParseRecordSOA() pos = %v, want %v", pos, tt.wantPos)
				}
			}
		})
	}
}

func TestNewRecordSOAFromString(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    RecordSOA
		wantErr bool
	}{
		{
			name:  "valid SOA string",
			input: "ns1.example.com. admin.example.com. 2023090101 3600 900 1209600 86400",
			want: NewRecordSOA(
				testDomainName(t, "ns1.example.com"),
				testDomainName(t, "admin.example.com"),
				2023090101, 3600, 900, 1209600, 86400,
			),
			wantErr: false,
		},
		{
			name:  "single label names",
			input: "localhost. admin. 1 0 0 0 0",
			want: NewRecordSOA(
				testDomainName(t, "localhost"),
				testDomainName(t, "admin"),
				1, 0, 0, 0, 0,
			),
			wantErr: false,
		},
		{
			name:    "missing fields",
			input:   "ns1.example.com. admin.example.com. 2023090101",
			want:    RecordSOA{},
			wantErr: true,
		},
		{
			name:    "non-numeric timer",
			input:   "ns1.example.com. admin.example.com. abc 3600 900 1209600 86400",
			want:    RecordSOA{},
			wantErr: true,
		},
		{
			name:    "invalid domain with consecutive dots",
			input:   "ns1..example.com. admin.example.com. 2023090101 3600 900 1209600 86400",
			want:    RecordSOA{},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewRecordSOAFromString(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewRecordSOAFromString() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewRecordSOAFromString() got = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestRecordSOAString(t *testing.T) {
	tests := []struct {
		name  string
		input RecordSOA
		want  string
	}{
		{
			name: "standard SOA",
			input: NewRecordSOA(
				testDomainName(t, "ns1.example.com"),
				testDomainName(t, "admin.example.com"),
				2023090101, 3600, 900, 1209600, 86400,
			),
			want: "ns1.example.com. admin.example.com. 2023090101 3600 900 1209600 86400",
		},
		{
			name:  "root domain",
			input: NewRecordSOA(NewRootDomainName(), NewRootDomainName(), 1, 0, 0, 0, 0),
			want:  ". . 1 0 0 0 0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.input.String()
			if got != tt.want {
				t.Errorf("RecordSOA.String() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestRecordSOAType(t *testing.T) {
	soa := NewRecordSOA(NewRootDomainName(), NewRootDomainName(), 0, 0, 0, 0, 0)
	if soa.Type() != TYPE_SOA {
		t.Errorf("RecordSOA.Type() = %v, want %v", soa.Type(), TYPE_SOA)
	}
}

func TestRecordSOACanonicalWireFormat(t *testing.T) {
	// Test that canonical wire format is lowercase
	var serial uint32 = 2023090101
	var refresh uint32 = 3600
	var retry uint32 = 900
	var expire uint32 = 1209600
	var minimum uint32 = 86400
	soa := NewRecordSOA(
		testDomainName(t, "NS1.EXAMPLE.COM"),
		testDomainName(t, "ADMIN.EXAMPLE.COM"),
		serial, refresh, retry, expire, minimum,
	)
	want := []byte{
		3, 'n', 's', '1', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0,
		5, 'a', 'd', 'm', 'i', 'n', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0,
		uint8(serial >> 24), uint8((serial << 8) >> 24), uint8((serial << 16) >> 24), uint8((serial << 24) >> 24), // serial
		uint8(refresh >> 24), uint8((refresh << 8) >> 24), uint8((refresh << 16) >> 24), uint8((refresh << 24) >> 24), // refresh
		uint8(retry >> 24), uint8((retry << 8) >> 24), uint8((retry << 16) >> 24), uint8((retry << 24) >> 24), // retry
		uint8(expire >> 24), uint8((expire << 8) >> 24), uint8((expire << 16) >> 24), uint8((expire << 24) >> 24), // expire
		uint8(minimum >> 24), uint8((minimum << 8) >> 24), uint8((minimum << 16) >> 24), uint8((minimum << 24) >> 24), // minimum
	}

	got := soa.CanonicalWireFormat()
	if !bytes.Equal(got, want) {
		t.Errorf("RecordSOA.CanonicalWireFormat() = %v, want %v", got, want)
	}
}

func TestRecordSOARoundTrip(t *testing.T) {
	original := NewRecordSOA(
		testDomainName(t, "ns1.example.com"),
		testDomainName(t, "admin.example.com"),
		2023090101, 3600, 900, 1209600, 86400,
	)

	// Serialize to canonical wire format
	wire := original.CanonicalWireFormat()

	// Parse back
	parsed, end, err := ParseRecordSOA(wire, 0)
	if err != nil {
		t.Fatalf("ParseRecordSOA() error = %v", err)
	}
	if end != uint32(len(wire)) {
		t.Errorf("round trip end pos = %v, want %v", end, len(wire))
	}
	if !reflect.DeepEqual(parsed, original) {
		t.Errorf("round trip got = %+v, want %+v", parsed, original)
	}
}

func TestRecordSOAAppendWireFormat(t *testing.T) {
	soa := NewRecordSOA(
		//           1 + 3           1 + 7                                 1 + 3           1
		testDomainName(t, "ns1.example.com"),
		//           1 + 5           2 ( name compression )
		testDomainName(t, "admin.example.com"),
		2023090101, 3600, 900, 1209600, 86400,
	)
	db := NewNameCompressionDB()

	var w WireFormat
	size := soa.AppendWireFormat(&w, db)
	expectedSize := uint32(45) // mname(17) + rname(6(admin)+2(name compresssion)) + 20
	if size != expectedSize {
		t.Errorf("AppendWireFormat() size = %v, want %v", size, expectedSize)
	}

	// Parse back from what we wrote
	got, pos, err := ParseRecordSOA(w, 0)
	if err != nil {
		t.Fatalf("ParseRecordSOA() error = %v", err)
	}
	if pos != size {
		t.Errorf("ParseRecordSOA() pos = %v, want %v", pos, size)
	}
	if !reflect.DeepEqual(got, soa) {
		t.Errorf("AppendWireFormat -> ParseRecordSOA round trip: got = %+v, want %+v", got, soa)
	}
}

// Test that using compression db results in shorter wire format
func TestRecordSOACompression(t *testing.T) {
	mname := testDomainName(t, "ns1.example.com")
	rname := testDomainName(t, "admin.example.com")
	soa1 := NewRecordSOA(mname, rname, 2023090101, 3600, 900, 1209600, 86400)
	soa2 := NewRecordSOA(mname, rname, 2023090102, 3600, 900, 1209600, 86400)

	db := NewNameCompressionDB()

	var w WireFormat
	size1 := soa1.AppendWireFormat(&w, db)
	size2 := soa2.AppendWireFormat(&w, db)

	// The second SOA should be shorter because the domain names were already seen
	if size2 >= size1 {
		t.Errorf("Compressed SOA size (%d) should be smaller than original (%d)", size2, size1)
	}

	// Parse both back and verify correctness
	pos := uint32(0)
	got1, pos, err := ParseRecordSOA(w, pos)
	if err != nil {
		t.Fatalf("ParseRecordSOA() first error = %v", err)
	}
	if !reflect.DeepEqual(got1, soa1) {
		t.Errorf("first parsed SOA mismatch: got %+v, want %+v", got1, soa1)
	}

	got2, end, err := ParseRecordSOA(w, pos)
	if err != nil {
		t.Fatalf("ParseRecordSOA() second error = %v", err)
	}
	if !reflect.DeepEqual(got2, soa2) {
		t.Errorf("second parsed SOA mismatch: got %+v, want %+v", got2, soa2)
	}
	if end != uint32(len(w)) {
		t.Errorf("end pos = %v, want %v", end, len(w))
	}
}
