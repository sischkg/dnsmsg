package dnsmsg

import (
	"bytes"
	"encoding/json"
	"reflect"
	"testing"
)

func TestParseRecordTXT(t *testing.T) {
	long := make([]byte, 255)
	for i := range long {
		long[i] = 'a'
	}

	tests := []struct {
		name    string
		input   WireFormat
		begin   uint32
		end     uint32
		want    RecordTXT
		wantPos uint32
		wantErr bool
	}{
		{
			name:    "one character-string",
			input:   WireFormat{0x05, 'h', 'e', 'l', 'l', 'o'},
			begin:   0,
			end:     6,
			want:    NewRecordTXT([]byte("hello")),
			wantPos: 6,
		},
		{
			name:    "two character-strings",
			input:   WireFormat{0x03, 'f', 'o', 'o', 0x03, 'b', 'a', 'r'},
			begin:   0,
			end:     8,
			want:    NewRecordTXT([]byte("foo"), []byte("bar")),
			wantPos: 8,
		},
		{
			name:    "empty character-string",
			input:   WireFormat{0x00},
			begin:   0,
			end:     1,
			want:    NewRecordTXT([]byte{}),
			wantPos: 1,
		},
		{
			name:    "255-octet character-string",
			input:   append(WireFormat{0xff}, long...),
			begin:   0,
			end:     256,
			want:    NewRecordTXT(long),
			wantPos: 256,
		},
		{
			name:    "RDATA at an offset in a message",
			input:   WireFormat{0xaa, 0xbb, 0x03, 'a', 'b', 'c'},
			begin:   2,
			end:     6,
			want:    NewRecordTXT([]byte("abc")),
			wantPos: 6,
		},
		{
			name:    "no character-strings (RDLENGTH 0)",
			input:   WireFormat{0x00, 0x00},
			begin:   0,
			end:     0,
			want:    RecordTXT{},
			wantErr: true,
		},
		{
			name:    "character-string exceeds RDATA",
			input:   WireFormat{0x04, 'a', 'b'},
			begin:   0,
			end:     3,
			want:    RecordTXT{},
			wantErr: true,
		},
		{
			name:    "truncated character-string data",
			input:   WireFormat{0x03, 'a', 'b'},
			begin:   0,
			end:     3,
			want:    RecordTXT{},
			wantErr: true,
		},
		{
			name:    "RDATA end beyond the wire format",
			input:   WireFormat{0x05, 'h', 'e'},
			begin:   0,
			end:     5,
			want:    RecordTXT{},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, pos, err := ParseRecordTXT(tt.input, tt.begin, tt.end)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseRecordTXT() error = %v, wantErr %v", err, tt.wantErr)
			}
			if err != nil {
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ParseRecordTXT() got = %q, want %q", got, tt.want)
			}
			if pos != tt.wantPos {
				t.Errorf("ParseRecordTXT() pos = %v, want %v", pos, tt.wantPos)
			}
		})
	}
}

func TestNewRecordTXTFromString(t *testing.T) {
	long := string(bytes.Repeat([]byte("a"), 256))

	tests := []struct {
		name    string
		input   string
		want    RecordTXT
		wantErr bool
	}{
		{
			name:  "quoted string",
			input: `"hello"`,
			want:  NewRecordTXT([]byte("hello")),
		},
		{
			name:  "unquoted string",
			input: `hello`,
			want:  NewRecordTXT([]byte("hello")),
		},
		{
			name:  "quoted string containing a space",
			input: `"hello world"`,
			want:  NewRecordTXT([]byte("hello world")),
		},
		{
			name:  "SPF record",
			input: `"v=spf1 -all"`,
			want:  NewRecordTXT([]byte("v=spf1 -all")),
		},
		{
			name:  "two quoted strings",
			input: `"foo" "bar"`,
			want:  NewRecordTXT([]byte("foo"), []byte("bar")),
		},
		{
			name:  "two unquoted strings",
			input: `foo bar`,
			want:  NewRecordTXT([]byte("foo"), []byte("bar")),
		},
		{
			name:  "empty quoted string",
			input: `""`,
			want:  NewRecordTXT([]byte{}),
		},
		{
			name:  "unquoted string followed by a quoted string",
			input: `ab"cd"`,
			want:  NewRecordTXT([]byte("ab"), []byte("cd")),
		},
		{
			name:  "three-digit decimal escape",
			input: `"a\065b"`,
			want:  NewRecordTXT([]byte("aAb")),
		},
		{
			name:  "escaped quote and backslash",
			input: `"say \"hi\" \\"`,
			want:  NewRecordTXT([]byte(`say "hi" \`)),
		},
		{
			name:  "escaped space in an unquoted string",
			input: `a\032b`,
			want:  NewRecordTXT([]byte("a b")),
		},
		{
			name:  "255-character string",
			input: `"` + long[:255] + `"`,
			want:  NewRecordTXT([]byte(long[:255])),
		},
		{
			name:    "no character-strings",
			input:   ``,
			wantErr: true,
		},
		{
			name:    "white space only",
			input:   `   `,
			wantErr: true,
		},
		{
			name:    "unterminated quoted string",
			input:   `"abc`,
			wantErr: true,
		},
		{
			name:    "trailing backslash",
			input:   `tail\`,
			wantErr: true,
		},
		{
			name:    "character-string of 256 characters",
			input:   long,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewRecordTXTFromString(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewRecordTXTFromString() error = %v, wantErr %v", err, tt.wantErr)
			}
			if err != nil {
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewRecordTXTFromString() got = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestRecordTXTString(t *testing.T) {
	tests := []struct {
		name  string
		input RecordTXT
		want  string
	}{
		{
			name:  "one character-string",
			input: NewRecordTXT([]byte("hello")),
			want:  `"hello"`,
		},
		{
			name:  "character-string containing a space",
			input: NewRecordTXT([]byte("hello world")),
			want:  `"hello world"`,
		},
		{
			name:  "two character-strings",
			input: NewRecordTXT([]byte("foo"), []byte("bar")),
			want:  `"foo" "bar"`,
		},
		{
			name:  "empty character-string",
			input: NewRecordTXT([]byte{}),
			want:  `""`,
		},
		{
			name:  "quote and backslash are escaped",
			input: NewRecordTXT([]byte(`say "hi" \`)),
			want:  `"say \"hi\" \\"`,
		},
		{
			name:  "non-printable octets use decimal escapes",
			input: NewRecordTXT([]byte{0x61, 0x00, 0x62, 0x7f, 0xff}),
			want:  `"a\000b\127\255"`,
		},
		{
			name:  "period is not escaped inside a quoted string",
			input: NewRecordTXT([]byte("v=spf1 include:example.com -all")),
			want:  `"v=spf1 include:example.com -all"`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.input.String()
			if got != tt.want {
				t.Errorf("RecordTXT.String() = %q, want %q", got, tt.want)
				return
			}
			// The presentation form must read back as the same record.
			back, err := NewRecordTXTFromString(got)
			if err != nil {
				t.Errorf("NewRecordTXTFromString(%q) error = %v", got, err)
				return
			}
			if !reflect.DeepEqual(back, tt.input) {
				t.Errorf("NewRecordTXTFromString(RecordTXT.String()) = %q, want %q", back, tt.input)
			}
		})
	}
}

func TestRecordTXTType(t *testing.T) {
	txt := NewRecordTXT([]byte("hello"))
	if txt.Type() != TYPE_TXT {
		t.Errorf("RecordTXT.Type() = %v, want %v", txt.Type(), TYPE_TXT)
	}
	if TYPE_TXT != ResourceType(16) {
		t.Errorf("TYPE_TXT = %v, want 16", TYPE_TXT)
	}
	if TYPE_TXT.String() != "TXT" {
		t.Errorf("TYPE_TXT.String() = %q, want %q", TYPE_TXT.String(), "TXT")
	}
	typ, err := NewType("TXT")
	if err != nil {
		t.Errorf("NewType(\"TXT\"): %v", err)
	}
	if typ != TYPE_TXT {
		t.Errorf("NewType(\"TXT\") = %v, want %v", typ, TYPE_TXT)
	}
}

func TestRecordTXTCanonicalWireFormat(t *testing.T) {
	// The character-strings are opaque octets: unlike a domain name, the
	// canonical form keeps them exactly as stored, upper case included.
	txt := NewRecordTXT([]byte("Hello"), []byte("WORLD"))

	got := txt.CanonicalWireFormat()
	want := []byte{
		0x05, 'H', 'e', 'l', 'l', 'o',
		0x05, 'W', 'O', 'R', 'L', 'D',
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("RecordTXT.CanonicalWireFormat() = %v, want %v", got, want)
	}
}

func TestRecordTXTRoundTrip(t *testing.T) {
	original := NewRecordTXT([]byte("text with \000 NUL"), []byte("second string"))

	var wire WireFormat
	size := original.AppendWireFormat(&wire, nil)
	if size != wire.Size() {
		t.Fatalf("AppendWireFormat() size = %v, wire size = %v", size, wire.Size())
	}

	parsed, end, err := ParseRecordTXT(wire, 0, wire.Size())
	if err != nil {
		t.Fatalf("ParseRecordTXT() error = %v", err)
	}
	if end != wire.Size() {
		t.Errorf("ParseRecordTXT() end = %v, want %v", end, wire.Size())
	}
	if !reflect.DeepEqual(parsed, original) {
		t.Errorf("AppendWireFormat -> ParseRecordTXT round trip: got = %q, want %q", parsed, original)
	}
}

func TestRecordTXTAppendWireFormat(t *testing.T) {
	txt := NewRecordTXT([]byte("spf"), []byte("v=spf1 -all"))

	want := []byte{
		0x03, 's', 'p', 'f',
		0x0b, 'v', '=', 's', 'p', 'f', '1', ' ', '-', 'a', 'l', 'l',
	}

	// TXT RDATA holds no domain names, so a non-nil compression DB has no
	// effect: the octets are written as they are.
	for _, db := range []*NameCompressionDB{nil, NewNameCompressionDB()} {
		var w WireFormat
		size := txt.AppendWireFormat(&w, db)
		if size != uint32(len(want)) {
			t.Errorf("AppendWireFormat() size = %v, want %v", size, len(want))
		}
		if !reflect.DeepEqual(w, WireFormat(want)) {
			t.Errorf("AppendWireFormat() = %v, want %v", w, want)
		}
	}
}

func TestRecordTXTAppendCanonicalWireFormat(t *testing.T) {
	txt := NewRecordTXT([]byte("Hello World"))

	var w WireFormat
	size := txt.AppendCanonicalWireFormat(&w)
	if size != 12 {
		t.Errorf("AppendCanonicalWireFormat() size = %v, want 12", size)
	}

	parsed, pos, err := ParseRecordTXT(w, 0, w.Size())
	if err != nil {
		t.Fatalf("ParseRecordTXT() error = %v", err)
	}
	if pos != size {
		t.Errorf("AppendCanonicalWireFormat() pos = %v, want %v", pos, size)
	}
	if !reflect.DeepEqual(parsed, txt) {
		t.Errorf("AppendCanonicalWireFormat -> ParseRecordTXT round trip: got = %q, want %q", parsed, txt)
	}
}

// txtWireFormat builds the expected RDATA of a TXT record: a length octet
// followed by that many octets, for each character-string.
func txtWireFormat(strings ...[]byte) WireFormat {
	var w WireFormat
	for _, s := range strings {
		w = append(w, byte(len(s)))
		w = append(w, s...)
	}
	return w
}

// TestRecordTXTAppendWireFormatLongString verifies that a character-string
// longer than 255 octets is written as several consecutive
// character-strings: a character-string holds at most 255 octets, so the
// length octet alone cannot describe a longer text.
func TestRecordTXTAppendWireFormatLongString(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
		want  WireFormat
	}{
		{
			name:  "255-octet character-string",
			input: bytes.Repeat([]byte("a"), 255),
			want:  txtWireFormat(bytes.Repeat([]byte("a"), 255)),
		},
		{
			name:  "256-octet character-string is split",
			input: bytes.Repeat([]byte("a"), 256),
			want: txtWireFormat(bytes.Repeat([]byte("a"), 255),
				[]byte("a")),
		},
		{
			name:  "300-octet character-string is split",
			input: bytes.Repeat([]byte("a"), 300),
			want: txtWireFormat(bytes.Repeat([]byte("a"), 255),
				bytes.Repeat([]byte("a"), 45)),
		},
		{
			name:  "510-octet character-string is split into two",
			input: bytes.Repeat([]byte("a"), 510),
			want: txtWireFormat(bytes.Repeat([]byte("a"), 255),
				bytes.Repeat([]byte("a"), 255)),
		},
		{
			name:  "empty character-string",
			input: []byte{},
			want:  txtWireFormat([]byte{}),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			txt := NewRecordTXT(tt.input)

			var w WireFormat
			size := txt.AppendWireFormat(&w, nil)
			if size != uint32(len(tt.want)) {
				t.Errorf("AppendWireFormat() size = %v, want %v", size, len(tt.want))
			}
			if !reflect.DeepEqual(w, tt.want) {
				t.Errorf("AppendWireFormat() = %v, want %v", w, tt.want)
			}

			// The RDATA must stay parsable, and the octets must survive
			// the split.
			parsed, pos, err := ParseRecordTXT(w, 0, w.Size())
			if err != nil {
				t.Fatalf("ParseRecordTXT() error = %v", err)
			}
			if pos != w.Size() {
				t.Errorf("ParseRecordTXT() pos = %v, want %v", pos, w.Size())
			}
			var joined []byte
			for _, s := range parsed.Strings {
				joined = append(joined, s...)
			}
			if !bytes.Equal(joined, tt.input) {
				t.Errorf("ParseRecordTXT() octets = %v, want %v", joined, tt.input)
			}
		})
	}
}

// TestResourceRecordTXT verifies that a TXT record is read from and written
// to a message wire format through ParseResourceRecord and
// AppendResourceRecord.
func TestResourceRecordTXT(t *testing.T) {
	rr := ResourceRecord{
		Name:  testDomainName(t, "txt.example.com"),
		Class: CLASS_IN,
		Type:  TYPE_TXT,
		TTL:   3600,
		RData: NewRecordTXT([]byte("v=spf1 -all")),
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
	rdata, ok := got.RData.(RecordTXT)
	if !ok {
		t.Fatalf("ParseResourceRecord() RData = %T, want RecordTXT", got.RData)
	}
	if !reflect.DeepEqual(rdata, NewRecordTXT([]byte("v=spf1 -all"))) {
		t.Errorf("ParseResourceRecord() RData = %q, want %q", rdata, rr.RData)
	}
}

// TestRecordTXTJSON verifies the JSON form of a TXT record: each
// character-string is exported as a base64 string.
func TestRecordTXTJSON(t *testing.T) {
	txt := NewRecordTXT([]byte("hello world"), []byte{0x00, 0x01})

	data, err := json.Marshal(txt)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	want := `{"Strings":["aGVsbG8gd29ybGQ","AAE"]}`
	if string(data) != want {
		t.Errorf("json.Marshal() = %q, want %q", string(data), want)
	}

	var got RecordTXT
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	if !reflect.DeepEqual(got, txt) {
		t.Errorf("json.Unmarshal() = %q, want %q", got, txt)
	}

	var invalid RecordTXT
	if err := json.Unmarshal([]byte(`{"Strings":["!!!" ]}`), &invalid); err == nil {
		t.Error("json.Unmarshal() error = nil, want an error")
	}
}
