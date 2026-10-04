package dnsmsg

import (
	"bytes"
	"reflect"
	"testing"
)

func mustDomainname(s string) Domainname {
	d, err := NewDomainname(s)
	if err != nil {
		panic(err)
	}
	return d
}

func TestParseRecordMX(t *testing.T) {
	tests := []struct {
		name    string
		input   []byte
		begin   uint32
		want    RecordMX
		wantEnd uint32
		wantErr bool
	}{
		{
			name:    "valid MX record",
			input:   []byte{0, 10, 4, 'm', 'a', 'i', 'l', 2, 'g', 'o', 0}, // Pref 10, "mail.go."
			begin:   0,
			want:    NewRecordMX(10, mustDomainname("mail.go")),
			wantEnd: 11,
			wantErr: false,
		},
		{
			name:    "truncated MX record",
			input:   []byte{0, 10, 7}, // Pref 10, but incomplete name
			begin:   0,
			want:    RecordMX{},
			wantEnd: 0,
			wantErr: true,
		},
		{
			name:    "empty input",
			input:   []byte{},
			begin:   0,
			want:    RecordMX{},
			wantEnd: 0,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, end, err := ParseRecordMX(tt.input, tt.begin)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseRecordMX() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ParseRecordMX() got = %v, want %v", got, tt.want)
			}
			if end != tt.wantEnd {
				t.Errorf("ParseRecordMX() end = %v, want %v", end, tt.wantEnd)
			}
		})
	}
}

func TestNewRecordMXFromString(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    RecordMX
		wantErr bool
	}{
		{
			name:    "valid MX string",
			input:   "10 mail.example.com",
			want:    NewRecordMX(10, mustDomainname("mail.example.com")),
			wantErr: false,
		},
		{
			name:    "invalid preference",
			input:   "invalid mail.example.com",
			want:    RecordMX{},
			wantErr: true,
		},
		{
			name:    "invalid domain",
			input:   "10 invalid domain name",
			want:    RecordMX{},
			wantErr: true,
		},
		{
			name:    "too few fields",
			input:   "10",
			want:    RecordMX{},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewRecordMXFromString(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewRecordMXFromString() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewRecordMXFromString() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRecordMX_String(t *testing.T) {
	d, _ := NewDomainname("mail.example.com")
	r := NewRecordMX(10, d)
	want := "10 mail.example.com."
	if got := r.String(); got != want {
		t.Errorf("RecordMX.String() = %v, want %v", got, want)
	}
}

func TestRecordMX_AppendWireFormat(t *testing.T) {
	d, _ := NewDomainname("mail.example.com")
	r := NewRecordMX(10, d)
	w := new(WireFormat)
	db := NewNameCompressionDB()

	r.AppendWireFormat(w, db)

	// Preference (2 bytes: 0, 10) + domain name ("mail.example.com." = 4 + 7 + 3 = 14 + 3 = 17)
	// Total should be 2 + 17 = 19
	// Wait, NewDomainname("mail.example.com") is [mail, example, com]
	// Lengths: 4, 7, 3.
	// Wire format: \x04mail\x07example\x03com\x00
	// Total size = 2 + (1 + 4) + (1 + 7) + (1 + 3) + 1 = 2 + 5 + 8 + 4 + 1 = 20.

	expected := []byte{0, 10, 4, 'm', 'a', 'i', 'l', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0}
	if !bytes.Equal(*w, expected) {
		t.Errorf("RecordMX.AppendWireFormat() = %v, want %v", *w, expected)
	}
}
