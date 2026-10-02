package dnsmsg

import (
	"testing"
)

func TestParseRecordA(t *testing.T) {
	tests := []struct {
		name    string
		input   []byte
		begin   uint32
		want    RecordA
		wantErr bool
	}{
		{
			name:  "valid A record",
			input: []byte{192, 168, 1, 1},
			begin: 0,
			want:  NewRecordA([4]byte{192, 168, 1, 1}),
			wantErr: false,
		},
		{
			name:  "truncated A record",
			input: []byte{192, 168, 1},
			begin: 0,
			want:    RecordA{},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg := make([]byte, len(tt.input))
			copy(msg, tt.input)
			got, _, err := ParseRecordA(msg, tt.begin)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseRecordA() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("ParseRecordA() got = %v, want %v", got, tt.want)
			}
		})
	}
}
