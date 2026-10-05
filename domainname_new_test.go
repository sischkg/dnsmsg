package dnsmsg

import (
	"bytes"
	"reflect"
	"strings"
	"testing"
)

func TestNewLabelFromString(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    Label
		wantErr bool
	}{
		{
			name:  "single character",
			input: "a",
			want:  Label{data: []byte("a")},
		},
		{
			name:  "www label",
			input: "www",
			want:  Label{data: []byte("www")},
		},
		{
			name:  "63 characters(maximum)",
			input: strings.Repeat("a", 63),
			want:  Label{data: []byte(strings.Repeat("a", 63))},
		},
		{
			name:    "empty label",
			input:   "",
			wantErr: true, // RFC 1035: ラベル長0は空ラベル(終端)として使われるため、Label単体としては無効
		},
		{
			name:    "64 characters(too long)",
			input:   strings.Repeat("a", 64),
			wantErr: true, // RFC 1035 §3.1: ラベルは63オクテット以下
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewLabelFromString(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewLabelFromString() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewLabelFromString() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNewLabel(t *testing.T) {
	tests := []struct {
		name    string
		input   []byte
		want    Label
		wantErr bool
	}{
		{
			name:  "www label",
			input: []byte("www"),
			want:  Label{data: []byte("www")},
		},
		{
			name:  "non-ascii bytes",
			input: []byte{0xc3, 0xa4},
			want:  Label{data: []byte{0xc3, 0xa4}},
		},
		{
			name:    "empty label",
			input:   []byte{},
			wantErr: true,
		},
		{
			name:    "64 characters(too long)",
			input:   make([]byte, 64),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewLabel(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewLabel() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewLabel() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNewRootLabel(t *testing.T) {
	got := NewRootLabel()
	want := Label{data: []byte{}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("NewRootLabel() = %v, want %v", got, want)
	}
	if got.Size() != 0 {
		t.Errorf("NewRootLabel().Size() = %v, want 0", got.Size())
	}
	if !bytes.Equal(got.WireFormat(), []byte{0}) {
		t.Errorf("NewRootLabel().WireFormat() = %v, want [0]", got.WireFormat())
	}
	if got.String() != "" {
		t.Errorf("NewRootLabel().String() = %q, want \"\"", got.String())
	}
}

func TestLabelWireFormat(t *testing.T) {
	tests := []struct {
		name  string
		input Label
		want  []byte
	}{
		{
			name:  "root label",
			input: Label{data: []byte{}},
			want:  []byte{0},
		},
		{
			name:  "single character",
			input: Label{data: []byte("a")},
			want:  []byte{1, 'a'},
		},
		{
			name:  "www label",
			input: Label{data: []byte("www")},
			want:  []byte{3, 'w', 'w', 'w'},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.input.WireFormat()
			if !bytes.Equal(got, tt.want) {
				t.Errorf("Label.WireFormat() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestLabelWriteWireFormat(t *testing.T) {
	tests := []struct {
		name    string
		input   Label
		initial WireFormat
		want    WireFormat
		wantLen uint32
	}{
		{
			name:    "write to empty wire format",
			input:   Label{data: []byte("www")},
			initial: WireFormat{},
			want:    WireFormat{3, 'w', 'w', 'w'},
			wantLen: 4,
		},
		{
			name:    "write to existing wire format",
			input:   Label{data: []byte("ww")},
			initial: WireFormat{3, 'c', 'o', 'm', 0},
			want:    WireFormat{3, 'c', 'o', 'm', 0, 2, 'w', 'w'},
			wantLen: 3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.initial
			size := tt.input.WriteWireFormat(&got)
			if size != tt.wantLen {
				t.Errorf("Label.WriteWireFormat() size = %v, want %v", size, tt.wantLen)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Label.WriteWireFormat() = %v, want %v", got, tt.want)
			}
		})
	}

	t.Run("nil *WireFormat is a no-op", func(t *testing.T) {
		var w *WireFormat
		size := Label{data: []byte("www")}.WriteWireFormat(w)
		if size != 0 {
			t.Errorf("Label.WriteWireFormat(nil) = %v, want 0", size)
		}
	})
}

func TestLabelSize(t *testing.T) {
	tests := []struct {
		name  string
		input Label
		want  uint32
	}{
		{name: "root label", input: Label{data: []byte{}}, want: 0},
		{name: "single character", input: Label{data: []byte("a")}, want: 1},
		{name: "www label", input: Label{data: []byte("www")}, want: 3},
		{
			name:  "63 characters",
			input: Label{data: []byte(strings.Repeat("a", 63))},
			want:  63,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.input.Size()
			if got != tt.want {
				t.Errorf("Label.Size() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestLabelEqual(t *testing.T) {
	tests := []struct {
		name string
		lhs  Label
		rhs  Label
		want bool
	}{
		{
			name: "same label",
			lhs:  Label{data: []byte("www")},
			rhs:  Label{data: []byte("www")},
			want: true,
		},
		{
			name: "case insensitive",
			lhs:  Label{data: []byte("WWW")},
			rhs:  Label{data: []byte("www")},
			want: true, // RFC 4343 §2: ドメイン名の大文字小文字は区別しない
		},
		{
			name: "mixed case with digits",
			lhs:  Label{data: []byte("A1b2C3")},
			rhs:  Label{data: []byte("a1b2c3")},
			want: true,
		},
		{
			name: "different content",
			lhs:  Label{data: []byte("aB")},
			rhs:  Label{data: []byte("aC")},
			want: false,
		},
		{
			name: "different length",
			lhs:  Label{data: []byte("www")},
			rhs:  Label{data: []byte("wwwx")},
			want: false,
		},
		{
			name: "root labels are equal",
			lhs:  Label{data: []byte{}},
			rhs:  Label{data: []byte{}},
			want: true,
		},
		{
			name: "root label and other label",
			lhs:  Label{data: []byte{}},
			rhs:  Label{data: []byte("a")},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.lhs.Equal(tt.rhs)
			if got != tt.want {
				t.Errorf("Label.Equal() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestLabelCanonicalLabel(t *testing.T) {
	tests := []struct {
		name  string
		input Label
		want  Label
	}{
		{
			name:  "uppercase lowered",
			input: Label{data: []byte("WWW")},
			want:  Label{data: []byte("www")},
		},
		{
			name:  "mixed case lowered",
			input: Label{data: []byte("WwW.Example")},
			want:  Label{data: []byte("www.example")},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.input.CanonicalLabel()
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Label.CanonicalLabel() = %v, want %v", got, tt.want)
			}
		})
	}

	// The root label has no characters to lower.
	root := NewRootLabel()
	got := root.CanonicalLabel()
	if !root.Equal(got) {
		t.Errorf("root CanonicalLabel() = %v, want equal to root label", got)
	}
}

func TestLabelString(t *testing.T) {
	tests := []struct {
		name  string
		input Label
		want  string
	}{
		{
			name:  "plain label",
			input: Label{data: []byte("www")},
			want:  "www",
		},
		{
			name:  "dot is escaped",
			input: Label{data: []byte("my.domain")},
			want:  "my\\.domain", // RFC 1035 §5: '.'はエスケープして表記する
		},
		{
			name:  "backslash is escaped",
			input: Label{data: []byte("a\\b")},
			want:  "a\\\\b",
		},
		{
			name:  "null byte is escaped",
			input: Label{data: []byte{0x00}},
			want:  "\\000", // RFC 1035 §5: \DDD形式で表記する
		},
		{
			name:  "control character is escaped",
			input: Label{data: []byte{0x08}},
			want:  "\\008", // RFC 1035 §5: \DDD形式、DDDは10進数(8)
		},
		{
			name:  "space is escaped",
			input: Label{data: []byte{0x20}},
			want:  "\\032", // RFC 1035 §5: \DDD形式、DDDは10進数(32)
		},
		{
			name:  "non-printable high byte is escaped",
			input: Label{data: []byte{0x7f}},
			want:  "\\127", // RFC 1035 §5: \DDD形式、DDDは10進数(127)
		},
		{
			name:  "bang is printable",
			input: Label{data: []byte{0x21}},
			want:  "!",
		},
		{
			name:  "tilde is printable",
			input: Label{data: []byte{0x7e}},
			want:  "~",
		},
		{
			name:  "mixed escaped characters",
			input: Label{data: []byte{'a', 0x04, '.'}},
			want:  "a\\004\\.",
		},
		{
			name:  "root label",
			input: Label{data: []byte{}},
			want:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.input.String()
			if got != tt.want {
				t.Errorf("Label.String() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNewRootDomainName(t *testing.T) {
	got := NewRootDomainName()
	want := DomainName{labels: []Label{{data: []byte{}}}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("NewRootDomainName() = %v, want %v", got, want)
	}
	if got.String() != "" {
		t.Errorf("NewRootDomainName().String() = %q, want \"\"", got.String())
	}
}

func TestNewDomainNameFromString(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    DomainName
		wantErr bool
	}{
		{
			name:  "empty name is root",
			input: "",
			want:  DomainName{labels: []Label{{data: []byte{}}}},
		},
		{
			name:  "root domain",
			input: ".",
			want:  DomainName{labels: []Label{{data: []byte{}}}},
		},
		{
			name:  "single label",
			input: "com",
			want: DomainName{labels: []Label{
				{data: []byte("com")},
				{data: []byte{}},
			}},
		},
		{
			name:  "single label with trailing dot",
			input: "com.",
			want: DomainName{labels: []Label{
				{data: []byte("com")},
				{data: []byte{}},
			}},
		},
		{
			name:  "simple domain",
			input: "www.example.com",
			want: DomainName{labels: []Label{
				{data: []byte("www")},
				{data: []byte("example")},
				{data: []byte("com")},
				{data: []byte{}},
			}},
		},
		{
			name:  "simple domain with trailing dot",
			input: "www.example.com.",
			want: DomainName{labels: []Label{
				{data: []byte("www")},
				{data: []byte("example")},
				{data: []byte("com")},
				{data: []byte{}},
			}},
		},
		{
			name: "case is preserved",
			want: DomainName{labels: []Label{
				{data: []byte("WWW")},
				{data: []byte("EXAMPLE")},
				{data: []byte("COM")},
				{data: []byte{}},
			}},
			input: "WWW.EXAMPLE.COM.",
		},
		{
			name: "escaped dot inside label",
			want: DomainName{labels: []Label{
				{data: []byte("my.domain")},
				{data: []byte{}},
			}},
			input: "my\\.domain",
		},
		{
			name: "three-digit decimal escape",
			want: DomainName{labels: []Label{
				{data: []byte{0x41}},
				{data: []byte{}},
			}},
			input: "\\065", // RFC 1035 §5: \DDD形式、\065は 10進数65 (ASCII 'A')
		},
		{
			name: "label with maximum length is valid",
			want: DomainName{labels: []Label{
				{data: []byte(strings.Repeat("a", 63))},
				{data: []byte{}},
			}},
			input: strings.Repeat("a", 63),
		},
		{
			name: "domain with maximum wire length(255)",
			input: strings.Repeat("a", 63) + "." +
				strings.Repeat("b", 63) + "." +
				strings.Repeat("c", 63) + "." +
				strings.Repeat("d", 61) + ".",
			want: DomainName{labels: []Label{
				{data: []byte(strings.Repeat("a", 63))},
				{data: []byte(strings.Repeat("b", 63))},
				{data: []byte(strings.Repeat("c", 63))},
				{data: []byte(strings.Repeat("d", 61))},
				{data: []byte{}},
			}},
		},
		{
			name:    "empty label",
			input:   "a..com.",
			wantErr: true, // RFC 1035: ラベル長0は終端のみ許容される
		},
		{
			name:    "leading dot",
			input:   ".a.",
			wantErr: true, // RFC 1035: ラベル長0は終端のみ許容される
		},
		{
			name:    "label is too long",
			input:   strings.Repeat("a", 64) + ".",
			wantErr: true, // RFC 1035 §3.1: ラベルは63オクテット以下
		},
		{
			name: "wire length exceeds 255",
			input: strings.Repeat("a", 63) + "." +
				strings.Repeat("b", 63) + "." +
				strings.Repeat("c", 63) + "." +
				strings.Repeat("d", 62) + ".",
			wantErr: true, // RFC 1035 §4.1.4: 名前は255オクテット以下
		},
		{
			name:    "trailing backslash",
			input:   "domain\\",
			wantErr: true, // presentation formatで終端されていないエスケープ
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewDomainNameFromString(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewDomainNameFromString() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewDomainNameFromString() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNewDomainNameFromLabel(t *testing.T) {
	tests := []struct {
		name  string
		input []Label
		want  DomainName
	}{
		{
			name: "root domain",
			input: []Label{
				{data: []byte{}},
			},
			want: DomainName{labels: []Label{{data: []byte{}}}},
		},
		{
			name: "simple domain",
			input: []Label{
				{data: []byte("www")},
				{data: []byte("example")},
				{data: []byte("com")},
				{data: []byte{}},
			},
			want: DomainName{labels: []Label{
				{data: []byte("www")},
				{data: []byte("example")},
				{data: []byte("com")},
				{data: []byte{}},
			}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewDomainNameFromLabel(tt.input)
			if err != nil {
				t.Errorf("NewDomainNameFromLabel() error = %v, want nil", err)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewDomainNameFromLabel() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNewDomainNameFromWireFormat(t *testing.T) {
	tests := []struct {
		name    string
		input   WireFormat
		index   uint32
		want    DomainName
		wantErr bool
	}{
		{
			name:  "simple domain",
			input: WireFormat{3, 'w', 'w', 'w', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0},
			want: DomainName{labels: []Label{
				{data: []byte("www")},
				{data: []byte("example")},
				{data: []byte("com")},
				{data: []byte{}},
			}},
		},
		{
			name:  "single label",
			input: WireFormat{3, 'c', 'o', 'm', 0},
			want: DomainName{labels: []Label{
				{data: []byte("com")},
				{data: []byte{}},
			}},
		},
		{
			name:  "root domain",
			input: WireFormat{0},
			want:  DomainName{labels: []Label{{data: []byte{}}}},
		},
		{
			name:  "name preceded by other bytes",
			input: WireFormat{0x00, 0x01, 3, 'c', 'o', 'm', 0},
			index: 2,
			want: DomainName{labels: []Label{
				{data: []byte("com")},
				{data: []byte{}},
			}},
		},
		{
			name:    "empty wireformat",
			input:   WireFormat{},
			index:   0,
			wantErr: true, // indexが範囲外のためエラー
		},
		{
			name:    "index out of range",
			input:   WireFormat{3, 'c', 'o', 'm', 0},
			index:   5,
			wantErr: true, // RFC 1035 §4.1.4: 範囲外のオフセットは読めない
		},
		{
			name:    "not terminated by root label",
			input:   WireFormat{1, 'a'},
			wantErr: true, // RFC 1035 §3.1: ドメイン名はルートラベル(0)で終端する
		},
		{
			name:    "label runs past the end",
			input:   WireFormat{5, 'a', 'b', 'c'},
			wantErr: true, // RFC 1035 §3.1: ラベル長が末尾を超える
		},
		{
			name:    "compression pointer at start",
			input:   WireFormat{0xC0, 0x00},
			wantErr: true, // RFC 1035 §4.1.4: 名前圧縮は使用しない
		},
		{
			name:    "compression pointer mid-name",
			input:   WireFormat{3, 'w', 'w', 'w', 0xC0, 0x06, 0x00},
			wantErr: true, // RFC 1035 §4.1.4: 名前圧縮は使用しない
		},
		{
			name:    "reserved label type 01",
			input:   WireFormat{0x41, 'A', 'B'},
			wantErr: true, // RFC 1035 §3.1: 上位2ビットが01は予約済み
		},
		{
			name:    "reserved label type 10",
			input:   WireFormat{0x81, 'A', 'B'},
			wantErr: true, // RFC 1035 §3.1: 上位2ビットが10は予約済み
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewDomainNameFromWireFormat(&tt.input, tt.index)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewDomainNameFromWireFormat() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewDomainNameFromWireFormat() = %v, want %v", got, tt.want)
			}
		})
	}

	t.Run("nil *WireFormat is an error", func(t *testing.T) {
		var w *WireFormat
		if _, err := NewDomainNameFromWireFormat(w, 0); err == nil {
			t.Errorf("NewDomainNameFromWireFormat(nil) error = nil, want non-nil")
		}
	})
}

func TestNewDomainNameFromCompressedWireFormat(t *testing.T) {
	// RFC 1035 Section 4.1.4: 圧縮ポインタ(0xC0 + 14ビットオフセット)は
	// 名前中のどこにでも出現しうる。返される end はポインタ先の後ろでなく、
	// 元の名後の位置であり、その名に続くフィールドの解析に重要である。
	tests := []struct {
		name    string
		input   WireFormat
		index   uint32
		want    DomainName
		wantEnd uint32
		wantErr bool
	}{
		{
			name:  "name without compression",
			input: WireFormat{3, 'w', 'w', 'w', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0},
			want: DomainName{labels: []Label{
				{data: []byte("www")},
				{data: []byte("example")},
				{data: []byte("com")},
				{data: []byte{}},
			}},
			wantEnd: 17,
		},
		{
			name:    "root domain",
			input:   WireFormat{0},
			want:    DomainName{labels: []Label{{data: []byte{}}}},
			wantEnd: 1,
		},
		{
			name:  "pointer to the start of the name",
			input: WireFormat{3, 'w', 'w', 'w', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, 0xC0, 0x00},
			index: 17,
			want: DomainName{labels: []Label{
				{data: []byte("www")},
				{data: []byte("example")},
				{data: []byte("com")},
				{data: []byte{}},
			}},
			wantEnd: 19,
		},
		{
			name:  "pointer to a mid-name position",
			input: WireFormat{3, 'w', 'w', 'w', 0, 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, 0xC0, 0x05},
			index: 18,
			want: DomainName{labels: []Label{
				{data: []byte("example")},
				{data: []byte("com")},
				{data: []byte{}},
			}},
			wantEnd: 20,
		},
		{
			name:  "label followed by a pointer",
			input: WireFormat{3, 'w', 'w', 'w', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, 1, 's', 0xC0, 0x00},
			index: 17,
			want: DomainName{labels: []Label{
				{data: []byte("s")},
				{data: []byte("www")},
				{data: []byte("example")},
				{data: []byte("com")},
				{data: []byte{}},
			}},
			wantEnd: 21,
		},
		{
			name:  "chained pointers",
			input: WireFormat{3, 'w', 'w', 'w', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, 0xC0, 0x00, 0xC0, 0x11},
			index: 19,
			want: DomainName{labels: []Label{
				{data: []byte("www")},
				{data: []byte("example")},
				{data: []byte("com")},
				{data: []byte{}},
			}},
			wantEnd: 21,
		},
		{
			name:    "offset beyond 255 (multi-byte pointer offset)",
			input:   append(append(append([]byte{3, 'c', 'o', 'm', 0}, make([]byte, 295)...), 1, 'x', 0, 0), 0xC1, 0x2C),
			index:   304,
			want:    DomainName{labels: []Label{{data: []byte("x")}, {data: []byte{}}}},
			wantEnd: 306,
		},
		{
			name:    "pointer to itself is rejected",
			input:   WireFormat{0xC0, 0x00},
			wantErr: true,
		},
		{
			name:    "forward pointer is rejected",
			input:   WireFormat{0xC0, 0x05, 0, 0, 0, 0xC0, 0x00},
			wantErr: true,
		},
		{
			name:    "pointer offset out of range is rejected",
			input:   WireFormat{0xC0, 0xFF},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, end, err := NewDomainNameFromCompressedWireFormat(&tt.input, tt.index)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewDomainNameFromCompressedWireFormat() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if !reflect.DeepEqual(got, tt.want) {
					t.Errorf("NewDomainNameFromCompressedWireFormat() = %v, want %v", got, tt.want)
				}
				if end != tt.wantEnd {
					t.Errorf("NewDomainNameFromCompressedWireFormat() end = %v, want %v", end, tt.wantEnd)
				}
			}
		})
	}

	t.Run("nil *WireFormat is an error", func(t *testing.T) {
		var w *WireFormat
		if _, _, err := NewDomainNameFromCompressedWireFormat(w, 0); err == nil {
			t.Errorf("NewDomainNameFromCompressedWireFormat(nil) error = nil, want non-nil")
		}
	})
}

func TestDomainNameString(t *testing.T) {
	tests := []struct {
		name  string
		input DomainName
		want  string
	}{
		{
			name:  "root domain",
			input: DomainName{labels: []Label{{data: []byte{}}}},
			want:  "",
		},
		{
			name: "single label",
			input: DomainName{labels: []Label{
				{data: []byte("com")},
				{data: []byte{}},
			}},
			want: "com.",
		},
		{
			name: "simple domain",
			input: DomainName{labels: []Label{
				{data: []byte("www")},
				{data: []byte("example")},
				{data: []byte("com")},
				{data: []byte{}},
			}},
			want: "www.example.com.",
		},
		{
			name: "label with dot",
			input: DomainName{labels: []Label{
				{data: []byte("my.domain")},
				{data: []byte{}},
			}},
			want: "my\\.domain.",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.input.String()
			if got != tt.want {
				t.Errorf("DomainName.String() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDomainNameAppendLabel(t *testing.T) {
	// Labels are appended in presentation order, most specific first:
	// "example" first, then "com", producing "example.com".
	got := NewRootDomainName()
	got.AppendLabel(Label{data: []byte("example")})
	want := DomainName{labels: []Label{
		{data: []byte("example")},
		{data: []byte{}},
	}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("after AppendLabel(example): got %v, want %v", got, want)
	}

	got.AppendLabel(Label{data: []byte("com")})
	want = DomainName{labels: []Label{
		{data: []byte("example")},
		{data: []byte("com")},
		{data: []byte{}},
	}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("after AppendLabel(com): got %v, want %v", got, want)
	}

	if s := got.String(); s != "example.com." {
		t.Errorf("DomainName.String() = %v, want %v", s, "example.com.")
	}
}

func TestDomainNameCanonicalDomainName(t *testing.T) {
	tests := []struct {
		name       string
		input      DomainName
		want       DomainName
		wantString string
	}{
		{
			name: "upper and mixed case lowered",
			input: DomainName{labels: []Label{
				{data: []byte("WWW")},
				{data: []byte("Example")},
				{data: []byte("COM")},
				{data: []byte{}},
			}},
			want: DomainName{labels: []Label{
				{data: []byte("www")},
				{data: []byte("example")},
				{data: []byte("com")},
				{data: []byte{}},
			}},
			wantString: "www.example.com.",
		},
		{
			name: "lower-cased label unchanged",
			input: DomainName{labels: []Label{
				{data: []byte("example")},
				{data: []byte("com")},
				{data: []byte{}},
			}},
			want: DomainName{labels: []Label{
				{data: []byte("example")},
				{data: []byte("com")},
				{data: []byte{}},
			}},
			wantString: "example.com.",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.input.CanonicalDomainName()
			// Compare the presentation string and Equal() rather than
			// DeepEqual: the canonical root label is the zero-value
			// Label (nil data) while the original is an empty slice,
			// and the two are indistinguishable through the public API.
			if s := got.String(); s != tt.wantString {
				t.Errorf("DomainName.CanonicalDomainName().String() = %q, want %q", s, tt.wantString)
			}
			if !got.Equal(tt.want) {
				t.Errorf("DomainName.CanonicalDomainName() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDomainNameCanonicalWireFormat(t *testing.T) {
	tests := []struct {
		name  string
		input DomainName
		want  WireFormat
	}{
		{
			name:  "zero value is the root domain",
			input: DomainName{},
			want:  WireFormat{0},
		},
		{
			name:  "root domain",
			input: NewRootDomainName(),
			want:  WireFormat{0},
		},
		{
			name: "single label",
			input: DomainName{labels: []Label{
				{data: []byte("com")},
				{data: []byte{}},
			}},
			want: WireFormat{3, 'c', 'o', 'm', 0},
		},
		{
			name: "three labels",
			input: DomainName{labels: []Label{
				{data: []byte("www")},
				{data: []byte("example")},
				{data: []byte("com")},
				{data: []byte{}},
			}},
			want: WireFormat{3, 'w', 'w', 'w', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0},
		},
		{
			name: "upper and mixed case lowered",
			input: DomainName{labels: []Label{
				{data: []byte("WWW")},
				{data: []byte("Example")},
				{data: []byte("COM")},
				{data: []byte{}},
			}},
			want: WireFormat{3, 'w', 'w', 'w', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.input.CanonicalWireFormat()
			if !bytes.Equal(got, tt.want) {
				t.Errorf("DomainName.CanonicalWireFormat() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDomainNameEqual(t *testing.T) {
	tests := []struct {
		name string
		lhs  DomainName
		rhs  DomainName
		want bool
	}{
		{
			name: "equal names",
			lhs: DomainName{labels: []Label{
				{data: []byte("example")},
				{data: []byte("com")},
				{data: []byte{}},
			}},
			rhs: DomainName{labels: []Label{
				{data: []byte("example")},
				{data: []byte("com")},
				{data: []byte{}},
			}},
			want: true,
		},
		{
			name: "case insensitive",
			lhs: DomainName{labels: []Label{
				{data: []byte("WWW")},
				{data: []byte("EXAMPLE")},
				{data: []byte("COM")},
				{data: []byte{}},
			}},
			rhs: DomainName{labels: []Label{
				{data: []byte("www")},
				{data: []byte("example")},
				{data: []byte("com")},
				{data: []byte{}},
			}},
			want: true, // RFC 4343 §2: ドメイン名の大文字小文字は区別しない
		},
		{
			name: "different label content",
			lhs: DomainName{labels: []Label{
				{data: []byte("example")},
				{data: []byte("com")},
				{data: []byte{}},
			}},
			rhs: DomainName{labels: []Label{
				{data: []byte("example")},
				{data: []byte("org")},
				{data: []byte{}},
			}},
			want: false,
		},
		{
			name: "different number of labels",
			lhs: DomainName{labels: []Label{
				{data: []byte("www")},
				{data: []byte("example")},
				{data: []byte("com")},
				{data: []byte{}},
			}},
			rhs: DomainName{labels: []Label{
				{data: []byte("example")},
				{data: []byte("com")},
				{data: []byte{}},
			}},
			want: false,
		},
		{
			name: "root domains are equal",
			lhs:  DomainName{labels: []Label{{data: []byte{}}}},
			rhs:  DomainName{labels: []Label{{data: []byte{}}}},
			want: true,
		},
		{
			name: "root domain and other domain",
			lhs:  DomainName{labels: []Label{{data: []byte{}}}},
			rhs: DomainName{labels: []Label{
				{data: []byte("com")},
				{data: []byte{}},
			}},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.lhs.Equal(tt.rhs)
			if got != tt.want {
				t.Errorf("DomainName.Equal() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDomainNameParentDomainNames(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			// The name itself and every parent, most specific first,
			// down to (but excluding) the root domain.
			name:  "simple domain includes itself and parents",
			input: "www.example.com.",
			want: []string{
				"www.example.com.",
				"example.com.",
				"com.",
			},
		},
		{
			// Parents are returned in canonical (lower-case) form.
			name:  "upper case input returned canonical",
			input: "WWW.EXAMPLE.COM.",
			want: []string{
				"www.example.com.",
				"example.com.",
				"com.",
			},
		},
		{
			name:  "single label has itself only",
			input: "com.",
			want: []string{
				"com.",
			},
		},
		{
			name:  "deep name lists all the way to the second-level parent",
			input: "a.b.example.co.jp.",
			want: []string{
				"a.b.example.co.jp.",
				"b.example.co.jp.",
				"example.co.jp.",
				"co.jp.",
				"jp.",
			},
		},
		{
			// The root domain is never part of the result, so for the
			// root itself the slice is empty.
			name:  "root domain yields empty slice",
			input: ".",
			want:  []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ndn, err := NewDomainNameFromString(tt.input)
			if err != nil {
				t.Fatalf("NewDomainNameFromString(%q) error = %v, want nil", tt.input, err)
			}

			got := ndn.ParentDomainNames()
			if len(got) != len(tt.want) {
				t.Fatalf("DomainName.ParentDomainNames() = %v, want %v", got, tt.want)
			}
			for i, w := range tt.want {
				if s := got[i].String(); s != w {
					t.Errorf("DomainName.ParentDomainNames()[%d].String() = %q, want %q", i, s, w)
					continue
				}
			}

			// The root domain (".") must not appear among the parents.
			for i, p := range got {
				if p.String() == "" {
					t.Errorf("DomainName.ParentDomainNames()[%d] is the root domain, want non-root", i)
				}
			}
		})
	}
}

func TestDomainNameDBKey(t *testing.T) {
	t.Run("root domain", func(t *testing.T) {
		got := NewRootDomainName().DBKey()
		want := [DOMAINNAME_MAX_LENGTH]byte{}
		if got != want {
			t.Fatalf("root DBKey() = %v, want %v", got, want)
		}
	})

	t.Run("single label", func(t *testing.T) {
		com, err := NewDomainNameFromString("com.")
		if err != nil {
			t.Fatalf("NewDomainNameFromString() error = %v, want nil", err)
		}
		got := com.DBKey()
		want := [DOMAINNAME_MAX_LENGTH]byte{}
		want[0] = 3
		copy(want[1:4], []byte("com"))
		// want[4] is the terminating zero octet.
		if got != want {
			t.Fatalf("DBKey() = %v, want %v", got, want)
		}
	})

	t.Run("three labels", func(t *testing.T) {
		name, err := NewDomainNameFromString("www.example.com.")
		if err != nil {
			t.Fatalf("NewDomainNameFromString() error = %v, want nil", err)
		}
		got := name.DBKey()
		want := [DOMAINNAME_MAX_LENGTH]byte{}
		want[0] = 3
		copy(want[1:4], []byte("www"))
		want[4] = 7
		copy(want[5:12], []byte("example"))
		want[12] = 3
		copy(want[13:16], []byte("com"))
		// want[16] is the terminating zero octet.
		if got != want {
			t.Fatalf("DBKey() = %v, want %v", got, want)
		}
	})

	t.Run("case insensitive", func(t *testing.T) {
		upper, err := NewDomainNameFromString("WWW.EXAMPLE.COM.")
		if err != nil {
			t.Fatalf("NewDomainNameFromString() error = %v, want nil", err)
		}
		lower, err := NewDomainNameFromString("www.example.com.")
		if err != nil {
			t.Fatalf("NewDomainNameFromString() error = %v, want nil", err)
		}
		// RFC 4343 Section 2: names compare equal regardless of case.
		if upper.DBKey() != lower.DBKey() {
			t.Errorf("DBKey() is not case insensitive: %v, want %v", upper.DBKey(), lower.DBKey())
		}
	})

	t.Run("same key as legacy Domainname", func(t *testing.T) {
		dn, err := NewDomainNameFromString("www.example.com.")
		if err != nil {
			t.Fatalf("NewDomainNameFromString() error = %v, want nil", err)
		}
		legacy := Domainname{{'w', 'w', 'w'}, {'e', 'x', 'a', 'm', 'p', 'l', 'e'}, {'c', 'o', 'm'}}
		if dn.DBKey() != legacy.DBKey() {
			t.Errorf("DBKey() = %v, want legacy %v", dn.DBKey(), legacy.DBKey())
		}
	})
}

func TestDomainNameSize(t *testing.T) {
	tests := []struct {
		name  string
		input DomainName
		want  uint32
	}{
		{
			name:  "zero value is just the root terminator",
			input: DomainName{},
			want:  1,
		},
		{
			name:  "root domain",
			input: NewRootDomainName(),
			want:  1,
		},
		{
			name: "single label",
			input: DomainName{labels: []Label{
				{data: []byte("com")},
				{data: []byte{}},
			}},
			want: 5,
		},
		{
			name: "three labels",
			input: DomainName{labels: []Label{
				{data: []byte("www")},
				{data: []byte("example")},
				{data: []byte("com")},
				{data: []byte{}},
			}},
			want: 17,
		},
		{
			name: "upper and mixed case does not change the size",
			input: DomainName{labels: []Label{
				{data: []byte("WWW")},
				{data: []byte("Example")},
				{data: []byte("COM")},
				{data: []byte{}},
			}},
			want: 17,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.input.Size(); got != tt.want {
				t.Errorf("DomainName.Size() = %v, want %v", got, tt.want)
			}
			// Size() must agree with the canonical wire encoding it describes.
			if got := uint32(len(tt.input.CanonicalWireFormat())); got != tt.want {
				t.Errorf("len(CanonicalWireFormat()) = %v, want Size() %v", got, tt.want)
			}
		})
	}
}

func TestDomainNameIsRoot(t *testing.T) {
	tests := []struct {
		name  string
		input DomainName
		want  bool
	}{
		{
			name:  "zero value is the root domain",
			input: DomainName{},
			want:  true,
		},
		{
			name:  "root domain",
			input: NewRootDomainName(),
			want:  true,
		},
		{
			name: "single label",
			input: DomainName{labels: []Label{
				{data: []byte("com")},
				{data: []byte{}},
			}},
			want: false,
		},
		{
			name: "three labels",
			input: DomainName{labels: []Label{
				{data: []byte("www")},
				{data: []byte("example")},
				{data: []byte("com")},
				{data: []byte{}},
			}},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.input.IsRoot(); got != tt.want {
				t.Errorf("DomainName.IsRoot() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNameCompressionDBDomainName(t *testing.T) {
	db := NewNameCompressionDB()
	name, err := NewDomainNameFromString("www.example.com.")
	if err != nil {
		t.Fatalf("NewDomainNameFromString() error = %v, want nil", err)
	}

	// Not found initially.
	if _, found := db.FindDomainName(name); found {
		t.Error("NameCompressionDB.FindDomainName() should return false for new name")
	}

	// Add and find.
	db.AddDomainName(name, 10)
	pointer, found := db.FindDomainName(name)
	if !found {
		t.Error("NameCompressionDB.FindDomainName() should return true after AddDomainName")
	}
	if pointer != 10 {
		t.Errorf("NameCompressionDB.FindDomainName() = %v, want %v", pointer, 10)
	}

	// FindDomainName is case insensitive, so a name added in another case
	// still matches.
	mixed, err := NewDomainNameFromString("WwW.ExAMPLE.Com")
	if err != nil {
		t.Fatalf("NewDomainNameFromString() error = %v, want nil", err)
	}
	if pointer, found = db.FindDomainName(mixed); !found {
		t.Error("NameCompressionDB.FindDomainName() should find name under different case")
	} else if pointer != 10 {
		t.Errorf("NameCompressionDB.FindDomainName() = %v, want %v", pointer, 10)
	}
}

func TestNameCompressionDBDomainName_CrossType(t *testing.T) {
	// The keys of DomainName and Domainname are identical, so names added
	// through one type are visible through the other.
	db := NewNameCompressionDB()

	legacy := Domainname{{'W', 'w', 'W'}, {'e', 'x', 'a', 'm', 'p', 'l', 'e'}, {'c', 'o', 'm'}}
	db.Add(legacy, 10)

	name, err := NewDomainNameFromString("www.example.com.")
	if err != nil {
		t.Fatalf("NewDomainNameFromString() error = %v, want nil", err)
	}
	if pointer, found := db.FindDomainName(name); !found {
		t.Error("FindDomainName() should find the name added through Domainname")
	} else if pointer != 10 {
		t.Errorf("FindDomainName() = %v, want %v", pointer, 10)
	}
	if pointer, found := db.Find(legacy); !found {
		t.Error("Find() should still find the name")
	} else if pointer != 10 {
		t.Errorf("Find() = %v, want %v", pointer, 10)
	}

	db.AddDomainName(name, 20)
	if pointer, found := db.Find(legacy); !found {
		t.Error("Find() should find the name added through DomainName")
	} else if pointer != 20 {
		t.Errorf("Find() = %v, want %v", pointer, 20)
	}
}

func TestNameCompressionDBDomainName_Nil(t *testing.T) {
	var db *NameCompressionDB
	name, err := NewDomainNameFromString("com.")
	if err != nil {
		t.Fatalf("NewDomainNameFromString() error = %v, want nil", err)
	}

	if _, found := db.FindDomainName(name); found {
		t.Error("FindDomainName() on nil NameCompressionDB should return false")
	}
	db.AddDomainName(name, 1) // must not panic
}

func TestDomainNameStringRoundtrip(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{name: "single label", input: "com", want: "com."},
		{name: "simple domain", input: "www.example.com.", want: "www.example.com."},
		{name: "escaped dot", input: "my\\.domain.", want: "my\\.domain."},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			name, err := NewDomainNameFromString(tt.input)
			if err != nil {
				t.Errorf("NewDomainNameFromString() error = %v, want nil", err)
				return
			}
			got := name.String()
			if got != tt.want {
				t.Errorf("DomainName.String() = %v, want %v", got, tt.want)
			}
		})
	}
}
