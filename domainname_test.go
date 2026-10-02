package dnsmsg

import (
	"bytes"
	"fmt"
	"reflect"
	"testing"
)

func TestNewCanonicalDomainnameFromBytes(t *testing.T) {
	tests := []struct {
		name    string
		input   []byte
		want    Domainname
		wantErr bool
	}{
		{
			name:    "simple domain",
			input:   []byte{3, 'w', 'w', 'w', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0},
			want:    Domainname{{'w', 'w', 'w'}, {'e', 'x', 'a', 'm', 'p', 'l', 'e'}, {'c', 'o', 'm'}},
			wantErr: false,
		},
		{
			name:    "root domain",
			input:   []byte{0},
			want:    nil, // 空の Domainname を返す（nil スライス）
			wantErr: false,
		},
		{
			name:    "single label",
			input:   []byte{3, 'c', 'o', 'm', 0},
			want:    Domainname{{'c', 'o', 'm'}},
			wantErr: false,
		},
		{
			name:    "out of bounds",
			input:   []byte{5, 'a', 'b', 'c'},
			want:    nil,
			wantErr: true,
		},
		{
			name:    "not terminated",
			input:   []byte{1, 'a'},
			want:    nil,
			wantErr: true,
		},
		{
			name:    "compression not supported",
			input:   []byte{0xC0, 0x00},
			want:    nil,
			wantErr: true,
		},
		{
			name:    "reserved label type 01",
			input:   []byte{0x41, 0x41, 0x42},
			want:    nil,
			wantErr: true, // RFC 1035 §3.1: 上位2ビットが 01 または 10 は予約済み
		},
		{
			name:    "reserved label type 10",
			input:   []byte{0x81, 0x41, 0x42},
			want:    nil,
			wantErr: true, // RFC 1035 §3.1: 上位2ビットが 01 または 10 は予約済み
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewCanonicalDomainnameFromBytes(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewCanonicalDomainnameFromBytes() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewCanonicalDomainnameFromBytes() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNewDomainnameFromWireFormat(t *testing.T) {
	tests := []struct {
		name    string
		input   []byte
		begin   uint32
		want    Domainname
		wantPos uint32
		wantErr bool
	}{
		{
			name:    "simple domain",
			input:   []byte{3, 'w', 'w', 'w', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0},
			begin:   0,
			want:    Domainname{{'w', 'w', 'w'}, {'e', 'x', 'a', 'm', 'p', 'l', 'e'}, {'c', 'o', 'm'}},
			wantPos: 17,
			wantErr: false,
		},
		{
			name:    "forward compression pointer rejection",
			input:   []byte{3, 'w', 'w', 'w', 0, 3, 'c', 'o', 'm', 0, 3, 'w', 'w', 'w', 0xC0, 0x0E},
			begin:   14,
			want:    nil, // RFC 1035 §4.1.4: 圧縮ポインタはメッセージ内の前の位置のみ指せる。自身または前方を指す場合は無効。
			wantPos: 16,
			wantErr: true,
		},
		{
			name:    "compression pointer at beginning",
			input:   []byte{3, 'w', 'w', 'w', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, 0xC0, 0x00},
			begin:   17,
			want:    Domainname{{'w', 'w', 'w'}, {'e', 'x', 'a', 'm', 'p', 'l', 'e'}, {'c', 'o', 'm'}},
			wantPos: 19,
			wantErr: false,
		},
		{
			name:    "out of bounds",
			input:   []byte{1, 'a'},
			begin:   10,
			want:    nil,
			wantPos: 10,
			wantErr: true,
		},
		{
			name:    "self-referencing compression pointer",
			input:   []byte{0xC0, 0x00},
			begin:   0,
			want:    nil,
			wantPos: 2,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, pos, err := NewDomainnameFromWireFormat(tt.input, tt.begin)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewDomainnameFromWireFormat() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewDomainnameFromWireFormat() name = %v, want %v", got, tt.want)
			}
			if pos != tt.wantPos {
				t.Errorf("NewDomainnameFromWireFormat() pos = %v, want %v", pos, tt.wantPos)
			}
		})
	}
}

func TestNewDomainname(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    Domainname
		wantErr bool
	}{
		{
			name:    "simple domain",
			input:   "www.example.com.",
			want:    Domainname{{'w', 'w', 'w'}, {'e', 'x', 'a', 'm', 'p', 'l', 'e'}, {'c', 'o', 'm'}, {}},
			wantErr: false,
		},
		{
			name:    "root domain",
			input:   ".",
			want:    Domainname{}, // ルートドメインは{}
			wantErr: false,
		},
		{
			name:    "root domain",
			input:   "",
			want:    Domainname{}, // ルートドメインは{}
			wantErr: false,
		},
		{
			name:    "single label",
			input:   "com.",
			want:    Domainname{{'c', 'o', 'm'}, {}},
			wantErr: false,
		},
		{
			name:    "escaped dot",
			input:   "my\\.domain.",
			want:    Domainname{{'m', 'y', '.', 'd', 'o', 'm', 'a', 'i', 'n'}, {}}, // バックスラッシュはエスケープフラグのみ、ドットはラベル内に含まれる
			wantErr: false,
		},
		{
			name:    "three-digit decimal escape",
			input:   "\\046.", // RFC 1035 §5.1: \DDD形式、\046は 10進数46 (ASCII '.')
			want:    Domainname{{'.'}, {}},
			wantErr: false,
		},
		{
			name:    "consecutive dots (empty label)",
			input:   "a..com.",
			want:    nil,
			wantErr: true, // RFC 1035: ラベル長0以外の空ラベルは許容されない
		},
		{
			name:    "label length exceeds 63",
			input:   fmt.Sprintf("a%s.", string(make([]byte, 63))), // RFC 1035 §3.1: ラベルは63文字以下
			want:    nil,
			wantErr: true,
		},
		{
			name:    "trailing backslash",
			input:   "domain\\",
			want:    nil,
			wantErr: true, // presentation formatで終端されていないエスケープ
		},
		{
			name:    "too long domain",
			input:   string(bytes.Repeat([]byte("a"), 256)) + ".",
			want:    nil,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewDomainname(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewDomainname() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewDomainname() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDomainnameString(t *testing.T) {
	tests := []struct {
		name  string
		input Domainname
		want  string
	}{
		{
			name:  "simple domain",
			input: Domainname{{'w', 'w', 'w'}, {'e', 'x', 'a', 'm', 'p', 'l', 'e'}, {'c', 'o', 'm'}, {}},
			want:  "www.example.com.",
		},
		{
			name:  "root domain",
			input: Domainname{},
			want:  ".",
		},
		{
			name:  "with escaped dot",
			input: Domainname{{'m', 'y', '.', 'd', 'o', 'm', 'a', 'i', 'n'}},
			want:  "my\\.domain.",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.input.String()
			if got != tt.want {
				t.Errorf("Domainname.String() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDomainnameCanonicalWireFormat(t *testing.T) {
	name := Domainname{{'W', 'W', 'W'}, {'E', 'x', 'a', 'm', 'p', 'l', 'e'}, {'C', 'O', 'M'}}
	want := []byte{3, 'w', 'w', 'w', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0}

	got := name.CanonicalWireFormat()
	if !bytes.Equal(got, want) {
		t.Errorf("Domainname.CanonicalWireFormat() = %v, want %v", got, want)
	}
}

func TestDomainnameSize(t *testing.T) {
	name := Domainname{{'w', 'w', 'w'}, {'e', 'x', 'a', 'm', 'p', 'l', 'e'}, {'c', 'o', 'm'}}
	// 1+3 + 1+7 + 1+3 + 1 (terminator) = 17
	want := uint32(17)

	got := name.Size()
	if got != want {
		t.Errorf("Domainname.Size() = %v, want %v", got, want)
	}
}

func TestDomainnameSuffixes(t *testing.T) {
	name := Domainname{{'w', 'w', 'w'}, {'e', 'x', 'a', 'm', 'p', 'l', 'e'}, {'c', 'o', 'm'}}

	got := name.Suffixes()
	if len(got) != 3 {
		t.Errorf("Domainname.Suffixes() length = %v, want %v", len(got), 3)
	}

	wantSuffixes := []Domainname{
		{{'w', 'w', 'w'}, {'e', 'x', 'a', 'm', 'p', 'l', 'e'}, {'c', 'o', 'm'}},
		{{'e', 'x', 'a', 'm', 'p', 'l', 'e'}, {'c', 'o', 'm'}},
		{{'c', 'o', 'm'}},
	}

	for i, want := range wantSuffixes {
		if !reflect.DeepEqual(got[i], want) {
			t.Errorf("Domainname.Suffixes()[%d] = %v, want %v", i, got[i], want)
		}
	}
}

func TestNameCompressionDB(t *testing.T) {
	db := NewNameCompressionDB()
	name := Domainname{{'w', 'w', 'w'}, {'e', 'x', 'a', 'm', 'p', 'l', 'e'}, {'c', 'o', 'm'}}

	// Not found initially
	_, found := db.Find(name)
	if found {
		t.Error("NameCompressionDB.Find() should return false for new name")
	}

	// Add and find
	db.Add(name, 10)
	pointer, found := db.Find(name)
	if !found {
		t.Error("NameCompressionDB.Find() should return true after Add")
	}
	if pointer != 10 {
		t.Errorf("NameCompressionDB.Find() = %v, want %v", pointer, 10)
	}
}

func TestNewDomainnameFromWireFormat_Compression(t *testing.T) {
	// RFC 1035 Section 4.1.4 に基づくテスト
	// 圧縮ポインタ: 上位2ビットが 11 (0xC0), 下位14ビットがオフセット

	tests := []struct {
		name    string
		input   []byte
		begin   uint32
		want    Domainname
		wantErr bool
	}{
		{
			name:    "compression pointer to offset 0",
			input:   []byte{3, 'w', 'w', 'w', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, 0xC0, 0x00},
			begin:   17,
			want:    Domainname{{'w', 'w', 'w'}, {'e', 'x', 'a', 'm', 'p', 'l', 'e'}, {'c', 'o', 'm'}},
			wantErr: false,
		},
		{
			name:    "compression pointer to offset 5",
			input:   []byte{3, 'w', 'w', 'w', 0, 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, 0xC0, 0x05},
			begin:   18,
			want:    Domainname{{'e', 'x', 'a', 'm', 'p', 'l', 'e'}, {'c', 'o', 'm'}},
			wantErr: false,
		},
		{
			name:    "label followed by compression pointer",
			input:   []byte{3, 'w', 'w', 'w', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, 1, 's', 0xC0, 0x00},
			begin:   17,
			want:    Domainname{{'s'}, {'w', 'w', 'w'}, {'e', 'x', 'a', 'm', 'p', 'l', 'e'}, {'c', 'o', 'm'}},
			wantErr: false,
		},
		{
			name: "offset > 255 (multi-byte offset)",
			// オフセット 300 = 0x012C → 0xC1, 0x2C
			input:   append(append(append([]byte{3, 'c', 'o', 'm', 0}, make([]byte, 295)...), 1, 'x', 0, 0), 0xC1, 0x2C),
			begin:   304,
			want:    Domainname{{'x'}},
			wantErr: false,
		},
		{
			name: "chained compression pointers",
			// pos 0: www.example.com; pos 17: 0xC0 0x00; pos 19: 0xC0 0x11
			input:   []byte{3, 'w', 'w', 'w', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, 0xC0, 0x00, 0xC0, 0x11},
			begin:   19,
			want:    Domainname{{'w', 'w', 'w'}, {'e', 'x', 'a', 'm', 'p', 'l', 'e'}, {'c', 'o', 'm'}},
			wantErr: false,
		},
		{
			name:    "loop detection (pointer to self)",
			input:   []byte{0xC0, 0x00},
			begin:   0,
			want:    nil,
			wantErr: true,
		},
		{
			name:    "loop detection (pointer forward)",
			input:   []byte{0xC0, 0x05, 0, 0, 0, 0xC0, 0x00},
			begin:   0,
			want:    nil,
			wantErr: true, // オフセット5はbegin(0)より後を指す → ループ検出
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, _, err := NewDomainnameFromWireFormat(tt.input, tt.begin)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewDomainnameFromWireFormat() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewDomainnameFromWireFormat() = %v, want %v", got, tt.want)
			}
		})
	}
}
