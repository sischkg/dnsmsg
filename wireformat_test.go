package dnsmsg

import (
	"bytes"
	"testing"
)

func TestWireFormatAppendCanonicalDomainname(t *testing.T) {
	tests := []struct {
		name     string
		domain   Domainname
		wantWire []byte
		wantSize uint32
	}{
		{
			name:     "nil WireFormat",
			domain:   Domainname{{'a'}},
			wantWire: nil,
			wantSize: 0,
		},
		{
			name:     "nil Domainname",
			domain:   nil,
			wantWire: []byte{0},
			wantSize: 1,
		},
		{
			name:     "root domain (empty Domainname)",
			domain:   Domainname{},
			wantWire: []byte{0},
			wantSize: 1,
		},
		{
			name:     "single label",
			domain:   Domainname{{'c', 'o', 'm'}},
			wantWire: []byte{3, 'c', 'o', 'm', 0},
			wantSize: 5,
		},
		{
			name:     "two labels",
			domain:   Domainname{{'e', 'x', 'a', 'm', 'p', 'l', 'e'}, {'c', 'o', 'm'}},
			wantWire: []byte{7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0},
			wantSize: 13,
		},
		{
			name:     "three labels",
			domain:   Domainname{{'w', 'w', 'w'}, {'e', 'x', 'a', 'm', 'p', 'l', 'e'}, {'c', 'o', 'm'}},
			wantWire: []byte{3, 'w', 'w', 'w', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0},
			wantSize: 17,
		},
		{
			name:     "uppercase is converted to lowercase",
			domain:   Domainname{{'W', 'W', 'W'}, {'E', 'x', 'A', 'm', 'P', 'l', 'E'}, {'C', 'O', 'M'}},
			wantWire: []byte{3, 'w', 'w', 'w', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0},
			wantSize: 17,
		},
		{
			name:     "append to existing wire format",
			domain:   Domainname{{'a'}},
			wantWire: []byte{0xff, 1, 'a', 0},
			wantSize: 3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var w *WireFormat
			if tt.name == "nil WireFormat" {
				size := w.AppendCanonicalDomainname(tt.domain)
				if size != tt.wantSize {
					t.Errorf("AppendCanonicalDomainname() size = %v, want %v", size, tt.wantSize)
				}
				return
			}

			if tt.name == "append to existing wire format" {
				w = new(WireFormat)
				*w = []byte{0xff}
			} else {
				w = new(WireFormat)
			}

			size := w.AppendCanonicalDomainname(tt.domain)
			if size != tt.wantSize {
				t.Errorf("AppendCanonicalDomainname() size = %v, want %v", size, tt.wantSize)
			}
			if !bytes.Equal(*w, tt.wantWire) {
				t.Errorf("AppendCanonicalDomainname() wire = %v, want %v", *w, tt.wantWire)
			}
		})
	}
}

func TestWireFormatAppendDomainname(t *testing.T) {
	tests := []struct {
		name     string
		domain   Domainname
		wantWire []byte
		wantSize uint32
	}{
		{
			name:     "nil WireFormat",
			domain:   Domainname{{'a'}},
			wantWire: nil,
			wantSize: 0,
		},
		{
			name:     "nil Domainname",
			domain:   nil,
			wantWire: []byte{0},
			wantSize: 1,
		},
		{
			name:     "root domain (empty Domainname)",
			domain:   Domainname{},
			wantWire: []byte{0},
			wantSize: 1,
		},
		{
			name:     "single label without compression DB",
			domain:   Domainname{{'c', 'o', 'm'}},
			wantWire: []byte{3, 'c', 'o', 'm', 0},
			wantSize: 5,
		},
		{
			name:     "three labels without compression DB",
			domain:   Domainname{{'w', 'w', 'w'}, {'e', 'x', 'a', 'm', 'p', 'l', 'e'}, {'c', 'o', 'm'}},
			wantWire: []byte{3, 'w', 'w', 'w', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0},
			wantSize: 17,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var w *WireFormat
			if tt.name == "nil WireFormat" {
				size := w.AppendDomainname(tt.domain, NewNameCompressionDB())
				if size != tt.wantSize {
					t.Errorf("AppendDomainname() size = %v, want %v", size, tt.wantSize)
				}
				return
			}

			w = new(WireFormat)
			size := w.AppendDomainname(tt.domain, nil)
			if size != tt.wantSize {
				t.Errorf("AppendDomainname() size = %v, want %v", size, tt.wantSize)
			}
			if !bytes.Equal(*w, tt.wantWire) {
				t.Errorf("AppendDomainname() wire = %v, want %v", *w, tt.wantWire)
			}
		})
	}
}

func TestWireFormatAppendDomainname_Compression(t *testing.T) {
	// Compression DB を使用して、2回目以降の同じサフィックスが圧縮ポインタで書き込まれることを確認
	db := NewNameCompressionDB()
	var w WireFormat

	// 1 つ目のドメイン名: www.example.com.
	name1 := Domainname{{'w', 'w', 'w'}, {'e', 'x', 'a', 'm', 'p', 'l', 'e'}, {'c', 'o', 'm'}}
	size1 := w.AppendDomainname(name1, db)
	if size1 != 17 {
		t.Errorf("first AppendDomainname size = %v, want 17", size1)
	}

	// 2 つ目のドメイン名: www.example.com. (同じ名前で圧縮される)
	size2 := w.AppendDomainname(name1, db)
	if size2 != 2 {
		t.Errorf("second AppendDomainname size = %v, want 2 (compression pointer)", size2)
	}
	// 圧縮ポインタ: 0xC0 0x00 (offset 0 を指す)
	if len(w) != 19 {
		t.Errorf("wire length = %v, want 19", len(w))
	}
	if w[17] != 0xC0 || w[18] != 0x00 {
		t.Errorf("compression pointer = %02x %02x, want c0 00", w[17], w[18])
	}
}

func TestWireFormatAppendDomainname_Compression_PartialMatch(t *testing.T) {
	// サフィックスのみが圧縮されるケースを確認
	db := NewNameCompressionDB()
	var w WireFormat

	// 1 つ目: example.com.
	name1 := Domainname{{'e', 'x', 'a', 'm', 'p', 'l', 'e'}, {'c', 'o', 'm'}}
	size1 := w.AppendDomainname(name1, db)
	if size1 != 13 {
		t.Errorf("first AppendDomainname size = %v, want 13", size1)
	}

	// 2 つ目: www.example.com. → "www." を書き、"example.com." のサフィックスは圧縮
	// AppendDomainname は name[i:] (サフィックス) を DB で検索する。
	// name2[1:] = {example, com} は name1[0:] と一致するため、DB に登録されている offset 0 が返される。
	name2 := Domainname{{'w', 'w', 'w'}, {'e', 'x', 'a', 'm', 'p', 'l', 'e'}, {'c', 'o', 'm'}}
	size2 := w.AppendDomainname(name2, db)
	if size2 != 6 {
		t.Errorf("second AppendDomainname size = %v, want 6 (4 bytes for 'www.' + 2 bytes compression pointer)", size2)
	}

	// ワイヤーフォーマットを確認:
	// offset 0-12:  example.com. (13 bytes)
	// offset 13:   3  (label length for "www")
	// offset 14-16: w w w
	// offset 17-18: 0xC0 0x00 (compression pointer to offset 0 where "example.com." starts)
	if len(w) != 19 {
		t.Errorf("wire length = %v, want 19", len(w))
	}
	if w[13] != 3 {
		t.Errorf("label length at offset 13 = %v, want 3", w[13])
	}
	if w[14] != 'w' || w[15] != 'w' || w[16] != 'w' {
		t.Errorf("label at offset 14-16 = %v, want 'www'", []byte{w[14], w[15], w[16]})
	}
	// 圧縮ポインタが offset 0 を指していることを確認
	if w[17] != 0xC0 || w[18] != 0x00 {
		t.Errorf("compression pointer at offset 17-18 = %02x %02x, want c0 00", w[17], w[18])
	}
}

func TestWireFormatAppendDomainname_Compression_RoundTrip(t *testing.T) {
	// 圧縮されたワイヤーフォーマットをパースして、元のドメイン名と一致することを確認
	db := NewNameCompressionDB()
	var w WireFormat

	names := []Domainname{
		{{'w', 'w', 'w'}, {'e', 'x', 'a', 'm', 'p', 'l', 'e'}, {'c', 'o', 'm'}},
		{{'w', 'w', 'w'}, {'e', 'x', 'a', 'm', 'p', 'l', 'e'}, {'c', 'o', 'm'}},
		{{'m', 'a', 'i', 'l'}, {'e', 'x', 'a', 'm', 'p', 'l', 'e'}, {'c', 'o', 'm'}},
	}

	// 圧縮してワイヤーフォーマットに追記
	positions := make([]uint32, 0, len(names))
	for _, name := range names {
		positions = append(positions, w.Size())
		w.AppendDomainname(name, db)
	}

	// 各位置からドメイン名をパースして元の名前と一致することを確認
	for i, pos := range positions {
		parsed, _, err := NewDomainnameFromWireFormat(w, pos)
		if err != nil {
			t.Fatalf("parse name at offset %d: %v", pos, err)
		}
		if !parsed.Equal(names[i]) {
			t.Errorf("round trip name[%d] = %v, want %v", i, parsed, names[i])
		}
	}
}

func TestWireFormatAppendDomainName(t *testing.T) {
	tests := []struct {
		name     string
		domain   string
		wantWire []byte
		wantSize uint32
	}{
		{
			name:     "nil WireFormat",
			domain:   "a.",
			wantWire: nil,
			wantSize: 0,
		},
		{
			name:     "root domain",
			domain:   ".",
			wantWire: []byte{0},
			wantSize: 1,
		},
		{
			name:     "single label",
			domain:   "com.",
			wantWire: []byte{3, 'c', 'o', 'm', 0},
			wantSize: 5,
		},
		{
			name:     "three labels",
			domain:   "www.example.com.",
			wantWire: []byte{3, 'w', 'w', 'w', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0},
			wantSize: 17,
		},
		{
			name:     "append to existing wire format",
			domain:   "a.",
			wantWire: []byte{0xff, 1, 'a', 0},
			wantSize: 3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			name, err := NewDomainNameFromString(tt.domain)
			if err != nil {
				t.Fatalf("NewDomainNameFromString(%q): %v", tt.domain, err)
			}

			var w *WireFormat
			if tt.name == "nil WireFormat" {
				size := w.AppendDomainName(name, NewNameCompressionDB())
				if size != tt.wantSize {
					t.Errorf("AppendDomainName() size = %v, want %v", size, tt.wantSize)
				}
				return
			}

			if tt.name == "append to existing wire format" {
				w = new(WireFormat)
				*w = []byte{0xff}
			} else {
				w = new(WireFormat)
			}

			size := w.AppendDomainName(name, nil)
			if size != tt.wantSize {
				t.Errorf("AppendDomainName() size = %v, want %v", size, tt.wantSize)
			}
			if !bytes.Equal(*w, tt.wantWire) {
				t.Errorf("AppendDomainName() wire = %v, want %v", *w, tt.wantWire)
			}
		})
	}
}

func TestWireFormatAppendDomainName_Compression(t *testing.T) {
	// Compression DB を使用して、2回目以降の同じサフィックスが圧縮ポインタで書き込まれることを確認
	db := NewNameCompressionDB()
	var w WireFormat

	// 1 つ目のドメイン名: www.example.com.
	name, err := NewDomainNameFromString("www.example.com.")
	if err != nil {
		t.Fatalf("NewDomainNameFromString(): %v", err)
	}
	size1 := w.AppendDomainName(name, db)
	if size1 != 17 {
		t.Errorf("first AppendDomainName size = %v, want 17", size1)
	}

	// 2 つ目のドメイン名: www.example.com. (同じ名前で圧縮される)
	size2 := w.AppendDomainName(name, db)
	if size2 != 2 {
		t.Errorf("second AppendDomainName size = %v, want 2 (compression pointer)", size2)
	}
	// 圧縮ポインタ: 0xC0 0x00 (offset 0 を指す)
	if len(w) != 19 {
		t.Errorf("wire length = %v, want 19", len(w))
	}
	if w[17] != 0xC0 || w[18] != 0x00 {
		t.Errorf("compression pointer = %02x %02x, want c0 00", w[17], w[18])
	}
}

func TestWireFormatAppendDomainName_Compression_PartialMatch(t *testing.T) {
	// サフィックスのみが圧縮されるケースを確認
	db := NewNameCompressionDB()
	var w WireFormat

	name1, err := NewDomainNameFromString("example.com.")
	if err != nil {
		t.Fatalf("NewDomainNameFromString(): %v", err)
	}
	// 1 つ目: example.com.
	size1 := w.AppendDomainName(name1, db)
	if size1 != 13 {
		t.Errorf("first AppendDomainName size = %v, want 13", size1)
	}

	// 2 つ目: www.example.com. → "www." を書き、"example.com." のサフィックスは圧縮
	// AppendDomainName は name.labels[i:] (サフィックス) を DB で検索する。
	// name2 の "example" ラベルからのサフィックス {example, com} は name1 の先頭からと一致するため、
	// DB に登録されている offset 0 が返される。
	name2, err := NewDomainNameFromString("www.example.com.")
	if err != nil {
		t.Fatalf("NewDomainNameFromString(): %v", err)
	}
	size2 := w.AppendDomainName(name2, db)
	if size2 != 6 {
		t.Errorf("second AppendDomainName size = %v, want 6 (4 bytes for 'www.' + 2 bytes compression pointer)", size2)
	}

	// ワイヤーフォーマットを確認:
	// offset 0-12:  example.com. (13 bytes)
	// offset 13:   3  (label length for "www")
	// offset 14-16: w w w
	// offset 17-18: 0xC0 0x00 (compression pointer to offset 0 where "example.com." starts)
	if len(w) != 19 {
		t.Errorf("wire length = %v, want 19", len(w))
	}
	if w[13] != 3 {
		t.Errorf("label length at offset 13 = %v, want 3", w[13])
	}
	if w[14] != 'w' || w[15] != 'w' || w[16] != 'w' {
		t.Errorf("label at offset 14-16 = %v, want 'www'", []byte{w[14], w[15], w[16]})
	}
	// 圧縮ポインタが offset 0 を指していることを確認
	if w[17] != 0xC0 || w[18] != 0x00 {
		t.Errorf("compression pointer at offset 17-18 = %02x %02x, want c0 00", w[17], w[18])
	}
}

func TestWireFormatAppendDomainName_CompressionDB(t *testing.T) {
	// 1 番目に www.example.com.、2 番目に mail.example.com. を書き込むことで、
	//   (1) 書き込まれたドメイン名(およびサフィックス)が NameCompressionDB に
	//       それぞれの開始位置と共に登録されること
	//   (2) 2 番目の "mail.example.com." の "example.com." 部分が圧縮されること
	// を確認
	db := NewNameCompressionDB()
	var w WireFormat

	name1, err := NewDomainNameFromString("www.example.com.")
	if err != nil {
		t.Fatalf("NewDomainNameFromString(): %v", err)
	}
	// 1 番目: www.example.com. → ラベル www(4) + example(8) + com(4) + 終端(1)
	if size := w.AppendDomainName(name1, db); size != 17 {
		t.Errorf("first AppendDomainName size = %v, want 17", size)
	}

	name2, err := NewDomainNameFromString("mail.example.com.")
	if err != nil {
		t.Fatalf("NewDomainNameFromString(): %v", err)
	}
	// 2 番目: mail.example.com. → ラベル mail(5) + 圧縮ポインタ(2)
	// ("example.com." は 1 番目の名前で既に書き込まれているため圧縮される)
	if size := w.AppendDomainName(name2, db); size != 7 {
		t.Errorf("second AppendDomainName size = %v, want 7 (5 bytes for 'mail.' + 2 bytes compression pointer)", size)
	}

	// NameCompressionDB には、次のドメイン名がそれぞれの開始位置で登録されている
	dbChecks := []struct {
		name    string
		wantPtr uint16
	}{
		{name: "www.example.com.", wantPtr: 0},
		{name: "example.com.", wantPtr: 4},
		{name: "com.", wantPtr: 12},
		{name: "mail.example.com.", wantPtr: 17},
	}
	for _, tt := range dbChecks {
		t.Run(tt.name, func(t *testing.T) {
			n, err := NewDomainNameFromString(tt.name)
			if err != nil {
				t.Fatalf("NewDomainNameFromString(%q): %v", tt.name, err)
			}
			pointer, found := db.FindDomainName(n)
			if !found {
				t.Errorf("db.FindDomainName(%q) should be found", tt.name)
				return
			}
			if pointer != tt.wantPtr {
				t.Errorf("db.FindDomainName(%q) pointer = %v, want %v", tt.name, pointer, tt.wantPtr)
			}
		})
	}

	// ワイヤーフォーマットを確認:
	// offset 0-16:  www.example.com. (17 bytes, 非圧縮)
	// offset 17:    4  ("mail" のラベル長)
	// offset 18-21: m a i l
	// offset 22-23: 0xC0 0x04 (offset 4 の "example.com." を指す圧縮ポインタ)
	if len(w) != 24 {
		t.Errorf("wire length = %v, want 24", len(w))
	}
	if w[17] != 4 {
		t.Errorf("label length at offset 17 = %v, want 4", w[17])
	}
	if w[18] != 'm' || w[19] != 'a' || w[20] != 'i' || w[21] != 'l' {
		t.Errorf("label at offset 18-21 = %v, want 'mail'", []byte{w[18], w[19], w[20], w[21]})
	}
	// "example.com." 部分の圧縮ポインタが offset 4 (0xC004) を指すことを確認
	if w[22] != 0xC0 || w[23] != 0x04 {
		t.Errorf("compression pointer at offset 22-23 = %02x %02x, want c0 04", w[22], w[23])
	}
}

func TestWireFormatAppendDomainName_Compression_CaseInsensitive(t *testing.T) {
	// ドメイン名の大文字小文字は区別しない(RFC 4343 §2)ため、
	// 大文字小文字が異なる名前でも同じ圧縮ポインタが使われることを確認
	db := NewNameCompressionDB()
	var w WireFormat

	name, err := NewDomainNameFromString("www.example.com.")
	if err != nil {
		t.Fatalf("NewDomainNameFromString(): %v", err)
	}
	size1 := w.AppendDomainName(name, db)
	if size1 != 17 {
		t.Errorf("first AppendDomainName size = %v, want 17", size1)
	}

	upper, err := NewDomainNameFromString("WWW.EXAMPLE.COM.")
	if err != nil {
		t.Fatalf("NewDomainNameFromString(): %v", err)
	}
	size2 := w.AppendDomainName(upper, db)
	if size2 != 2 {
		t.Errorf("AppendDomainName for differently-cased name = %v, want 2 (compression pointer)", size2)
	}
	// 圧縮ポインタ: 0xC0 0x00 (offset 0 を指す)
	if len(w) != 19 {
		t.Errorf("wire length = %v, want 19", len(w))
	}
	if w[17] != 0xC0 || w[18] != 0x00 {
		t.Errorf("compression pointer = %02x %02x, want c0 00", w[17], w[18])
	}
}

func TestWireFormatSize(t *testing.T) {
	tests := []struct {
		name     string
		wire     WireFormat
		wantSize uint32
	}{
		{
			name:     "nil WireFormat",
			wire:     nil,
			wantSize: 0,
		},
		{
			name:     "empty WireFormat",
			wire:     WireFormat{},
			wantSize: 0,
		},
		{
			name:     "WireFormat with data",
			wire:     WireFormat{1, 2, 3, 4, 5},
			wantSize: 5,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.wire.Size(); got != tt.wantSize {
				t.Errorf("Size() = %v, want %v", got, tt.wantSize)
			}
		})
	}
}

func TestWireFormatString(t *testing.T) {
	tests := []struct {
		name    string
		w       WireFormat
		wantStr string
	}{
		{
			name:    "empty WireFormat",
			w:       WireFormat{},
			wantStr: "",
		},
		{
			name:    "single byte",
			w:       WireFormat{0x42},
			wantStr: "42 ",
		},
		{
			name:    "multiple bytes",
			w:       WireFormat{0x12, 0x34, 0x56},
			wantStr: "12 34 56 ",
		},
		{
			name:    "bytes with leading zeros",
			w:       WireFormat{0x01, 0x0a, 0x00},
			wantStr: "01 0a 00 ",
		},
		{
			name:    "nil WireFormat",
			w:       nil,
			wantStr: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.w.String(); got != tt.wantStr {
				t.Errorf("String() = %q, want %q", got, tt.wantStr)
			}
		})
	}
}

func TestWireFormatAppendUInt8(t *testing.T) {
	tests := []struct {
		name   string
		w      WireFormat
		value  uint8
		wantW  WireFormat
		wantSz uint32
	}{
		{
			name:   "zero value",
			w:      WireFormat{},
			value:  0,
			wantW:  WireFormat{0},
			wantSz: 1,
		},
		{
			name:   "max uint8",
			w:      WireFormat{},
			value:  0xFF,
			wantW:  WireFormat{0xFF},
			wantSz: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sz := tt.w.AppendUInt8(tt.value)
			if sz != tt.wantSz {
				t.Errorf("AppendUInt8() = %v, want %v", sz, tt.wantSz)
			}
			if !bytes.Equal(tt.w, tt.wantW) {
				t.Errorf("wire = %v, want %v", tt.w, tt.wantW)
			}
		})
	}
}

func TestWireFormatAppendUInt16(t *testing.T) {
	tests := []struct {
		name   string
		w      WireFormat
		value  uint16
		wantW  WireFormat
		wantSz uint32
	}{
		{
			name:   "big endian encoding",
			w:      WireFormat{},
			value:  0x1234,
			wantW:  WireFormat{0x12, 0x34},
			wantSz: 2,
		},
		{
			name:   "zero value",
			w:      WireFormat{},
			value:  0,
			wantW:  WireFormat{0, 0},
			wantSz: 2,
		},
		{
			name:   "max uint16",
			w:      WireFormat{},
			value:  0xFFFF,
			wantW:  WireFormat{0xFF, 0xFF},
			wantSz: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sz := tt.w.AppendUInt16(tt.value)
			if sz != tt.wantSz {
				t.Errorf("AppendUInt16() = %v, want %v", sz, tt.wantSz)
			}
			if !bytes.Equal(tt.w, tt.wantW) {
				t.Errorf("wire = %v, want %v", tt.w, tt.wantW)
			}
		})
	}
}

func TestWireFormatAppendUInt32(t *testing.T) {
	tests := []struct {
		name   string
		w      WireFormat
		value  uint32
		wantW  WireFormat
		wantSz uint32
	}{
		{
			name:   "big endian encoding",
			w:      WireFormat{},
			value:  0x12345678,
			wantW:  WireFormat{0x12, 0x34, 0x56, 0x78},
			wantSz: 4,
		},
		{
			name:   "zero value",
			w:      WireFormat{},
			value:  0,
			wantW:  WireFormat{0, 0, 0, 0},
			wantSz: 4,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sz := tt.w.AppendUInt32(tt.value)
			if sz != tt.wantSz {
				t.Errorf("AppendUInt32() = %v, want %v", sz, tt.wantSz)
			}
			if !bytes.Equal(tt.w, tt.wantW) {
				t.Errorf("wire = %v, want %v", tt.w, tt.wantW)
			}
		})
	}
}

func TestWireFormatPutUint8(t *testing.T) {
	tests := []struct {
		name   string
		w      WireFormat
		offset uint32
		value  uint8
		wantOk uint32
		wantW  WireFormat
	}{
		{
			name:   "nil WireFormat",
			w:      nil,
			offset: 0,
			value:  0x42,
			wantOk: 0,
			wantW:  nil,
		},
		{
			name:   "out of bounds",
			w:      WireFormat{0},
			offset: 1,
			value:  0x42,
			wantOk: 0,
			wantW:  WireFormat{0},
		},
		{
			name:   "write at offset 0",
			w:      WireFormat{0x00},
			offset: 0,
			value:  0xAB,
			wantOk: 1,
			wantW:  WireFormat{0xAB},
		},
		{
			name:   "write at offset 2",
			w:      WireFormat{0x01, 0x02, 0x00},
			offset: 2,
			value:  0xCD,
			wantOk: 1,
			wantW:  WireFormat{0x01, 0x02, 0xCD},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ok, err := tt.w.PutUint8(tt.offset, tt.value)
			if (err != nil) != (tt.wantOk == 0) {
				t.Errorf("PutUint8() error = %v, wantOk %v", err, tt.wantOk)
			}
			if ok != tt.wantOk {
				t.Errorf("PutUint8() = %v, want %v", ok, tt.wantOk)
			}
			if !bytes.Equal(tt.w, tt.wantW) {
				t.Errorf("wire = %v, want %v", tt.w, tt.wantW)
			}
		})
	}
}

func TestWireFormatPutUint16(t *testing.T) {
	tests := []struct {
		name   string
		w      WireFormat
		offset uint32
		value  uint16
		wantOk uint32
		wantW  WireFormat
	}{
		{
			name:   "nil WireFormat",
			w:      nil,
			offset: 0,
			value:  0x1234,
			wantOk: 0,
			wantW:  nil,
		},
		{
			name:   "out of bounds",
			w:      WireFormat{0, 0, 0},
			offset: 2,
			value:  0x1234,
			wantOk: 0,
			wantW:  WireFormat{0, 0, 0},
		},
		{
			name:   "write at offset 0",
			w:      WireFormat{0x00, 0x00},
			offset: 0,
			value:  0x1234,
			wantOk: 2,
			wantW:  WireFormat{0x12, 0x34},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ok, err := tt.w.PutUint16(tt.offset, tt.value)
			if (err != nil) != (tt.wantOk == 0) {
				t.Errorf("PutUint16() error = %v, wantOk %v", err, tt.wantOk)
			}
			if ok != tt.wantOk {
				t.Errorf("PutUint16() = %v, want %v", ok, tt.wantOk)
			}
			if !bytes.Equal(tt.w, tt.wantW) {
				t.Errorf("wire = %v, want %v", tt.w, tt.wantW)
			}
		})
	}
}

func TestWireFormatPutUint32(t *testing.T) {
	tests := []struct {
		name   string
		w      WireFormat
		offset uint32
		value  uint32
		wantOk uint32
		wantW  WireFormat
	}{
		{
			name:   "nil WireFormat",
			w:      nil,
			offset: 0,
			value:  0x12345678,
			wantOk: 0,
			wantW:  nil,
		},
		{
			name:   "out of bounds",
			w:      WireFormat{0, 0, 0, 0, 0},
			offset: 2,
			value:  0x12345678,
			wantOk: 0,
			wantW:  WireFormat{0, 0, 0, 0, 0},
		},
		{
			name:   "write at offset 0",
			w:      WireFormat{0x00, 0x00, 0x00, 0x00},
			offset: 0,
			value:  0x12345678,
			wantOk: 4,
			wantW:  WireFormat{0x12, 0x34, 0x56, 0x78},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ok, err := tt.w.PutUint32(tt.offset, tt.value)
			if (err != nil) != (tt.wantOk == 0) {
				t.Errorf("PutUint32() error = %v, wantOk %v", err, tt.wantOk)
			}
			if ok != tt.wantOk {
				t.Errorf("PutUint32() = %v, want %v", ok, tt.wantOk)
			}
			if !bytes.Equal(tt.w, tt.wantW) {
				t.Errorf("wire = %v, want %v", tt.w, tt.wantW)
			}
		})
	}
}

func TestWireFormatGetUInt8(t *testing.T) {
	tests := []struct {
		name      string
		w         WireFormat
		offset    uint32
		wantValue uint8
		wantErr   bool
	}{
		{
			name:      "nil WireFormat",
			w:         nil,
			offset:    0,
			wantValue: 0,
			wantErr:   true,
		},
		{
			name:      "out of bounds",
			w:         WireFormat{0xAB},
			offset:    1,
			wantValue: 0,
			wantErr:   true,
		},
		{
			name:      "read at offset 0",
			w:         WireFormat{0xAB, 0xCD},
			offset:    0,
			wantValue: 0xAB,
			wantErr:   false,
		},
		{
			name:      "read at offset 1",
			w:         WireFormat{0xAB, 0xCD},
			offset:    1,
			wantValue: 0xCD,
			wantErr:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotValue, err := tt.w.GetUInt8(tt.offset)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetUInt8() error = %v, wantErr %v", err, tt.wantErr)
			}
			if gotValue != tt.wantValue {
				t.Errorf("GetUInt8() = %v, want %v", gotValue, tt.wantValue)
			}
		})
	}
}

func TestWireFormatGetUInt16(t *testing.T) {
	tests := []struct {
		name      string
		w         WireFormat
		offset    uint32
		wantValue uint16
		wantErr   bool
	}{
		{
			name:      "nil WireFormat",
			w:         nil,
			offset:    0,
			wantValue: 0,
			wantErr:   true,
		},
		{
			name:      "out of bounds",
			w:         WireFormat{0x12, 0x34, 0x56},
			offset:    2,
			wantValue: 0,
			wantErr:   true,
		},
		{
			name:      "read at offset 0",
			w:         WireFormat{0x12, 0x34, 0x56, 0x78},
			offset:    0,
			wantValue: 0x1234,
			wantErr:   false,
		},
		{
			name:      "read at offset 2",
			w:         WireFormat{0x12, 0x34, 0x56, 0x78},
			offset:    2,
			wantValue: 0x5678,
			wantErr:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotValue, err := tt.w.GetUInt16(tt.offset)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetUInt16() error = %v, wantErr %v", err, tt.wantErr)
			}
			if gotValue != tt.wantValue {
				t.Errorf("GetUInt16() = %v, want %v", gotValue, tt.wantValue)
			}
		})
	}
}

func TestWireFormatGetUInt32(t *testing.T) {
	tests := []struct {
		name      string
		w         WireFormat
		offset    uint32
		wantValue uint32
		wantErr   bool
	}{
		{
			name:      "nil WireFormat",
			w:         nil,
			offset:    0,
			wantValue: 0,
			wantErr:   true,
		},
		{
			name:      "out of bounds",
			w:         WireFormat{0x12, 0x34, 0x56, 0x78, 0x9A},
			offset:    2,
			wantValue: 0,
			wantErr:   true,
		},
		{
			name:      "read at offset 0",
			w:         WireFormat{0x12, 0x34, 0x56, 0x78},
			offset:    0,
			wantValue: 0x12345678,
			wantErr:   false,
		},
		{
			name:      "read at offset 4",
			w:         WireFormat{0x00, 0x00, 0x00, 0x00, 0x12, 0x34, 0x56, 0x78},
			offset:    4,
			wantValue: 0x12345678,
			wantErr:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotValue, err := tt.w.GetUInt32(tt.offset)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetUInt32() error = %v, wantErr %v", err, tt.wantErr)
			}
			if gotValue != tt.wantValue {
				t.Errorf("GetUInt32() = %v, want %v", gotValue, tt.wantValue)
			}
		})
	}
}

func TestWireFormatAppendBytes(t *testing.T) {
	tests := []struct {
		name   string
		w      WireFormat
		bytes  []byte
		wantW  WireFormat
		wantSz uint32
	}{
		{
			name:   "empty bytes",
			w:      WireFormat{},
			bytes:  []byte{},
			wantW:  WireFormat{},
			wantSz: 0,
		},
		{
			name:   "append to empty",
			w:      WireFormat{},
			bytes:  []byte{0x12, 0x34, 0x56},
			wantW:  WireFormat{0x12, 0x34, 0x56},
			wantSz: 3,
		},
		{
			name:   "append to existing",
			w:      WireFormat{0xAA, 0xBB},
			bytes:  []byte{0xCC, 0xDD},
			wantW:  WireFormat{0xAA, 0xBB, 0xCC, 0xDD},
			wantSz: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sz := tt.w.AppendBytes(tt.bytes)
			if sz != tt.wantSz {
				t.Errorf("AppendBytes() = %v, want %v", sz, tt.wantSz)
			}
			if !bytes.Equal(tt.w, tt.wantW) {
				t.Errorf("wire = %v, want %v", tt.w, tt.wantW)
			}
		})
	}
}

func TestWireFormatGetBytes(t *testing.T) {
	tests := []struct {
		name      string
		w         WireFormat
		offset    uint32
		length    uint32
		wantBytes []byte
		wantErr   bool
	}{
		{
			name:      "nil WireFormat",
			w:         nil,
			offset:    0,
			length:    2,
			wantBytes: nil,
			wantErr:   true,
		},
		{
			name:      "out of bounds offset",
			w:         WireFormat{0x12, 0x34},
			offset:    2,
			length:    1,
			wantBytes: nil,
			wantErr:   true,
		},
		{
			name:      "out of bounds length",
			w:         WireFormat{0x12, 0x34, 0x56},
			offset:    1,
			length:    3,
			wantBytes: nil,
			wantErr:   true,
		},
		{
			name:      "read from start",
			w:         WireFormat{0x12, 0x34, 0x56, 0x78},
			offset:    0,
			length:    2,
			wantBytes: []byte{0x12, 0x34},
			wantErr:   false,
		},
		{
			name:      "read from middle",
			w:         WireFormat{0x12, 0x34, 0x56, 0x78},
			offset:    1,
			length:    2,
			wantBytes: []byte{0x34, 0x56},
			wantErr:   false,
		},
		{
			name:      "read all",
			w:         WireFormat{0xAA, 0xBB, 0xCC},
			offset:    0,
			length:    3,
			wantBytes: []byte{0xAA, 0xBB, 0xCC},
			wantErr:   false,
		},
		{
			name:      "zero length",
			w:         WireFormat{0x12},
			offset:    0,
			length:    0,
			wantBytes: []byte{},
			wantErr:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotBytes, err := tt.w.GetBytes(tt.offset, tt.length)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetBytes() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !bytes.Equal(gotBytes, tt.wantBytes) {
				t.Errorf("GetBytes() = %v, want %v", gotBytes, tt.wantBytes)
			}
		})
	}
}
