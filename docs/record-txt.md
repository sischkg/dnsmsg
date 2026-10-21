# TXT レコード（`RecordTXT`）

TXT レコード（TYPE=16、`TYPE_TXT`）は、オーナー名に結び付いた任意のテキストを
保持する DNS リソースレコードです（RFC 1035 Section 3.3.14）。SPF の正当性
検証（RFC 7208）やドメイン所有権の確認などに使われます。

RDATA は 1 個以上の character-string からなります。character-string は
1 バイトの長さオクタットと、その長さ分のオクテットです（RFC 1035
Section 3.3）。1 個の character-string が保持できるのは 255 オクテットまでで、
RDLENGTH は「1 + 各文字列の長さ」の合計になります。

TXT のテキストは解釈されません。`RecordTXT` はオクテット列をそのまま保持し、
解读（デコード）も行いません。

## レコードの構造

| 項目 | 内容 |
|------|------|
| Name | オーナー名（`DomainName`） |
| Class | `CLASS_IN` (1) |
| Type | `TYPE_TXT` (16) |
| TTL | TTL（秒） |
| RDATA | 1 個以上の character-string（RDLENGTH は `1 + 各文字列の長さ` の合計。例: 11 オクテットの文字列 1 個なら 12 バイト） |

`RecordTXT` の中身フィールド `Strings`（`[][]byte`）はエクスポート済みです
（パッケージの外から `rdata.Strings` で直接読めます）。

## 主要な API

| API | 説明 |
|-----|------|
| `NewRecordTXT(strs ...[]byte) RecordTXT` | オクテット列から直接構築。エラーは返さない |
| `NewRecordTXTFromString(s string) (RecordTXT, error)` | 表示形式文字列から構築。引用符付き・引用符なしの文字列やエスケープを解釈する |
| `ParseRecordTXT(w WireFormat, begin uint32, end uint32) (RecordTXT, uint32, error)` | `w` の `begin` から `end` までを character-string の列としてパース。成功時は `end` を返す |
| `(RecordTXT).Type() ResourceType` | `TYPE_TXT` (16) |
| `(RecordTXT).String() string` | 表示形式（各 character-string を二重引用符で囲み、空白で区切る） |
| `(RecordTXT).CanonicalWireFormat() []byte` | canonical 形の RDATA（RFC 4034: TXT にはドメイン名がないので RDATA はそのまま） |
| `(RecordTXT).AppendWireFormat(w *WireFormat, db *NameCompressionDB) uint32` | RDATA を `w` に付加。`db` は使わない（TXT の RDATA にドメイン名は含まれない） |
| `(RecordTXT).AppendCanonicalWireFormat(w *WireFormat) uint32` | canonical 形の RDATA を付加 |

`RecordTXT` は `RDATA` インターフェースを実装します。
`ParseResourceRecord` の `TYPE_TXT` case で `rr.RData` には `RecordTXT`（値）が
格納されます。

## 構築と表示

```go
txt, err := dnsmsg.NewRecordTXTFromString(`"v=spf1 -all"`)
// err == nil
fmt.Println(txt.String()) // "\"v=spf1 -all\""
```

表示形式では、各 character-string を二重引用符で囲み、多个の文字列は空白で
区切ります（実測確認済み）。

```go
txt, err := dnsmsg.NewRecordTXTFromString(`"foo" "bar"`)
// err == nil
fmt.Println(txt.String()) // "\"foo\" \"bar\""
```

引用符で囲んだ文字列は空白を含むことができます。引用符で囲まない文字列は
空白または引用符で終わります。どちらの形式でも、バックスラッシュは
エスケープとして働きます。

| 入力 | 結果 | 備考 |
|------|------|------|
| `hello` | `"hello"` | 引用符なしの文字列 |
| `"hello world"` | `"hello world"` | 引用符付きの文字列（空白を含む） |
| `v=spf1 -all` | `"v=spf1" "-all"` | 引用符なしの文字列は空白で終わるので 2 個になる |
| `"foo" "bar"` | `"foo" "bar"` | 2 個の character-string |
| `ab"cd"` | `"ab" "cd"` | 引用符なしの文字列の直後に引用符付き文字列が続く |
| `""` | `""` | 空の character-string |
| `a\032b` | `"a b"` | 3 桁の十進数エスケープ（RFC 4343） |
| `"say \"hi\" \\"` | `"say \"hi\" \\"` | 引用符とバックスラッシュのエスケープ |

`NewRecordTXTFromString` のエラー一覧（実測確認済み）:

| 条件 | エラー |
|------|--------|
| character-string が 1 個もない（空文字列、空白のみ） | `TXT record "" has no character-strings` |
| 引用符で閉じていない | `unterminated character-string in "\"abc"` |
| 末尾に孤立したバックスラッシュ | `last character of tail\ is \` |
| 256 オクテット以上の文字列 | `character-string is too long(length exceeds 255)` |

## RDATA の直接パース（`ParseRecordTXT`）

`ParseRecordTXT` は RDLENGTH で決まる範囲だけを読みます。`end` は RDATA の
終端（`ParseResourceRecord` では RDLENGTH から計算されます）を表し、
メッセージの残りの部分ではなく RDATA 自身が境界になります。

```go
wire := []byte{0x0b, 'v', '=', 's', 'p', 'f', '1', ' ', '-', 'a', 'l', 'l'}
txt, pos, err := dnsmsg.ParseRecordTXT(wire, 0, uint32(len(wire)))
// err == nil, pos == 12
fmt.Println(txt.String()) // "\"v=spf1 -all\""
```

RDLENGTH が 0 のレコード（character-string が 1 個もない）はエラーになります。

エラー一覧（実測確認済み）:

| 条件 | エラー |
|------|--------|
| `end` が `w` の範囲外 | `invalid TXT record RDATA size` |
| character-string が 1 個もない（RDLENGTH 0） | `TXT record has no character-strings` |
| 長さオクタットが RDATA の残りより大きい | `character-string exceeds RDATA(length: 4, remaining: 2)` |

## レコード全体の round-trip（`ParseResourceRecord`、実測確認済み）

`txt.example.com` の TXT が `v=spf1 -all` を指すレコードの wire format の例
（合計 39 バイト）:

```
03 74 78 74 07 65 78 61 6d 70 6c 65 03 63 6f 6d 00   ;; name = txt.example.com (19 バイト)
00 10                                                ;; TYPE = TXT (16)
00 01                                                ;; CLASS = IN (1)
00 00 01 2c                                          ;; TTL = 300
00 0c                                                ;; RDLENGTH = 12
0b 76 3d 73 70 66 31 20 2d 61 6c 6c                  ;; RDATA = 「v=spf1 -all」（12 バイト）
```

```go
wire := []byte{
    0x03, 't', 'x', 't', 0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x03, 'c', 'o', 'm', 0x00,
    0x00, 0x10, 0x00, 0x01, 0x00, 0x00, 0x01, 0x2c, 0x00, 0x0c,
    0x0b, 'v', '=', 's', 'p', 'f', '1', ' ', '-', 'a', 'l', 'l',
}
rr, end, err := dnsmsg.ParseResourceRecord(wire, 0)
// err == nil, end == 39
// rr.Type == TYPE_TXT, rr.Class == CLASS_IN, rr.TTL == 300
fmt.Println(rr.String()) // "txt.example.com. 1 16 300 \"v=spf1 -all\""

rdata := rr.RData.(dnsmsg.RecordTXT)
fmt.Println(rdata.String()) // "\"v=spf1 -all\""
```

## シリアライズ

### 圧縮なし（`db` = nil でも同じ）

TXT の RDATA にドメイン名は含まれないため、名前圧縮は行われません。`db` に
nil を渡しても非 nil を渡しても結果は同じです。

RDATA は各 character-string の「1 バイトの長さオクタット + オクテット列」で
書き出されます。

```
0b 76 3d 73 70 66 31 20 2d 61 6c 6c   ;; 「v=spf1 -all」
```

### 255 オクテットを超える文字列

character-string は最大 255 オクテットしか持てないため、255 オクテットを
超える文字列は複数の character-string に分割されて書き出されます。これは
より長いテキストを公開する名前サーバの做法と同じです（実測確認済み）。

300 オクテットの文字列 1 個は 302 バイト（`ff` + 255 バイト + `2d` + 45 バイト）
の RDATA になります。

```
ff 61 61 ... 61   ;; 1 つめの character-string（255 オクテット）
2d 61 61 ... 61   ;; 2 つめの character-string（45 オクテット）
```

分割してもオクテット列自体は失われません。連結した character-string は
元の文字列と一致します。

### canonical 形

`AppendCanonicalWireFormat` は RDATA をそのまま書き出します。RFC 4034
Section 6.2 の canonical 形は RDATA 内のドメイン名を変換しますが、TXT の
RDATA にドメイン名は含まれないため、変換的对象はありません（実測確認済み）。

```
0b 76 3d 73 70 66 31 20 2d 61 6c 6c
```

## JSON

`RecordTXT` は `MarshalJSON` / `UnmarshalJSON` を持ちます。character-string は
オクテット列なので base64 文字列としてエンコードされます。base64 は
パディングなし（RFC 4634）で、デコード時はパディングありの形式も受け付けます。

```go
json.Marshal(txt)
// {"Strings":["dj1zcGYxIC1hbGw"]}

json.Marshal(rr) // rr.Type == TYPE_TXT の場合
// {"Class":"IN","Name":"txt.example.com.","RData":{"Strings":["dj1zcGYxIC1hbGw"]},"TTL":300,"Type":"TXT"}
```

`ResourceRecord.UnmarshalJSON` は `Type` が `"TXT"`（または 16）のとき
`RData` を `RecordTXT` としてデコードします。base64 として不正な文字列
（`"!!!"` など）はエラーになります。

## 補足

- TXT の RDATA にはドメイン名がないため、`AppendWireFormat` は
  `NameCompressionDB` を使いません。`db` に nil を渡しても非 nil を渡しても
  出力は同じです。
- `RecordTXT.String()` は表示形式を返します。引用符（`"`）とバックスラッシュ
  （`\`）は `\"` と `\\` にエスケープされ、印字できないオクテット
  （0x20 未満と 0x7e より大きい値）は `\065` のような 3 桁の十進数
  エスケープになります（RFC 4343）。空白と `.` は引用符の中でそのまま
  出力されます。
- `ParseResourceRecord` の `TYPE_TXT` case では `rr.RData` に `RecordTXT` が
  格納されるため、`rr.RData.(dnsmsg.RecordTXT)` で取り出せます
  （index.md の「レコードデータの取り出し」参照）。
- `dq` コマンドでも `-t TXT` で TXT query を送信できます（dq.md 参照）。
