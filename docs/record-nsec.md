# NSEC レコード（`RecordNSEC`）

NSEC レコード（TYPE=32、`TYPE_NSEC`）は、ゾーン内に**存在しないドメイン名**の証明（DNSSEC の否定応答）に使われる DNS リソースレコードです（RFC 4034 Section 5.2）。

RDATA は 2 つの部分から構成されます。

1. **Next Domain Name**: 正規順序における次の NSEC レコードの所有者名（ドメイン名、名前圧縮あり）
2. **Type Bit Maps**: 所有者名に存在する RR タイプの集合（ウィンドウごとのビットマップ）

```
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/                     Next Domain Name /                                \
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/                     Type Bit Maps /                                     \
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

## レコードの構造

| 項目 | 内容 |
|------|------|
| Name | ドメイン名（`DomainName`） |
| Class | `CLASS_IN` (1) |
| Type | `TYPE_NSEC` (32) |
| TTL | TTL（秒） |
| RDATA | Next Domain Name（圧縮対応） + Type Bit Maps（非圧縮） |

`RecordNSEC` の中身フィールド `NextDomainName`（`DomainName`）と `Types`（`[]ResourceType`）はエクスポート済みです。パッケージの外からは `String()`（表示形式）や `CanonicalWireFormat()`（wire format のバイト列）で取り出します（index.md の「レコードデータの取り出し」の型アサーション例参照）。

## 主要な API

| API | 説明 |
|-----|------|
| `NewRecordNSEC(nextDomainName DomainName, types []ResourceType) RecordNSEC` | 構造体から直接構築。`types` は昇順にソートされて保持される（決定的なエンコーディングのため） |
| `NewRecordNSECFromString(s string) (RecordNSEC, error)` | 表示形式文字列から構築。形式は `<次ドメイン名> <タイプ> [<タイプ> ...]`。タイプは数値（`32`）または型名（`NSEC`、`TYPE32`） |
| `ParseRecordNSEC(w WireFormat, begin uint32, end uint32) (RecordNSEC, uint32, error)` | `w` の `begin` オフセットから Next Domain Name（圧縮ポインタ対応）と Type Bit Maps（`end` で RDLENGTH 範囲を区切る）をパース。成功時は終端オフセットを返す |
| `(RecordNSEC).Type() ResourceType` | `TYPE_NSEC` (32) |
| `(RecordNSEC).String() string` | 表示形式（例: `"example.org. A NS"`。ルート単独は `"."`） |
| `(RecordNSEC).CanonicalWireFormat() []byte` | Next Domain Name（小文字・非圧縮） + Type Bit Maps の canonical wire format |
| `(RecordNSEC).AppendWireFormat(w *WireFormat, db *NameCompressionDB) uint32` | Next Domain Name を `w.AppendDomainName` 経由で付加（`db` が nil でなければ圧縮ポインタ適用）、Type Bit Maps を付加 |
| `(RecordNSEC).AppendCanonicalWireFormat(w *WireFormat) uint32` | canonical 形（小文字・非圧縮）を付加 |

`RecordNSEC` は `RDATA` インターフェースを実装します。`ParseResourceRecord` の `TYPE_NSEC` case で `rr.RData` には `RecordNSEC`（値）が格納されます。

## 構築と表示

```go
nsec, err := dnsmsg.NewRecordNSECFromString("example.org A NS")
// err == nil
fmt.Println(nsec.String()) // "example.org. A NS"

// 数値タイプコードでも指定可能
nsec2, err := dnsmsg.NewRecordNSECFromString("example.org 1 2")
// err == nil
fmt.Println(nsec2.String()) // "example.org. A NS"

// TYPE prefix も受理
nsec3, err := dnsmsg.NewRecordNSECFromString("example.org TYPE1 TYPE2")
// err == nil
fmt.Println(nsec3.String()) // "example.org. A NS"
```

`NewRecordNSEC` は渡された `types` を昇順にソートして保持します:

```go
nsec := dnsmsg.NewRecordNSEC(
    dnsmsg.MustDomainName(t, "example.org"), // 例
    []dnsmsg.ResourceType{dnsmsg.TYPE_NS, dnsmsg.TYPE_A},
)
// nsec.Types == []ResourceType{TYPE_A, TYPE_NS}（ソート済み）
```

> **注**: `MustDomainName` はテスト用ヘルパーです。本パッケージには `NewDomainNameFromString` を使ってください。

`NewRecordNSECFromString` のエラー一覧（実測確認済み）:

| 条件 | エラー |
|------|--------|
| フィールド数が 2 未満（ドメイン名だけ、または空） | `invalid NSEC record format "..."` |
| 次ドメイン名が不正 | `invalid next domain name "..."`（`NewDomainNameFromString` のエラー） |
| 未知のタイプ名 | `unknown resource type "FOO"`（`NewType` のエラー） |
| 非数値・非型名のタイプトークン | `unknown resource type "..."` |

## RDATA の直接パース（`ParseRecordNSEC`）

```go
wire := []byte{
    0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', // label: example
    0x03, 'o', 'r', 'g', 0x00,                // label: org + root (Next Domain Name)
    0x00,                                     // type bitmap window 0
    0x01,                                     // bitmap length 1 octet
    0x60,                                     // bitmap: TYPE_A(bit6) + TYPE_NS(bit5)
}
nsec, end, err := dnsmsg.ParseRecordNSEC(wire, 0, uint32(len(wire)))
// err == nil, end == 16
fmt.Println(nsec.String()) // "example.org. A NS"
```

Type Bit Maps は `end`（RDLENGTH 由来のレコード終端オフセット）で区切られるため、メッセージ全体の残りではなくレコード内のみが読み込まれます（`ParseRecordDS` / `ParseRecordRRSIG` と同じ設計）。

エラー一覧（実測確認済み）:

| 条件 | エラー |
|------|--------|
| Next Domain Name が不正・未終了 | `cannot parse next domain name: ...` |
| タイプビットマップのウィンドウヘッダが不足 | `cannot parse NSEC type bitmap window header` |
| タイプビットマップ長が 0 または 32 を超える | `invalid NSEC type bitmap length N` |
| タイプビットマップがレコード範囲を超える | `NSEC type bitmap extends beyond record` |
| `begin` オフセットが範囲外 | `out of bound in parsing domainname` |

## タイプビットマップの仕様

各ウィンドウは 3 つのフィールドで構成されます。

| フィールド | サイズ | 意味 |
|----------|--------|------|
| Window Block # | 1 オクテット | タイプの上位ビット（`type / 256`） |
| Bitmap Length | 1 オクテット | ビットマップのオクテット数（1〜32） |
| Bitmap | 可変 | 各タイプの存在を 1 ビットで表現。bit 7（MSB）がオクテット内の最小タイプ |

ビット番号付けは MSB 優先です。例えばオクテット内でタイプ 0〜7 は bit 7〜0 に対応します。

例: `TYPE_A (1)` と `TYPE_NS (2)` はどちらもウィンドウ 0（0〜255）に属し、1 オクテットのビットマップで表現できます。

- タイプ 1 → bit 6 = `0x40`
- タイプ 2 → bit 5 = `0x20`
- ビットマップ = `0x60`

ワイヤ出力:
```
00 01 60   ;; window 0, length 1, bitmap 0x60
```

存在するタイプがない場合はウィンドウ自体が出力されず（空のビットマップ）、Type Bit Maps 部分は 0 オクテットになります。

## レコード全体の round-trip（`ParseResourceRecord`、実測確認済み）

`example.org.` の NSEC（次ドメイン名 `example.org.`、タイプ `A` と `NS`）の wire format の例（合計 16 バイト）:

```
07 65 78 61 6d 70 6c 65 03 6f 72 67 00   ;; Next Domain Name = example.org. (13 バイト)
00                                       ;; type bitmap window 0
01                                       ;; bitmap length 1
60                                       ;; bitmap: TYPE_A(1) + TYPE_NS(2)
```

```go
wire := []byte{
    0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
    0x03, 'o', 'r', 'g', 0x00,
    0x00, 0x01, 0x60,
}
rr, end, err := dnsmsg.ParseResourceRecord(wire, 0)
// err == nil, end == 16
// rr.Type == TYPE_NSEC, rr.Class == CLASS_IN (想定)
fmt.Println(rr.String()) // "example.org. 1 32 <TTL> example.org. A NS" 形式

rdata := rr.RData.(dnsmsg.RecordNSEC)
fmt.Println(rdata.String()) // "example.org. A NS"
```

`rr.String()` のフォーマットは `<name> <class> <type> <ttl> <rdata-string>` です（`ResourceRecord.String()` のフォーマット。RDATA 部分は `RecordNSEC.String()` の表示形式）。

## シリアライゼーション

```go
var w dnsmsg.WireFormat
db := dnsmsg.NewNameCompressionDB()
nsec := dnsmsg.NewRecordNSEC(
    dnsmsg.NewDomainNameFromString("example.org") // エラーチェック省略
    []dnsmsg.ResourceType{dnsmsg.TYPE_A, dnsmsg.TYPE_NS},
)
n := nsec.AppendWireFormat(&w, db)
// n == 16、w は上記 round-trip 例と同じ 16 バイト
```

`AppendWireFormat` は Next Domain Name を `w.AppendDomainName(nextDomainName, db)` で付加し、`db` が nil でなければ同じメッセージ内で先に出た共通接尾辞は圧縮ポインタ（`0xc000 | offset`）に置換されます。Type Bit Maps は圧縮の対象外で常に非圧縮で書き出されます。

`AppendCanonicalWireFormat` は RFC 4034 の canonical wire format（小文字・非圧縮・末尾ゼロ 1 オクテット）を書き出します。

## JSON マーシャリング

`RecordNSEC` は `MarshalJSON` / `UnmarshalJSON` を持ちます。Next Domain Name は表示形式文字列、Types はリソースタイプ名の配列（例: `["A", "NS"]`）としてエンコードされます。デコード時はタイプ名または数値コードのいずれも受理します。

## 補足

- `RecordNSEC` の `RDATA` インターフェースの実装は `Type()` / `String()` / `CanonicalWireFormat()` / `AppendWireFormat()` / `AppendCanonicalWireFormat()` です。
- テストは `record-nsec_test.go` のテーブル駆動テスト（`TestParseRecordNSEC` / `TestNewRecordNSECFromString` / `TestRecordNSECString` / `TestRecordNSECType` / `TestRecordNSECCanonicalWireFormat` / `TestRecordNSECRoundTrip` / `TestRecordNSECAppendWireFormat` / `TestRecordNSECFromStringRoundTrip` / `TestNewRecordNSEC` / `TestRecordNSECMarshalJSON` / `TestTypeBitmapCrossesWindowBoundary` など）でカバーされています。
- NSEC は DNSSEC（RFC 4034 / RFC 4035）の否定応答メカニズムの一環です。本パッケージでは NSEC レコード自体のパース・シリアライズを提供し、NSEC による証明ロジック（ゾーン巡回など）は提供しません。
