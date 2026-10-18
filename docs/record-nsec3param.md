# NSEC3PARAM レコード（`RecordNSEC3PARAM`）

NSEC3PARAM レコード（TYPE=51、`TYPE_NSEC3PARAM`）は、NSEC3 による署名済みゾーンで
ハッシュ化パラメータを示す DNS リソースレコードです（RFC 5155 Section 6）。

NSEC3 レコードが次ハッシュ化所有者名（Next Hashed Owner Name）を含むのに対し、
NSEC3PARAM はハッシュアルゴリズム・フラグ・反復回数・ソルトのみを持ち、
次のハッシュ化所有者名を含みません。

```
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Hash Alg. |   Flags   |     Iterations      |  Salt Length  |  Salt   |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

## レコードの構造

| 項目 | 内容 |
|------|------|
| Name | ドメイン名（`DomainName`） |
| Class | `CLASS_IN` (1) |
| Type | `TYPE_NSEC3PARAM` (51) |
| TTL | TTL（秒） |
| RDATA | Hash Algorithm(1) + Flags(1) + Iterations(2) + Salt Length(1) + Salt(n) + Type Bit Maps |

`RecordNSEC3PARAM` の中身フィールドは以下のとおりです。

| フィールド | 型 | 説明 |
|----------|-----|------|
| HashAlgorithm | `uint8` | ハッシュアルゴリズム（`HashAlgorithmSHA1` = 1） |
| Flags | `uint8` | フラグ（`FlagOptOut` = 0x01） |
| Iterations | `uint16` | ハッシュ反復回数 |
| Salt | `[]byte` | ソルト（長さ 0〜255 オクテット） |
| Types | `[]ResourceType` | 存在する RR タイプのリスト |

## 主要な API

| API | 説明 |
|-----|------|
| `NewRecordNSEC3PARAM(hashAlgorithm, flags uint8, iterations uint16, salt []byte, types []ResourceType) RecordNSEC3PARAM` | 構造体から直接構築。`types` は昇順にソートされて保持される |
| `NewRecordNSEC3PARAMFromString(s string) (RecordNSEC3PARAM, error)` | 表示形式文字列から構築。形式は `<hash-algorithm> <flags> <iterations> <salt-hex> <type> [<type> ...]` |
| `ParseRecordNSEC3PARAM(w WireFormat, begin uint32, end uint32) (RecordNSEC3PARAM, uint32, error)` | `w` の `begin` オフセットから RDATA をパース。`end` で RDLENGTH 範囲を区切る。成功時は終端オフセットを返す |
| `(RecordNSEC3PARAM).Type() ResourceType` | `TYPE_NSEC3PARAM` (51) |
| `(RecordNSEC3PARAM).String() string` | 表示形式（例: `"1 0 10 1122 A NS"`） |
| `(RecordNSEC3PARAM).CanonicalWireFormat() []byte` | RDATA の canonical wire format（小文字・非圧縮） |
| `(RecordNSEC3PARAM).AppendWireFormat(w *WireFormat, db *NameCompressionDB) uint32` | RDATA を `w` に付加。`db` は NSEC3PARAM の RDATA にはドメイン名を含まないため未使用 |
| `(RecordNSEC3PARAM).AppendCanonicalWireFormat(w *WireFormat) uint32` | canonical 形を付加 |

`RecordNSEC3PARAM` は `RDATA` インターフェースを実装します。`ParseResourceRecord` の `TYPE_NSEC3PARAM` case で `rr.RData` には `RecordNSEC3PARAM`（値）が格納されます。

## 構築と表示

```go
nsec3param, err := dnsmsg.NewRecordNSEC3PARAMFromString("1 0 10 1122 A NS")
// err == nil
fmt.Println(nsec3param.String()) // "1 0 10 1122 A NS"

// 数値タイプコードでも指定可能
nsec3param, err := dnsmsg.NewRecordNSEC3PARAMFromString("1 0 10 1122 1 2")
// err == nil
fmt.Println(nsec3param.String()) // "1 0 10 1122 A NS"
```

`NewRecordNSEC3PARAM` は渡された `types` を昇順にソートして保持します:

```go
nsec3param := dnsmsg.NewRecordNSEC3PARAM(
    dnsmsg.HashAlgorithmSHA1,
    0,
    10,
    []byte{0x11, 0x22},
    []dnsmsg.ResourceType{dnsmsg.TYPE_NS, dnsmsg.TYPE_A},
)
// nsec3param.Types == []ResourceType{TYPE_A, TYPE_NS}（ソート済み）
```

`NewRecordNSEC3PARAMFromString` のエラー一覧（実測確認済み）:

| 条件 | エラー |
|------|--------|
| フィールド数が 5 未満 | `invalid NSEC3PARAM record format "..."` |
| ハッシュアルゴリズムが非数値 | `invalid hash algorithm "..."` |
| フラグが非数値 | `invalid flags "..."` |
| 反復回数が非数値 | `invalid iterations "..."` |
| ソルトが不正な hex | `invalid salt "..."` |
| 未知のタイプ名 | `unknown resource type "FOO"`（`NewType` のエラー） |

> **注**: `strings.Fields` を使用しているため、空のソルト（長さ 0）を表示形式文字列から
> 直接指定することはできません。空ソルトが必要な場合は `NewRecordNSEC3PARAM` を直接使用してください。

## RDATA の直接パース（`ParseRecordNSEC3PARAM`）

```go
wire := []byte{
    0x01, // hash algorithm: SHA-1
    0x00, // flags
    0x00, 0x0a, // iterations: 10
    0x02, // salt length: 2
    0x11, 0x22, // salt
    0x00, 0x01, 0x60, // type bitmap: window 0, length 1, TYPE_A + TYPE_NS
}
nsec3param, end, err := dnsmsg.ParseRecordNSEC3PARAM(wire, 0, uint32(len(wire)))
// err == nil, end == 9
fmt.Println(nsec3param.String()) // "1 0 10 1122 A NS"
```

Type Bit Maps は `end`（RDLENGTH 由来のレコード終端オフセット）で区切られるため、メッセージ全体の残りではなくレコード内のみが読み込まれます（`ParseRecordDS` / `ParseRecordRRSIG` と同じ設計）。

エラー一覧（実測確認済み）:

| 条件 | エラー |
|------|--------|
| 各フィールドが不足 | `cannot parse NSEC3PARAM ...` |
| ソルトがレコード範囲を超える | `NSEC3PARAM salt extends beyond record` |
| タイプビットマップが不正 | `cannot parse NSEC3PARAM type bit maps: ...` |
| `begin` オフセットが範囲外 | `out of bound in parsing domainname` |

## タイプビットマップの仕様

NSEC3PARAM の Type Bit Maps は NSEC と同じ形式です。各ウィンドウは 3 つのフィールド（Window Block # 1 オクテット / Bitmap Length 1 オクテット / Bitmap 可変）で構成され、ビット番号付けは MSB 優先（オクテット内の bit 7 が最小タイプ）です。

詳細については [record-nsec.md](record-nsec.md) の「タイプビットマップの仕様」を参照してください。

## レコード全体の round-trip（`ParseResourceRecord`、実測確認済み）

NSEC3PARAM レコード（ハッシュアルゴリズム SHA-1、フラグ 0、反復回数 10、ソルト `1122`、タイプ `A` と `NS`）の wire format の例（合計 9 バイト）:

```
01                                       ;; Hash Algorithm: SHA-1 (1)
00                                       ;; Flags: 0
00 0a                                    ;; Iterations: 10
02                                       ;; Salt Length: 2
11 22                                    ;; Salt: 0x1122
00                                       ;; type bitmap window 0
01                                       ;; bitmap length 1
60                                       ;; bitmap: TYPE_A(bit6) + TYPE_NS(bit5)
```

```go
wire := []byte{
    0x01, 0x00, 0x00, 0x0a, 0x02, 0x11, 0x22,
    0x00, 0x01, 0x60,
}
rr, end, err := dnsmsg.ParseResourceRecord(wire, 0)
// err == nil, end == 9
// rr.Type == TYPE_NSEC3PARAM, rr.Class == CLASS_IN (想定)
fmt.Println(rr.String()) // "<name> 1 51 <TTL> 1 0 10 1122 A NS"

rdata := rr.RData.(dnsmsg.RecordNSEC3PARAM)
fmt.Println(rdata.String()) // "1 0 10 1122 A NS"
```

`rr.String()` のフォーマットは `<name> <class> <type> <ttl> <rdata-string>` です（`ResourceRecord.String()` のフォーマット。RDATA 部分は `RecordNSEC3PARAM.String()` の表示形式）。

## シリアライゼーション

```go
var w dnsmsg.WireFormat
db := dnsmsg.NewNameCompressionDB()
nsec3param := dnsmsg.NewRecordNSEC3PARAM(
    dnsmsg.HashAlgorithmSHA1,
    0,
    10,
    []byte{0x11, 0x22},
    []dnsmsg.ResourceType{dnsmsg.TYPE_A, dnsmsg.TYPE_NS},
)
n := nsec3param.AppendWireFormat(&w, db)
// n == 9、w は上記 round-trip 例と同じ 9 バイト
```

`AppendWireFormat` は NSEC3PARAM の RDATA をバイト列として書き出します。NSEC3PARAM の RDATA にはドメイン名を含まないため、`db`（`NameCompressionDB`）は未使用（nil の渡しも可能）です。

`AppendCanonicalWireFormat` は `AppendWireFormat` と同じ結果を出力します（NSEC3PARAM の RDATA に圧縮ポインタや小文字変換の対象となるドメイン名は含まれないため）。

## JSON マーシャリング

`RecordNSEC3PARAM` は `MarshalJSON` / `UnmarshalJSON` を持ちます。Salt は 16 進小文字文字列、Types はリソースタイプ名の配列（例: `["A", "NS"]`）としてエンコードされます。デコード時はタイプ名または数値コードのいずれも受理します。

## 補足

- `RecordNSEC3PARAM` の `RDATA` インターフェースの実装は `Type()` / `String()` / `CanonicalWireFormat()` / `AppendWireFormat()` / `AppendCanonicalWireFormat()` です。
- テストは `record-nsec3param_test.go` のテーブル駆動テスト（`TestParseRecordNSEC3PARAM` / `TestNewRecordNSEC3PARAMFromString` / `TestRecordNSEC3PARAMString` / `TestRecordNSEC3PARAMType` / `TestRecordNSEC3PARAMCanonicalWireFormat` / `TestRecordNSEC3PARAMRoundTrip` / `TestRecordNSEC3PARAMAppendWireFormat` / `TestRecordNSEC3PARAMFromStringRoundTrip` / `TestNewRecordNSEC3PARAM` / `TestRecordNSEC3PARAMMarshalJSON` など）でカバーされています。
- NSEC3PARAM は DNSSEC（RFC 5155）の否定応答メカニズムの一環です。本パッケージでは NSEC3PARAM レコード自体のパース・シリアライズを提供し、NSEC3 による証明ロジック（ハッシュ計算・ゾーン巡回など）は提供しません。
- ハッシュアルゴリズムは RFC 5155 で SHA-1（`HashAlgorithmSHA1` = 1）のみが定義されています。他のアルゴリズムは数値コードとして扱われます。
