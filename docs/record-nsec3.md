# NSEC3 レコード（`RecordNSEC3`）

NSEC3 レコード（TYPE=50、`TYPE_NSEC3`）は、ゾーン内に存在しないドメイン名の証明（DNSSEC の否定応答）に使われる NSEC の後継レコードです（RFC 5155 Section 3.2）。

NSEC がクリアテキストのドメイン名を Next Domain Name に含むのに対し、NSEC3 はハッシュ化された所有者名を使用し、ゾーン列挙（zone walking）を困難にします。

```
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Hash Alg. |   Flags   |     Iterations      |  Salt Length  |  Salt   /
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/      Hash Length    /   Next Hashed Owner Name  /    Type Bit Maps    /
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

## レコードの構造

| 項目 | 内容 |
|------|------|
| Name | ドメイン名（`DomainName`） |
| Class | `CLASS_IN` (1) |
| Type | `TYPE_NSEC3` (50) |
| TTL | TTL（秒） |
| RDATA | Hash Algorithm(1) + Flags(1) + Iterations(2) + Salt Length(1) + Salt(n) + Hash Length(1) + Next Hashed Owner Name(label length + name) + Type Bit Maps |

`RecordNSEC3` の中身フィールドは以下のとおりです。

| フィールド | 型 | 説明 |
|----------|-----|------|
| HashAlgorithm | `uint8` | ハッシュアルゴリズム（`HashAlgorithmSHA1` = 1） |
| Flags | `uint8` | フラグ（`FlagOptOut` = 0x01） |
| Iterations | `uint16` | ハッシュ反復回数 |
| Salt | `[]byte` | ソルト（長さ 0〜255 オクテット） |
| NextHashedName | `[]byte` | 次のハッシュ化所有者名（ラベル長オクテット付き） |
| Types | `[]ResourceType` | 存在する RR タイプのリスト |

## 主要な API

| API | 説明 |
|-----|------|
| `NewRecordNSEC3(hashAlgorithm, flags uint8, iterations uint16, salt, nextHashedName []byte, types []ResourceType) RecordNSEC3` | 構造体から直接構築。`types` は昇順にソートされて保持される |
| `NewRecordNSEC3FromString(s string) (RecordNSEC3, error)` | 表示形式文字列から構築。形式は `<hash-algorithm> <flags> <iterations> <salt-hex> <next-hashed-hex> <type> [<type> ...]` |
| `ParseRecordNSEC3(w WireFormat, begin uint32, end uint32) (RecordNSEC3, uint32, error)` | `w` の `begin` オフセットから RDATA をパース。`end` で RDLENGTH 範囲を区切る。成功時は終端オフセットを返す |
| `(RecordNSEC3).Type() ResourceType` | `TYPE_NSEC3` (50) |
| `(RecordNSEC3).String() string` | 表示形式（例: `"1 0 10 1122 334455 A NS"`） |
| `(RecordNSEC3).CanonicalWireFormat() []byte` | RDATA の canonical wire format（小文字・非圧縮） |
| `(RecordNSEC3).AppendWireFormat(w *WireFormat, db *NameCompressionDB) uint32` | RDATA を `w` に付加。`db` は NSEC3 の RDATA にはドメイン名を含まないため未使用 |
| `(RecordNSEC3).AppendCanonicalWireFormat(w *WireFormat) uint32` | canonical 形を付加 |

`RecordNSEC3` は `RDATA` インターフェースを実装します。`ParseResourceRecord` の `TYPE_NSEC3` case で `rr.RData` には `RecordNSEC3`（値）が格納されます。

## 構築と表示

```go
nsec3, err := dnsmsg.NewRecordNSEC3FromString("1 0 10 1122 334455 A NS")
// err == nil
fmt.Println(nsec3.String()) // "1 0 10 1122 334455 A NS"

// 数値タイプコードでも指定可能
nsec3, err := dnsmsg.NewRecordNSEC3FromString("1 0 10 1122 334455 1 2")
// err == nil
fmt.Println(nsec3.String()) // "1 0 10 1122 334455 A NS"
```

`NewRecordNSEC3` は渡された `types` を昇順にソートして保持します:

```go
nsec3 := dnsmsg.NewRecordNSEC3(
    dnsmsg.HashAlgorithmSHA1,
    0,
    10,
    []byte{0x11, 0x22},
    []byte{0x33, 0x44, 0x55},
    []dnsmsg.ResourceType{dnsmsg.TYPE_NS, dnsmsg.TYPE_A},
)
// nsec3.Types == []ResourceType{TYPE_A, TYPE_NS}（ソート済み）
```

`NewRecordNSEC3FromString` のエラー一覧（実測確認済み）:

| 条件 | エラー |
|------|--------|
| フィールド数が 6 未満 | `invalid NSEC3 record format "..."` |
| ハッシュアルゴリズムが非数値 | `invalid hash algorithm "..."` |
| フラグが非数値 | `invalid flags "..."` |
| 反復回数が非数値 | `invalid iterations "..."` |
| ソルトが不正な hex | `invalid salt "..."` |
| 次のハッシュ化所有者名が不正な hex | `invalid next hashed name "..."` |
| 未知のタイプ名 | `unknown resource type "FOO"`（`NewType` のエラー） |

## RDATA の直接パース（`ParseRecordNSEC3`）

```go
wire := []byte{
    0x01, // hash algorithm: SHA-1
    0x00, // flags
    0x00, 0x0a, // iterations: 10
    0x02, // salt length: 2
    0x11, 0x22, // salt
    0x03, // hash length: 3
    0x03, 0x33, 0x44, 0x55, // label length 3 + hashed name
    0x00, 0x01, 0x60, // type bitmap: window 0, length 1, TYPE_A + TYPE_NS
}
nsec3, end, err := dnsmsg.ParseRecordNSEC3(wire, 0, uint32(len(wire)))
// err == nil, end == 15
fmt.Println(nsec3.String()) // "1 0 10 1122 334455 A NS"
```

Type Bit Maps は `end`（RDLENGTH 由来のレコード終端オフセット）で区切られるため、メッセージ全体の残りではなくレコード内のみが読み込まれます（`ParseRecordDS` / `ParseRecordRRSIG` と同じ設計）。

エラー一覧（実測確認済み）:

| 条件 | エラー |
|------|--------|
| 各フィールドが不足 | `cannot parse NSEC3 ...` |
| ソルトがレコード範囲を超える | `NSEC3 salt extends beyond record` |
| 次のハッシュ化所有者名がレコード範囲を超える | `NSEC3 next hashed owner name extends beyond record` |
| ラベル長が Hash Length と不一致 | `NSEC3 next hashed owner name label length X does not match hash length Y` |
| タイプビットマップが不正 | `cannot parse NSEC3 type bit maps: ...` |
| `begin` オフセットが範囲外 | `out of bound in parsing domainname` |

## タイプビットマップの仕様

NSEC3 の Type Bit Maps は NSEC と同じ形式です。各ウィンドウは 3 つのフィールド（Window Block # 1 オクテット / Bitmap Length 1 オクテット / Bitmap 可変）で構成され、ビット番号付けは MSB 優先（オクテット内の bit 7 が最小タイプ）です。

詳細については [record-nsec.md](record-nsec.md) の「タイプビットマップの仕様」を参照してください。

## レコード全体の round-trip（`ParseResourceRecord`、実測確認済み）

NSEC3 レコード（ハッシュアルゴリズム SHA-1、フラグ 0、反復回数 10、ソルト `1122`、次のハッシュ化所有者名 `334455`、タイプ `A` と `NS`）の wire format の例（合計 15 バイト）:

```
01                                       ;; Hash Algorithm: SHA-1 (1)
00                                       ;; Flags: 0
00 0a                                    ;; Iterations: 10
02                                       ;; Salt Length: 2
11 22                                    ;; Salt: 0x1122
03                                       ;; Hash Length: 3
03 33 44 55                              ;; Next Hashed Owner Name: label length 3 + 3 bytes
00                                       ;; type bitmap window 0
01                                       ;; bitmap length 1
60                                       ;; bitmap: TYPE_A(bit6) + TYPE_NS(bit5)
```

```go
wire := []byte{
    0x01, 0x00, 0x00, 0x0a, 0x02, 0x11, 0x22,
    0x03, 0x03, 0x33, 0x44, 0x55,
    0x00, 0x01, 0x60,
}
rr, end, err := dnsmsg.ParseResourceRecord(wire, 0)
// err == nil, end == 15
// rr.Type == TYPE_NSEC3, rr.Class == CLASS_IN (想定)
fmt.Println(rr.String()) // "<name> 1 50 <TTL> 1 0 10 1122 334455 A NS"

rdata := rr.RData.(dnsmsg.RecordNSEC3)
fmt.Println(rdata.String()) // "1 0 10 1122 334455 A NS"
```

`rr.String()` のフォーマットは `<name> <class> <type> <ttl> <rdata-string>` です（`ResourceRecord.String()` のフォーマット。RDATA 部分は `RecordNSEC3.String()` の表示形式）。

## シリアライゼーション

```go
var w dnsmsg.WireFormat
db := dnsmsg.NewNameCompressionDB()
nsec3 := dnsmsg.NewRecordNSEC3(
    dnsmsg.HashAlgorithmSHA1,
    0,
    10,
    []byte{0x11, 0x22},
    []byte{0x33, 0x44, 0x55},
    []dnsmsg.ResourceType{dnsmsg.TYPE_A, dnsmsg.TYPE_NS},
)
n := nsec3.AppendWireFormat(&w, db)
// n == 15、w は上記 round-trip 例と同じ 15 バイト
```

`AppendWireFormat` は NSEC3 の RDATA をバイト列として書き出します。NSEC3 の RDATA にはドメイン名を含まないため、`db`（`NameCompressionDB`）は未使用（nil の渡しも可能）です。

`AppendCanonicalWireFormat` は `AppendWireFormat` と同じ結果を出力します（NSEC3 の RDATA に圧縮ポインタや小文字変換の対象となるドメイン名は含まれないため）。

## JSON マーシャリング

`RecordNSEC3` は `MarshalJSON` / `UnmarshalJSON` を持ちます。Salt と Next Hashed Name は 16 進小文字文字列、Types はリソースタイプ名の配列（例: `["A", "NS"]`）としてエンコードされます。デコード時はタイプ名または数値コードのいずれも受理します。

## 補足

- `RecordNSEC3` の `RDATA` インターフェースの実装は `Type()` / `String()` / `CanonicalWireFormat()` / `AppendWireFormat()` / `AppendCanonicalWireFormat()` です。
- テストは `record-nsec3_test.go` のテーブル駆動テスト（`TestParseRecordNSEC3` / `TestNewRecordNSEC3FromString` / `TestRecordNSEC3String` / `TestRecordNSEC3Type` / `TestRecordNSEC3CanonicalWireFormat` / `TestRecordNSEC3RoundTrip` / `TestRecordNSEC3AppendWireFormat` / `TestRecordNSEC3FromStringRoundTrip` / `TestNewRecordNSEC3` / `TestRecordNSEC3MarshalJSON` / `TestNSEC3FlagOptOut` / `TestNSEC3HashAlgorithmSHA1` など）でカバーされています。
- NSEC3 は DNSSEC（RFC 5155）の否定応答メカニズムの一環です。本パッケージでは NSEC3 レコード自体のパース・シリアライズを提供し、NSEC3 による証明ロジック（ハッシュ計算・ゾーン巡回など）は提供しません。
- ハッシュアルゴリズムは RFC 5155 で SHA-1（`HashAlgorithmSHA1` = 1）のみが定義されています。他のアルゴリズムは数値コードとして扱われます。
