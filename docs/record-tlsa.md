# TLSA レコード（`RecordTLSA`）

TLSA レコード（TYPE=52、`TYPE_TLSA`）は、サービスのドメイン名とそのサービスの
TLS 証明書（または証明書の公開鍵）を結びつける DNS リソースレコードです（RFC 6698）。
DANE（DNS-Based Authentication of Named Entities）の一部として、クライアントは
接続先に期待する証明書を DNS から知ることができます。

```
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Cert. Usage |   Selector    | Matching Type |               /
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/        Certificate Association Data（可変長、1 オクテット以上）/
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

レコードの名前は `_443._tcp.example.com.` のようなサービス名です（RFC 7671
Section 3.1）。RDATA は、証明書の使い方と認証データの作り方を示す 3 つの
1 オクテットフィールドと、 certificate association data（証明書または公開鍵の
ハッシュ、または証明書そのもの）です。

このライブラリはレコードの読み書きのみを担当し、認証データの計算や、
認証データが matching type の示す長さのハッシュかどうかの検査は行いません。
未割り当ての matching type を使う送信者にも、受信者はそのレコードを読める必要が
あるためです（RFC 6698 Section 2.1.3、Section 10）。

## レコードの構造

| 項目 | 内容 |
|------|------|
| Name | サービス名（例: `_443._tcp.example.com.`）。TLSA は DNS のクラスによらないレコードですが（RFC 6698 Section 6.1）、zone にはふつう `CLASS_IN` (1) で登録されます |
| Class | `CLASS_IN` (1)。他のクラスでもそのまま読み書きできる |
| Type | `TYPE_TLSA` (52) |
| TTL | TTL（秒）。TLSA に固有の意味はない |
| RDATA | Certificate Usage(1) + Selector(1) + Matching Type(1) + Certificate Association Data(n)、RDLENGTH は 4〜65535 |

`RecordTLSA` のフィールド:

| フィールド | 型 | 内容 |
|----------|----|------|
| `CertificateUsage` | `uint8` | 証明書の使い方（後述の定数） |
| `Selector` | `uint8` | 証明書のどの部分から認証データを作ったか |
| `MatchingType` | `uint8` | 認証データの作り方（ハッシュの有無とアルゴリズム） |
| `Data` | `[]byte` | certificate association data（1〜65532 オクテット） |

### Certificate usage（RFC 6698 Section 2.1.1 / Section 7.2）

| 定数 | 値 | IANA 登録名（RFC 7671 の略称） |
|------|----|-------------------------------|
| `TLSACertUsageCA` | 0 | PKIX-TA（CA constraint） |
| `TLSACertUsageServiceConstraint` | 1 | PKIX-EE（service certificate constraint） |
| `TLSACertUsageTrustAnchorAssertion` | 2 | DANE-TA（trust anchor assertion） |
| `TLSACertUsageDomainIssued` | 3 | DANE-EE（domain-issued certificate） |
| `TLSACertUsagePrivate` | 255 | 私用（private use） |

4〜254 は未割り当てで、そのまま保持・表示できます。

### Selector（RFC 6698 Section 2.1.2 / Section 7.3）

| 定数 | 値 | 内容 |
|------|----|------|
| `TLSASelectorFullCertificate` | 0 | 証明書全体 |
| `TLSASelectorSPKI` | 1 | 証明書の SubjectPublicKeyInfo（公開鍵） |
| `TLSASelectorPrivate` | 255 | 私用 |

2〜254 は未割り当てです。

### Matching type（RFC 6698 Section 2.1.3 / Section 7.4）

| 定数 | 値 | 認証データ |
|------|----|-----------|
| `TLSAMatchingNoHash` | 0 | selector が選んだものそのもの（ハッシュなし） |
| `TLSAMatchingSHA256` | 1 | SHA-256 でハッシュした値（32 オクテット） |
| `TLSAMatchingSHA512` | 2 | SHA-512 でハッシュした値（64 オクテット） |
| `TLSAMatchingPrivate` | 255 | 私用 |

3〜254 は未割り当てです。未割り当ての matching type のレコードも、その長さが
そのまま読み書きされます。

## 主要な API

| API | 説明 |
|-----|------|
| `NewRecordTLSA(certUsage, selector, matchingType uint8, data []byte) (RecordTLSA, error)` | フィールドから直接構築。`data` が空、または 65532 オクテットを超えるとお error |
| `NewRecordTLSAFromHex(certUsage, selector, matchingType uint8, hexData string) (RecordTLSA, error)` | 認証データを 16 進文字列から構築（大文字・小文字どちらも受理） |
| `NewRecordTLSAFromString(s string) (RecordTLSA, error)` | 表示形式文字列から構築（後述） |
| `ParseRecordTLSA(w WireFormat, begin, end uint32) (RecordTLSA, uint32, error)` | `w` の `begin` から `end`（RDLENGTH 由来のレコード終端）までの RDATA をパース。成功時は終端オフセットを返す |
| `(RecordTLSA).Type() ResourceType` | `TYPE_TLSA` (52) |
| `(RecordTLSA).String() string` | 表示形式（後述） |
| `(RecordTLSA).CanonicalWireFormat() []byte` | RDATA のバイト列（TLSA はドメイン名を含まないので RDATA と同じ） |
| `(RecordTLSA).AppendWireFormat(w *WireFormat, db *NameCompressionDB) uint32` | RDATA を `w` に付加。`db` は未使用 |
| `(RecordTLSA).AppendCanonicalWireFormat(w *WireFormat) uint32` | canonical 形を付加（`AppendWireFormat` と同じ） |

`RecordTLSA` は `RDATA` インターフェースを実装します。`ParseResourceRecord` の
`TYPE_TLSA` case で `rr.RData` には `RecordTLSA`（値）が格納されます。
`TYPE_TLSA.String()` は `"TLSA"`、`NewType("TLSA")` は `TYPE_TLSA` (52) を返します。

## 構築と表示

表示形式は RFC 6698 Section 3 の master file 表現と同じで、3 つの
1 オクテットフィールドを 10 進数、認証データを 16 進文字列として空白で区切ります。

```
<certificate-usage> <selector> <matching-type> <association-data>
```

```go
tlsa, err := dnsmsg.NewRecordTLSAFromString(
    "3 1 1 d2abde240d7cd3ee6b4b28c54df034b97983a1d16e8a410e4561cb106618e971")
// err == nil
fmt.Println(tlsa.String())
// "3 1 1 d2abde240d7cd3ee6b4b28c54df034b97983a1d16e8a410e4561cb106618e971"
fmt.Println(tlsa.CertificateUsage == dnsmsg.TLSACertUsageDomainIssued) // true
```

`String()` の 16 進文字列は必ず小文字です。master file は 255 文字を超える
文字列を行末で分割するため（RFC 1035 Section 5.1、RFC 6698 Section 3 の例の
`( ... )` 表記）、`NewRecordTLSAFromString` は空白で分割された 16 進文字列を
連結して読みます。

```go
// RFC 6698 Section 3 の SHA-512 の例を、master file の表記のまま読む
tlsa, err := dnsmsg.NewRecordTLSAFromString("1 1 2 92003ba34942dc74152e2f2c408d29ec\n" +
    "      a5a520e7f2e06bb944f4dca346baf63c\n" +
    "      1b177615d466f6c4b71c216a50292bd5\n" +
    "      8c9ebdd2f74e38fe51ffd48c43326cbc")
// err == nil、tlsa.Data は 64 オクテット
fmt.Println(tlsa.String()) // 16 進文字列が 1 続きになった表示
```

16 進文字列は大文字でも読めます（`String()` は小文字で出す）。
フィールドの値が 0〜255 の範囲にない数は読めません。

`NewRecordTLSAFromString` のエラー一覧（実測確認済み）:

| 条件 | エラー |
|------|--------|
| フィールド数が 4 未満 | `invalid TLSA record: expected a certificate usage, a selector, a matching type and a certificate association data, got 3 field(s)` |
| usage・selector・matching type が 10 進数ではない、4 桁以上、または 256 以上 | `invalid TLSA record: invalid certificate usage "256"`（各フィールドの名前が入る） |
| 16 進文字列が空 | `invalid TLSA record: empty certificate association data` |
| 16 進文字列の長さが奇数、または 16 進でない文字を含む | `invalid TLSA record: invalid certificate association data "abc"` |
| 認証データが 65532 オクテットを超える | `TLSA certificate association data of 65533 octets does not fit in an RDATA` |

## RDATA の直接パース（`ParseRecordTLSA`）

```go
rdata := []byte{
    0x03, 0x01, 0x01, // usage 3（DANE-EE）、selector 1（SPKI）、matching type 1（SHA-256）
    0xd2, 0xab, 0xde, 0x24, 0x0d, 0x7c, 0xd3, 0xee, 0x6b, 0x4b, 0x28, 0xc5,
    0x4d, 0xf0, 0x34, 0xb9, 0x79, 0x83, 0xa1, 0xd1, 0x6e, 0x8a, 0x41, 0x0e,
    0x45, 0x61, 0xcb, 0x10, 0x66, 0x18, 0xe9, 0x71,
}
tlsa, end, err := dnsmsg.ParseRecordTLSA(rdata, 0, uint32(len(rdata)))
// err == nil, end == 35
```

認証データ自身は長さをまったくもたないため、その範囲は `end`（ enclosing RR の
RDLENGTH 由来の終端オフセット）で区切ります。メッセージ全体の残りではありません
（`ParseRecordDS` / `ParseRecordNSEC3PARAM` と同じ設計）。`end` より後ろの
オクテットは読まれません。認証データはコピーされるため、もとのメッセージを
変更してもレコードは変わりません。

`ParseRecordTLSA` により作られる `RecordTLSA` は、RFC 6698 が検査する値の範囲を
通りません。最短の RDATA は 4 オクテット（3 つのフィールド + 1 オクテットの
認証データ）です。

エラー一覧（実測確認済み）:

| 条件 | エラー |
|------|--------|
| `end` がメッセージの末尾を超える | `invalid TLSA record RDATA size` |
| RDATA が 4 オクテットに満たない | `not enough size for TLSA record` |

## レコード全体の round-trip（`ParseResourceRecord`、実測確認済み）

`_443._tcp.example.com.` の TLSA（usage 3、selector 1、matching type 1、
SHA-256）の wire format の例（合計 68 バイト、名前は非圧縮）:

```
04 5f 34 34 33                   ;; "_443"
04 5f 74 63 70                   ;; "_tcp"
07 65 78 61 6d 70 6c 65          ;; "example"
03 63 6f 6d 00                   ;; "com"、名終端
00 34                            ;; TYPE = TLSA (52)
00 01                            ;; CLASS = IN (1)
00 00 0e 10                      ;; TTL = 3600
00 23                            ;; RDLENGTH = 35
03 01 01                         ;; usage 3、selector 1、matching type 1
d2 ab de 24 0d 7c d3 ee 6b 4b 28 c5 4d f0 34 b9
79 83 a1 d1 6e 8a 41 0e 45 61 cb 10 66 18 e9 71  ;; 認証データ 32 オクテット
```

```go
rr, end, err := dnsmsg.ParseResourceRecord(wire, 0)
// err == nil, end == 68
// rr.Type == TYPE_TLSA (52)、rr.Class == CLASS_IN、rr.TTL == 3600

tlsa := rr.RData.(dnsmsg.RecordTLSA)
fmt.Println(tlsa.String())
// "3 1 1 d2abde240d7cd3ee6b4b28c54df034b97983a1d16e8a410e4561cb106618e971"
fmt.Println(len(tlsa.Data)) // 32
```

`rr.String()` は `<name> <class> <type> <ttl> <rdata-string>` の形式です
（`_443._tcp.example.com. 1 52 3600 3 1 1 d2abde...`）。

## シリアライゼーション

```go
tlsa, _ := dnsmsg.NewRecordTLSA(dnsmsg.TLSACertUsageDomainIssued,
    dnsmsg.TLSASelectorSPKI, dnsmsg.TLSAMatchingSHA256, data) // data は 32 オクテット
var w dnsmsg.WireFormat
n := tlsa.AppendWireFormat(&w, nil)
// n == 35、w は 03 01 01 に data の 32 オクテットが続く RDATA
```

`AppendWireFormat` は usage・selector・matching type を 1 オクテットずつ、
その次に認証データを書き出します。TLSA の RDATA はドメイン名を含まないため
`db`（`NameCompressionDB`）は未使用で、nil を渡すこともできます。

`AppendCanonicalWireFormat` / `CanonicalWireFormat` は `AppendWireFormat` と
同じバイト列を出力します（RFC 4034 の canonical wire format において、
ドメイン名をもたないレコードの canonical 形は RDATA そのもののため）。

## JSON マーシャリング

`RecordTLSA` は `MarshalJSON` / `UnmarshalJSON` を持ちます。3 つのフィールドは
数値、認証データは 16 進小文字文字列としてエンコードされます（実測確認済み）:

```go
json.Marshal(tlsa)
// {"CertificateUsage":3,"Data":"d2abde240d7cd3ee6b4b28c54df034b97983a1d16e8a410e4561cb106618e971",
//  "MatchingType":1,"Selector":1}
```

| JSON フィールド | 内容 |
|----------------|------|
| `CertificateUsage` | 0〜255 の数値。10 進数の文字列（`"3"`）でも読める |
| `Selector` | 0〜255 の数値。同上 |
| `MatchingType` | 0〜255 の数値。同上 |
| `Data` | 認証データの 16 進文字列（偶数長、空文字列はエラー） |

`ResourceRecord.UnmarshalJSON` は `Type` が `"TLSA"`（または 52）のとき `RData` を
`RecordTLSA` としてデコードします（JSON 経由の RDATA は `*RecordTLSA` のポインタで、
wire format 経由の `RecordTLSA` は値になります）。フィールドが欠けている、または
値が範囲外の場合はエラーです（`invalid TLSA record: missing selector`、
`invalid TLSA record: invalid certificate usage`）。

## 補足

- 認証データの長さは matching type が示すハッシュの長さと一致する必要が
 ありますが、このライブラリはその一致を検査しません（matching type 1 なら 32
  オクテット、matching type 2 なら 64 オクテット、matching type 0 は
  証明書そのもの）。
- TLSA の名前の作り方は RFC 7671 Section 3.1 です。`dq` で TLSA を
  問い合わせることもできます（`dq -r -t TLSA _443._tcp.example.com.`、
  [dq.md](dq.md) 参照）。
- TLSA は DNSSEC の署名対象にもなります（RFC 6698 Section 7）。RRSet の署名と
  検証は [rrset.md](rrset.md) を参照してください。
- テストは `record-tlsa_test.go` のテーブル駆動テスト
  （`TestParseRecordTLSA` / `TestParseRecordTLSACopiesTheAssociationData` /
  `TestNewRecordTLSA` / `TestNewRecordTLSAFromHex` / `TestNewRecordTLSAFromString` /
  `TestNewRecordTLSAFromStringErrors` / `TestRecordTLSAString` /
  `TestRecordTLSAType` / `TestRecordTLSAWireFormatRoundTrip` /
  `TestParseResourceRecordTLSA` / `TestResourceRecordTLSAWireFormatRoundTrip` /
  `TestRecordTLSAJSON` / `TestRecordTLSAUnmarshalJSONFieldStrings` /
  `TestRecordTLSAUnmarshalJSONErrors`）でカバーされています。テストの値は
  RFC 6698 Section 2.3 と Section 3 の例を使っています。
