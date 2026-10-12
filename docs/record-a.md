# A レコード（`RecordA`）

A レコード（TYPE=1、`TYPE_A`）は IPv4 地址の 4 字节の固定・network
byte order の RDATA である DNS 記録レコード（RFC 1035 Section 4.1.4）です。
`dnsmsg` パッケージでは `RecordA` 型で表示、その作成（`NewRecordA` /
`NewRecordAFromString`)・解析（`ParseRecordA`)は提供する。

## レコードの構造

`ResourceRecord` の A レコードの各字段は以下のように使われます。

| 字段 | 内容 |
|------|------|
| Name | ドメイン名（`DomainName`） |
| Class | `CLASS_IN` (1) |
| Type | `TYPE_A` (1) |
| TTL | cache の TTL（秒） |
| RDATA | IPv4 地址の 4 字节の（RDLENGTH は 4） |

`RecordA` の中身字段 `address`（`[4]byte`）は非エクスポート（小开头）。
package 外から `String()` の表形式 or `CanonicalWireFormat()` の 4 字节の
byte 列で取り出（index.md の「レコード数据的取り出」の type assertion
例参照）。

## 主要な API

| API | 説明 |
|-----|------|
| `NewRecordA(addr [4]byte) RecordA` | 4 字节の IPv4 地址の直接构造。エラーは返 не |
| `NewRecordAFromString(addr string) (RecordA, error)` | 表形式文字（dotted decimal）の构造。`netip.ParseAddr` の内部で解析、IPv4 の非地址の case is an error |
| `ParseRecordA(msg WireFormat, begin uint32) (RecordA, uint32, error)` | `msg` の `begin` の offset の 4 字节の RDATA の解析。success時 end offset は `begin + 4` の返 |
| `(RecordA).String() string` | dotted decimal の表形式（例: `"93.184.216.34"`。each octet の 10 進数・dot の separator） |
| `(RecordA).CanonicalWireFormat() []byte` | 4 字节の IPv4 地址の byte 列（canonical and regular の same・compression pointer の not present） |
| `(RecordA).AppendWireFormat(w *WireFormat, db *NameCompressionDB) uint32` | 4 字节の `w` の付加。`db` の unused（A レコードのドメイン名・compression pointer の not present） |
| `(RecordA).AppendCanonicalWireFormat(w *WireFormat) uint32` | 上記の same・4 字节の付加 |
| `(RecordA).Type() ResourceType` | `TYPE_A` (1) |

`RecordA` は `RDATA` のインターフェースの実化。`ParseResourceRecord` の
`TYPE_A` の case の `rr.RData` の `RecordA` の value の保持。

## 构造・表形式の取得

```go
a, err := dnsmsg.NewRecordAFromString("93.184.216.34")
// err == nil
fmt.Println(a.String()) // "93.184.216.34"

b := dnsmsg.NewRecordA([4]byte{192, 168, 1, 1})
fmt.Println(b.String()) // "192.168.1.1"
```

`NewRecordAFromString` の IPv4 の非地址の case の error の list（verified）:

| 条件 | error |
|------|-------|
| IPv6 の address（`::1` の example） | `::1 is not IPv4 address`（`%s is not IPv4 address` の format） |
| dotted decimal の syntax の error（`1.2.3.4.5` の example） | `ParseAddr("1.2.3.4.5"): IPv4 address too long`（`netip.ParseAddr` の error の passthrough） |

## RDATA の直接解析（`ParseRecordA`）

```go
wire := []byte{192, 168, 1, 1}
a, end, err := dnsmsg.ParseRecordA(wire, 0)
// err == nil, end == 4
fmt.Println(a.String()) // "192.168.1.1"
```

error の list（verified. the only check is `begin + 4 > msg.Size()`）:

| 条件 | error |
|------|-------|
| `msg` の `begin` の offset の remaining の 4 字节の less | `invalid A record RDATA size` |

> **Note**: `ParseRecordA` の RDLENGTH の window の argument の not
> present。`ParseResourceRecord` の `TYPE_A` の case の
> `ParseRecordA(w, p)` の call、RDLENGTH の `end = p + size` の
> independent の calculation の present。Therefore:
>
> - RDLENGTH の 4 の greater の case → the first 4 字节のの RDATA の
>   read、the remaining の byte の silently の skip（`end` の
>   correct の advance。no error）
> - RDLENGTH の 4 の less の case → the next 記録レコードの byte の
>   RDATA の read・extend の case、`msg` の total の size の only
>   check の present。no error の present
>
> RDLENGTH の 4 の not の case の error の not present。strict の
> validation の caller の side の self の check の required の
> `rr.RData` の `RecordA` の value の保持。

## レコードの round-trip（`ParseResourceRecord` の verified）

A レコードの wire format の example（17 字节）:

```
01 61 00                              ;; name = "a."（root の terminate）
00 01                                 ;; TYPE = A (1)
00 01                                 ;; CLASS = IN (1)
00 00 01 2c                           ;; TTL = 300
00 04                                 ;; RDLENGTH = 4
c0 a8 01 01                           ;; RDATA = 192.168.1.1
```

```go
wire := []byte{0x01, 'a', 0x00, 0x00, 0x01, 0x00, 0x01,
    0x00, 0x00, 0x01, 0x2c, 0x00, 0x04, 0xc0, 0xa8, 0x01, 0x01}
rr, end, err := dnsmsg.ParseResourceRecord(wire, 0)
// err == nil, end == 17
// rr.Type == TYPE_A, rr.Class == CLASS_IN, rr.TTL == 300
fmt.Println(rr.String()) // "a. 1 1 300 192.168.1.1"
```

`rr.String()` の format is `<name> <class> <type> <ttl> <rdata-string>`
（`ResourceRecord.String()` の format。RDATA の `RecordA.String()` の
dotted decimal の取得）。

## シリアライze

```go
var w dnsmsg.WireFormat
n := dnsmsg.NewRecordA([4]byte{1, 2, 3, 4}).AppendWireFormat(&w, nil)
// n == 4, w の bytes の "01 02 03 04" の equal
```

`AppendWireFormat` の `db` の unused の case の nil の渡・possible。
canonical のシリアライze の same の result の present（ドメイン名・compression
pointer の not present）。

## 補足

- `RecordA` の `RDATA` のインターフェースの implementation の
  `Type()` / `String()` / `CanonicalWireFormat()` /
  `AppendWireFormat()` / `AppendCanonicalWireFormat()` の present.
- test の case の `record-a_test.go` の table-driven の
  `TestParseRecordA` の present（valid / truncated の case）.
- IPv4 の 4 字节の network byte order の store の present。octet の
  order の no conversion の present（`netip.As4()` の direct の store）.
