# AAAA レコード（`RecordAAAA`）

AAAA レコード（TYPE=28、`TYPE_AAAA`）は IPv6 アドレス（RFC 4038）を
RDATA に持つ DNS リソースレコードです。RDATA はネットワークバイトオーダーの
固定 16 バイト（RDLENGTH は常に 16）です。

## レコードの構造

| 項目 | 内容 |
|------|------|
| Name | ドメイン名（`DomainName`） |
| Class | `CLASS_IN` (1) |
| Type | `TYPE_AAAA` (28) |
| TTL | TTL（秒） |
| RDATA | IPv6 アドレスの 16 バイト（RDLENGTH=16） |

`RecordAAAA` の内部フィールド `address`（`[16]byte`）は非エクスポートです。
パッケージの外からは `String()`（表示形式）または
`CanonicalWireFormat()`（16 バイトの byte 列）で取り出します
（index.md の「レコードデータの取り出し」の型アサーション例参照）。

## 主要な API

| API | 説明 |
|-----|------|
| `NewRecordAAAA(addr [16]byte) RecordAAAA` | 16 バイトの IPv6 アドレスから直接構築。エラーは返さない |
| `NewRecordAAAAFromString(addr string) (RecordAAAA, error)` | 表示形式文字列（IPv6 notation）から構築。`netip.ParseAddr` でパースし、IPv4 アドレスの場合はエラー |
| `ParseRecordAAAA(msg WireFormat, begin uint32) (RecordAAAA, uint32, error)` | `msg` の `begin` オフセットの 16 バイトを RDATA としてパース。成功時は終端オフセット `begin + 16` を返す |
| `(RecordAAAA).String() string` | netip の正規形（小文字・圧縮済み、例: `"2001:db8::d47:bb"`） |
| `(RecordAAAA).CanonicalWireFormat() []byte` | 16 バイトの IPv6 アドレス（バイトオーダー変換なし） |
| `(RecordAAAA).AppendWireFormat(w *WireFormat, db *NameCompressionDB) uint32` | 16 バイトを `w` に追加。`db` は使用されない（ドメイン名・圧縮ポインタを含まないため） |
| `(RecordAAAA).AppendCanonicalWireFormat(w *WireFormat) uint32` | 上記と同一。16 バイトを追加 |
| `(RecordAAAA).Type() ResourceType` | `TYPE_AAAA` (28) |

`RecordAAAA` は `RDATA` インターフェースを実装します。
`ParseResourceRecord` の `TYPE_AAAA` case で `rr.RData` には
`RecordAAAA`（値）が格納されます。

## 構築と表示

```go
a, err := dnsmsg.NewRecordAAAAFromString("2001:db8::1")
// err == nil
fmt.Println(a.String()) // "2001:db8::1"

b := dnsmsg.NewRecordAAAA([16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1})
fmt.Println(b.String()) // "::1"
```

`NewRecordAAAAFromString` のエラー一覧（実測確認済み）:

| 条件 | エラー |
|------|--------|
| IPv4 アドレス（`1.2.3.4` など） | `<addr> is not IPv6 address` |
| 不正な文字列（`not-an-ip` など） | `ParseAddr("not-an-ip"): unable to parse IP`（`netip.ParseAddr` のエラーをそのまま返す） |

> **注**: IPv4-mapped アドレス（例 `::ffff:1.2.3.4`）は `netip.Addr.Is4()`
> が偽を返すため**受信され**、`String()` は
> `"::ffff:1.2.3.4"` となります（実測確認済み）。また loopback（`::1`）も
> 通常通り受け入れられます。

## RDATA の直接パース（`ParseRecordAAAA`）

```go
wire := []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01}
a, end, err := dnsmsg.ParseRecordAAAA(wire, 0)
// err == nil, end == 16
fmt.Println(a.String()) // "2001:db8::1"
```

パース処理は `netip.AddrFromSlice` による 16 バイトの解釈です
（ネットワークバイトオーダーはそのまま netip の 16 バイト表現と一致します）。

エラー一覧（実測確認済み）:

| 条件 | エラー |
|------|--------|
| `msg` の `begin` オフセット以降が 16 バイト未満 | `invalid AAAA record RDATA size` |

> **注 1**: RDLENGTH のウィンドウ引数は `ParseRecordA` と同じくありません
> （`ParseResourceRecord` は RDLENGTH を独立に計算し、`end` を次に
> スキップします）。RDLENGTH が 16 より大きい場合は先頭 16 バイトのみ
> 読み、残りは無視されます。16 より大きい RDATA の厳密な検証は
> 呼び出し側の責任です。
>
> **注 2**: ソースコードには IPv4 アドレス（`ip.Is4()`）検出のエラー
> `AAAA record contains IPv4-mapped address` がありますが、
> `netip.AddrFromSlice` は 16 バイトの slice に対して IPv6 アドレスを
> 返すため、この分岐は通常発生しません（IPv4-mapped の
> `00 00 00 00 00 00 ff ff c0 a8 01 01 00 00 00 00`（= `::ffff:192.168.1.1`）
> をパースすると正常にパースされることを確認済み（実測確認済み）。

## レコード全体の round-trip（`ParseResourceRecord`、実測確認済み）

AAAA レコードの wire format の例（合計 29 バイト）:

```
01 61 00                                    ;; name = "a."
00 1c                                       ;; TYPE = AAAA (28)
00 01                                       ;; CLASS = IN (1)
00 00 01 2c                                 ;; TTL = 300
00 10                                       ;; RDLENGTH = 16
20 01 0d b8 00 00 00 00                     ;; RDATA =
00 00 00 00 00 01                           ;;   2001:db8::1
```

```go
wire := []byte{0x01, 'a', 0x00,
	0x00, 0x1c, // TYPE = AAAA (28)
	0x00, 0x01, // CLASS = IN (1)
	0x00, 0x00, 0x01, 0x2c, // TTL = 300
	0x00, 0x10, // RDLENGTH = 16
	0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01}
rr, end, err := dnsmsg.ParseResourceRecord(wire, 0)
// err == nil, end == 29
// rr.Type == TYPE_AAAA, rr.Class == CLASS_IN, rr.TTL == 300
fmt.Println(rr.String()) // "a. 1 28 300 2001:db8::1"
```

## シリアライゼーション

```go
var w dnsmsg.WireFormat
aaaa := dnsmsg.NewRecordAAAA([16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1})
n := aaaa.AppendWireFormat(&w, nil) // nil の db に問題なし
// n == 16、w は "00 ... 00 01" の 16 バイト
```

`AppendWireFormat` と `AppendCanonicalWireFormat` は全く同じ byte 列
（16 バイトの IPv6 アドレス）を書き出します。ドメイン名や圧縮ポインタを
含まないため、通常の wire format と正規形（canonical）の間に違いはありません。

## 補足

- `String()` は `netip.Addr.String()` の出力です（小文字・ゼロ圧縮の
  表示形式、例: `2001:db8::1`、`::1`）。
- wire format はネットワークバイトオーダーのまま保持され、バイトオーダー
  の変換は行われません（`netip.As16()` / 16 バイト slice をそのまま利用）。
- テスト: `record-aaaa_test.go`（`TestParseRecordAAAA` /
  `TestNewRecordAAAAFromString` / `TestRecordAAAAString` /
  `TestRecordAAAAAppendWireFormat` など、テーブル駆動）。
