# EDNS(0) / OPT レコードの作成

EDNS(0)（RFC 6891）は additional データセクションに置く OPT 擬似レコード
（TYPE=41、`TYPE_OPT`）によって拡張情報を付加する仕組みです。
`dnsmsg` パッケージでは `Message.SetEDNS0` を呼び出すだけで OPT レコードを
追加セクションに挿入し、`WriteWireFormat` で wire format にシリアライズできます。

## OPT レコードの構造

OPT レコードの各フィールドは以下のように使われます。

| フィールド | 内容 |
|------------|------|
| Name     | root（空ドメイン名。`ResourceRecord.String()` の表示では先頭が空になる） |
| Class    | `CLASS_IN` (1) |
| TTL      | 拡張 UDP ペイロードサイズ（例: `EDNS0DefaultPayloadSize` = 1232） |
| RDATA    | `VERSION`（1 byte）+ `FLAGS`（2 bytes）+ EDNS オプション（0 個以上） |

RDATA の flags 下位 4 bit は EDNS バージョンで、`VERSION` バイトと一致しなければ
パース時にエラーになります。

## 主要な API

| API | 説明 |
|-----|------|
| `Message.SetEDNS0(payloadSize uint32, flags uint16, options ...EDNSOption)` | OPT レコードを追加セクションに設定する。既存の OPT を**置換**し、`ARCOUNT` の増加は 1 回のみ（繰り返し呼び出しでも冪等）。エラーは返さない |
| `NewRecordOPT(version uint8, flags uint16, options ...EDNSOption) RecordOPT` | OPT レコード構造体を直接作る |
| `NewRecordOPTFromString(s string) (RecordOPT, error)` | プレゼンテーション形式文字列から OPT を作る |
| `ParseRecordOPT(w WireFormat, begin uint32, end uint32) (RecordOPT, uint32, error)` | wire format から OPT をパース（`ParseWireFormat` が内部で呼ぶ） |
| `NewEDNSOptionNSID(nsid string) (EDNSOptionNSID, error)` | NSID オプション（RFC 7873）。ID は 1〜255 文字の可印 ASCII |
| `NewEDNSOptionEDE(errorCode uint16, extraText string) EDNSOptionEDE` | EDE オプション（RFC 8914）。エラーは返さない |
| `RegisterEDNSOptionParser(code uint16, p func(data []byte) EDNSOption)` | オプションコード用のパーサを登録。登録済みのコードの上書きになる |

よく使う定数と option code:

| 定数 | 値 | 説明 |
|------|-----|------|
| `EDNS0Version` | 0 | EDNS バージョン |
| `EDNS0FlagDO` | `0x8000` | DNSSEC DO bit（RFC 3225） |
| `EDNS0DefaultPayloadSize` | 1232 | 推奨 UDP ペイロードサイズ |
| `EDNSOptionCodeDNSSEC` | 1 | DNSSEC |
| `EDNSOptionCodeNSID` | 3 | NSID |
| `EDNSOptionCodeClientSubnet` | 8 | Client Subnet（RFC 4635） |
| `EDNSOptionCodeEDE` | 15 | Extended DNS Errors |

> **注**: `EDNSOptionCodeClientSubnet` は定数のみ定義されており、型付きの
> `EDNSOption` 実装はついていません。Client Subnet を送る場合は
> `EDNSOptionRaw` で RDATA を組み立てます（後述）。

## DO bit 付きの EDNS0 クエリの作成

```go
var query dnsmsg.Message
query.ID = 0xdead
query.QR = dnsmsg.QRQuery
query.OPCODE = dnsmsg.QpcodeQuery
query.RD = 1
if err := query.SetQuery("www.example.com.", dnsmsg.CLASS_IN, dnsmsg.TYPE_A); err != nil {
    // handle error
}
query.SetEDNS0(dnsmsg.EDNS0DefaultPayloadSize, dnsmsg.EDNS0FlagDO)

opt := query.AdditionalSection[0].RData.(dnsmsg.RecordOPT)
// opt.Flags == 0x8000, opt.Version == 0

wire := new(dnsmsg.WireFormat)
wire.WriteWireFormat(query)
// wire.Size() == 47
```

検証済み出力:

- OPT レコードの表示（`ResourceRecord.String()`）: `" 1 41 1232 8000"`（name は root なので空白始まり。class=1, type=41, ttl=1232, RDATA=`"8000"`）
- `RecordOPT.String()`: `"8000"`（flags は 4 桁 hex 表示）
- wire format（47 バイト）:
  `de ad 01 00 00 01 00 00 00 00 00 01 03 77 77 77 07 65 78 61 6d 70 6c 65 03 63 6f 6d 00 00 01 00 01 00 00 29 00 01 00 00 04 d0 00 03 00 80 00`
  - `00 00 04 d0` = TTL 1232（ペイロードサイズ）
  - `00 03 00 80 00` = RDATA 3 バイト: VERSION=0, FLAGS=0x8000（DO）
  - 末尾の `00` は root 名（OPT の Name）

## NSID オプション（RFC 7873）

```go
nsid, err := dnsmsg.NewEDNSOptionNSID("MY-NS-01")
// 1〜255 文字の可印 ASCII 以外の場合だけ err != nil

var query dnsmsg.Message
query.ID = 0xdead
query.SetQuery("www.example.com.", dnsmsg.CLASS_IN, dnsmsg.TYPE_A)
query.SetEDNS0(1232, 0, nsid)

var w dnsmsg.WireFormat
w.WriteWireFormat(query)
// w.Size() == 59
```

検証済み wire（OPT の RDATA 部分のみ）:

`00 00 00 00 03 00 08 4d 59 2d 4e 53 2d 30 31`

- `00 00` = VERSION / FLAGS（flags は 0）
- `00 03` = option code 3（NSID）
- `00 08` = option data 長 8
- `4d 59 2d 4e 53 2d 30 31` = `"MY-NS-01"`

パース後、option は `EDNSOptionNSID` として戻り、`opt.Options[0]` の
`String()` は `"NSID 4d592d4e532d3031"`（ID の hex 表示）になります。

## EDE を伴うレスポンス（RFC 8914）

```go
var resp dnsmsg.Message
resp.ID = 0xbeef
resp.QR = dnsmsg.QRResponse
resp.SetQuery("stale.example.com.", dnsmsg.CLASS_IN, dnsmsg.TYPE_A)
resp.RCODE = dnsmsg.RCodeNameError
resp.SetEDNS0(dnsmsg.EDNS0DefaultPayloadSize, 0,
    dnsmsg.NewEDNSOptionEDE(dnsmsg.EDECodeStaleAnswer, "answer is stale"))

var w dnsmsg.WireFormat
w.WriteWireFormat(resp)
// w.Size() == 70
```

検証済み wire（OPT の RDATA 部分のみ）:

`00 00 00 0f 00 11 00 03 61 6e 73 77 65 72 20 69 73 20 73 74 61 6c 65`

- `00 0f` = option code 15（EDE）
- `00 11` = option data 長 17
- `00 03` = EDE INFO-CODE 3（`EDECodeStaleAnswer`）
- `61 6e 73 77 65 72 20 69 73 20 73 74 61 6c 65` = `"answer is stale"`

パース後、option は `EDNSOptionEDE{ErrorCode: 3, ExtraText: "answer is stale"}`
となり、`String()` は `"EDE 3 \"answer is stale\""` です。

使用可能な EDE code（RFC 8914 定義の一部）:

| 定数 | 値 |
|------|-----|
| `EDECodeOther` | 0 |
| `EDECodeStaleAnswer` | 3 |
| `EDECodeForgedAnswer` | 4 |
| `EDECodeDNSSECBogus` | 6 |
| `EDECodeNotReady` | 14 |

## 生データオプション（`EDNSOptionRaw`）

パーサが登録されていないオプションコード（Client Subnet など）は
`EDNSOptionRaw` で送れます。

```go
raw := dnsmsg.EDNSOptionRaw{
    OptionCode: 4,
    OptionData: []byte{0x19, 0x02},
}

var query dnsmsg.Message
query.ID = 0xdead
query.SetQuery("www.example.com.", dnsmsg.CLASS_IN, dnsmsg.TYPE_A)
query.SetEDNS0(1232, 0, raw)
```

検証済み wire（OPT の RDATA 部分）: `00 00 00 04 00 02 19 02`
パース後、option はそのまま `EDNSOptionRaw{OptionCode: 4, OptionData: [0x19, 0x02]}`
に戻り、`String()` は `"4 1902"`（code と hex data）になります。

Client Subnet（RFC 4635）の場合は、SCOPE-ROUTER-PREFIX-LENGTH(1B) +
RESERVED(1B) + FAMILY(2B) + SCOPE-ADDRESS の RDATA を `OptionData` に
入れて同様に送ります（例: RFC 4635 付録の `10 00 00 01 0ac00001`）。

## カスタムオプションとパーサ登録

自前の EDNS オプションは `EDNSOption` インターフェース
（`Code() uint16` / `Data() []byte` / `String() string`）を実装した型として
`SetEDNS0` に渡せます。

```go
type customOption struct{ value []byte }

func (c customOption) Code() uint16 { return 10 }
func (c customOption) Data() []byte { return c.value }
func (c customOption) String() string {
    return fmt.Sprintf("custom %v", []byte(c.value))
}

var query dnsmsg.Message
query.ID = 0xdead
query.SetQuery("www.example.com.", dnsmsg.CLASS_IN, dnsmsg.TYPE_A)
query.SetEDNS0(1232, 0, customOption{value: []byte("hello")})
```

検証済み wire（OPT の RDATA 部分）: `00 00 00 0a 00 05 68 65 6c 6c 6f`

受信側でこのコードの option を型付き値として取り出したい場合は
`RegisterEDNSOptionParser` でパーサを登録します。

```go
dnsmsg.RegisterEDNSOptionParser(10, func(data []byte) dnsmsg.EDNSOption {
    return customOption{value: data}
})
```

登録すると `ParseWireFormat` の結果では `opt.Options[i]` が
`customOption`（`value == "hello"`）として戻ります。登録しない場合は
`EDNSOptionRaw` で戻ります（上掲の生データ例と同じ挙動です）。

## プレゼンテーション形式から構築（`NewRecordOPTFromString`）

```go
r, err := dnsmsg.NewRecordOPTFromString("0x8000 DO")
// r.Flags == 0x8000（DO bit 付き）, len(r.Options) == 1
fmt.Println(r.String()) // "8000 DO"
```

文法: 先頭フィールドは flags（10 進 or `0x` 付き 16 進）。続くフィールドは
`DO`（DNSSEC option の略）または `<option-code 10 進> <hex data>` のペア。

> **注意**: 先頭フィールドは `0x` 付きでないと **10 進**として解釈されます。
> `NewRecordOPTFromString("8000 DO")` の `r.String()` は `"1f40 DO"` であり、
> これは flags = 8000（10 進）= `0x1f40` であることを意味します（DO bit ではない）。

## レスポンスの解析と型アサーション

```go
wire := /* 受信した DNS メッセージの byte 列 */
msg, err := dnsmsg.ParseWireFormat(wire)
// 確認したい場合は msg.AdditionalSection 内の OPT レコードを検査

for _, rr := range msg.AdditionalSection {
    opt, ok := rr.RData.(dnsmsg.RecordOPT)
    if !ok {
        continue
    }
    for _, o := range opt.Options {
        switch t := o.(type) {
        case dnsmsg.EDNSOptionNSID:
            // t.ID
        case dnsmsg.EDNSOptionEDE:
            // t.ErrorCode, t.ExtraText
        case dnsmsg.EDNSOptionRaw:
            // t.OptionCode, t.OptionData
        }
    }
}
```

パース時の挙動:

- `VERSION` バイトと `FLAGS` 下位 4 bit が不一致 → エラー
- オプションの code(2)+length(2) ヘッダが 4 バイト未満で途切れている → エラー
- 登録のないオプションコード → `EDNSOptionRaw` に格納（エラーにはしない）
- EDE で data が 2 バイト未満 → `EDNSOptionRaw`（code 15）に格納（エラーにはしない）

## クエリの送信（UDP）

`SendQuery` はパッケージ関数で、構築した `Message` を UDP/TCP で送り、
レスポンスの `Message` を返します。

```go
var query dnsmsg.Message
query.ID = 0xdead
query.RD = 1
query.SetQuery("www.example.com.", dnsmsg.CLASS_IN, dnsmsg.TYPE_A)
query.SetEDNS0(dnsmsg.EDNS0DefaultPayloadSize, dnsmsg.EDNS0FlagDO)

reply, err := dnsmsg.SendQuery(query, "127.0.0.1", 53, dnsmsg.DNSoverUDP)
// reply.AdditionalSection / reply.AnswerSection を上記の型アサーションで検査
```

transport 引数は `dnsmsg.DNSoverUDP` ("udp") または `dnsmsg.DNSoverTCP` ("tcp")
です。TCP はメッセージ先頭に 2 バイト長の長さプレフィックスが付きます。

## 補足

- `SetEDNS0` は OPT レコードを**置換**します。2 回呼び出すと 2 番目の内容が
  残り、`ARCOUNT` は 1 のままです（冪等）。
- `Message.ARCOUNT` は `SetEDNS0` が管理するため、自前で増やす必要はありません。
- `SetQuery` は `QuestionSection` と `QDCOUNT` をセットします（既存の question
  は上書き）。
- 正規形（canonical、圧縮なし・小文字）のシリアライズは
  `(*WireFormat).AppendCanonicalWireFormat` 系で取得できます。
