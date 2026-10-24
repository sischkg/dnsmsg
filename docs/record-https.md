# HTTPS レコード（`RecordHTTPS`）

HTTPS レコード（TYPE=65、`TYPE_HTTPS`）は HTTP または HTTPS サービスの
サービス参数（service binding）です（RFC 9460 Section 3）。RDATA の形は
SVCB レコードと完全に同じで、`RecordHTTPS` は `RecordSVCB` を埋め込んで
表現形式・wire format・JSON の各メソッドをそのまま使います。
異なるのはレコード型だけなので、RDATA の構造・SvcParamKey の一覧・検証・
zone file 表現の詳細は [record-svcb.md](record-svcb.md) に説明しています。

```
example.com.  3600  IN  HTTPS  1 svc.example.com. alpn=h2,ipv4hint=192.0.2.1,192.0.2.2
```

## `RecordSVCB` を使う部分と違う部分

`RecordHTTPS` のフィールドは埋め込まれた `RecordSVCB` 1 つだけです。

| メソッド・関数 | 内容 |
|----------------|------|
| `Type()` | `TYPE_HTTPS` を返す。`RecordHTTPS` が `RecordSVCB` から受け継がない唯一のメソッド |
| `ParseRecordHTTPS(w, begin, end)` | wire format から HTTPS レコードを読む |
| `NewRecordHTTPS(svcPriority, targetName, params...)` | SvcParams を任意の順で受け取って作る |
| `NewRecordHTTPSFromParams(svcPriority, targetName, params)` | SvcParams を zone file の表現の map で受け取って作る |
| `NewRecordHTTPSFromString(s)` | zone file の 1 レコード分の文字列から読む |
| `(*RecordHTTPS).UnmarshalJSON(data)` | `MarshalJSON` が書いた JSON object から読む |

`String()`、`CanonicalWireFormat()`、`AppendWireFormat()`、
`AppendCanonicalWireFormat()`、`MarshalJSON()` は `RecordSVCB` のものそのままです。

## 使い方

```go
r, err := dnsmsg.NewRecordHTTPSFromString(
	"1 svc.example.com. alpn=h2,ipv4hint=192.0.2.1,192.0.2.2")
if err != nil {
	return err
}
fmt.Println(r.Type()) // HTTPS
fmt.Println(r.String())
// 1 svc.example.com. alpn=h2,ipv4hint=192.0.2.1,192.0.2.2

rr := dnsmsg.ResourceRecord{
	Name:  name,
	Class: dnsmsg.CLASS_IN,
	Type:  dnsmsg.TYPE_HTTPS,
	TTL:   3600,
	RData: r,
}
```

メッセージの中の HTTPS レコードは `ParseMessage` が `ParseRecordHTTPS` で読み、
`RecordHTTPS` として `AnswerSection` などに入ります。

## AliasMode の HTTPS レコード

`SvcPriority` が `0` のレコードは AliasMode で、TargetName が別の名前への
别名であり、SvcParams を持ってはなりません（RFC 9460 Section 2.4.1）。

```go
r, err := dnsmsg.NewRecordHTTPS(0, aliasName)
```

SvcParams を渡した場合はエラーになります。SvcParams がないレコードはメモリ上
`SvcParams` が `nil` で、ゾーン表記では `0 alias.example.com.` のように
優先順位と TargetName だけになります。

## SvcParamKey

HTTPS レコードに定義されているキー（RFC 9460 Section 7.2.1）は
`mandatory`・`alpn`・`no-default-alpn`・`port`・`ipv4hint`・`ech`・`ipv6hint`
で、このライブラリが `RecordSVCB` で扱っているキーと同じです。
登録されていないキーの値は解釈せずに保持し、`key` + 10 進数として表現します。
