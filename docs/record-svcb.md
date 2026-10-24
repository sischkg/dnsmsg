# SVCB レコード（`RecordSVCB`）

SVCB レコード（TYPE=64、`TYPE_SVCB`）は、その名前に紐づくサービスの接続先を
伝えるためのサービス参数（service binding）レコードです（RFC 9460）。
HTTPS レコード（TYPE=65）はこの RDATA 形式をそのまま使う特殊化で、
`RecordHTTPS` として [record-https.md](record-https.md) に説明しています。

```
_svcb._udp.example.com.  3600  IN  SVCB  1 svcb.example.com. alpn=h2,port=8443
```

## レコードの構造

| 項目 | 内容 |
|------|------|
| Name | サービスの名前（RFC 9460 Section 3.1 のサービス識別子でもよい） |
| Class | `CLASS_IN` |
| Type | `TYPE_SVCB` (64) |
| TTL | 通常のレコードと同じ |
| RDATA | 下記のフィールド列（RDLENGTH は TargetName と SvcParams の長さに依存） |

`RecordSVCB` のフィールド:

| フィールド | 型 | 内容 |
|----------|----|------|
| `SvcPriority` | `uint16` | サービスの優先順位。`0` は AliasMode、`1` 以上は ServiceMode |
| `TargetName` | `DomainName` | 别名先、またはサービスが実際に listen する名前 |
| `SvcParams` | `[]SvcParam` | `SvcParamKey=SvcParamValue` の対。キー番号の昇順で保持する |

AliasMode（`SvcPriority == 0`）のレコードは SvcParams を持てません。
ServiceMode のレコードは SvcParams を 0 個以上持ちます。

## wire format

```
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                SvcPriority                    |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
\
/                 TargetName                    \
\                                               /
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                SvcParamKey                  |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                SvcParamValue.Length         |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
\
/                 SvcParamValue                 \
\                                               /
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
```

SvcParams はこのブロックの繰り返しで、`SvcParamKey` は厳密な昇順でなければ
なりません（RFC 9460 Section 2.2）。`NewRecordSVCB` と
`NewRecordSVCBFromString` は渡された SvcParams を並べ替えるので、呼び出し側は
どの順で追加してもかまいません。

TargetName は wire format 上での名前圧縮を使いません。圧縮ポインタを含む
RDATA は解析時にエラーになります。これは RDATA の内側に置かれた名前が後で
他の名前に差し替えられると、そのポインタが壊れた位置を指してしまうためです。

## SvcParamKey と SvcParam

`SvcParam` のフィールド:

| フィールド | 型 | 内容 |
|----------|----|------|
| `Key` | `SvcParamKey` | `uint16` のキー番号 |
| `Value` | `[]byte` | RFC 9460 Appendix A の character-string 復号を適用済みの値 |

登録済みのキー（`SvcParamKey` の定数）:

| 定数 | 番号 | zone file 名 | value の内容 |
|------|------|--------------|--------------|
| `KeyMandatory` | 0 | `mandatory` | 必須キーの 2 バイト番号の列 |
| `KeyAlpn` | 1 | `alpn` | length-prefix を付けた ALPN protocol ID の列 |
| `KeyNoDefaultAlpn` | 2 | `no-default-alpn` | 常に空 |
| `KeyPort` | 3 | `port` | 10 進数のポート番号の ASCII 列 |
| `KeyIPv4Hint` | 4 | `ipv4hint` | 4 バイトの IPv4 アドレスの列 |
| `KeyECH` | 5 | `ech` | ECHConfigList のオクテット |
| `KeyIPv6Hint` | 6 | `ipv6hint` | 16 バイトの IPv6 アドレスの列 |

それ以外のキー番号は RFC 9460 Appendix A.2 のとおり `key` + 10 進数として
表現し、値は解釈せずにそのまま保持します。

`Value` は character-string 復号を適用した後の値です。`alpn` は各 ID の長さ
オクテットを含んだそのままのオクテット列、`port` は 10 進数の文字列です。
固定長項目のキー（`mandatory`・`ipv4hint`・`ipv6hint`）の値は項目の切れ目で
終わっていなければなりません。

## zone file 表現の読み書き

```go
// ゾーンファイルと同じ表記から作る
r, err := dnsmsg.NewRecordSVCBFromString("1 svcb.example.com. alpn=h2,port=8443")

// 文字列として書き出す（SvcParams はキー番号の昇順で並ぶ）
fmt.Println(r.String())
// 1 svcb.example.com. alpn=h2,port=8443

// パラメータを 1 つずつ追加して作る
alpn, err := dnsmsg.NewSvcParam(dnsmsg.KeyAlpn, "h2")
port, err := dnsmsg.NewSvcParam(dnsmsg.KeyPort, "8443")
r := dnsmsg.NewRecordSVCBFromParams(1, targetName, alpn, port)
```

`NewSvcParam(key, value)` に渡す `value` は zone file に書く表現と同じで、
character-string のエスケープ（RFC 9460 Appendix A.1）だけを適用したものです。
`NewRecordSVCBFromString` に渡す文字列はゾーンファイルに書く形式なので、
zone file の escape ともう 1 層分けます。

```go
// 1 つの ALPN ID にカンマを含む場合。
// NewSvcParam には復号後の値を渡すのでバックスラッシュ 1 つ。
p, err := dnsmsg.NewSvcParam(dnsmsg.KeyAlpn, `a\,b`)

// NewRecordSVCBFromString には zone file の表現を渡すのでバックスラッシュ 2 つ。
r, err := dnsmsg.NewRecordSVCBFromString(`1 svcb.example.com. alpn=a\\,b`)

fmt.Println(r.String()) // 1 svcb.example.com. alpn=a\\,b
```

`String()` は常に `r.String()` が `NewRecordSVCBFromString(r.String())` で
読み返せるような文字列を生成します。印字できないオクテットを含む値
（`ech` など）は `"..."` で囲んだ character-string として出力します。

## 検証

レコードを作る・読み込むいずれの経路（`NewRecordSVCB`、
`NewRecordSVCBFromString`、`ParseRecordSVCB`、JSON の import）でも次を検証します。

- AliasMode のレコードに SvcParams がないこと
- 同じキーの SvcParam が 1 つだけであること
- `mandatory` が必ず自身以外のキーで、1 度ずつであり、そのレコードが持つキー
  だけを列挙すること（RFC 9460 Section 8）
- 各キーの値がその wire format として正しい長さ・形式であること
- SvcParams が 16 ビットの RDLENGTH に収まること

`ParseRecordSVCB` は SvcParams の順が壊れている RDATA、途中で切れた項目、
RDATA の外にはみ出す項目もエラーにします。

## JSON

```json
{"SvcPriority":1,"TargetName":"svcb.example.com.","SvcParams":[
  {"Key":"alpn","Raw":"AmgyAmgz","Value":"h2,h3"},
  {"Key":"port","Raw":"IPs","Value":"8443"}]}
```

`Raw` は SvcParamValue の base64（RFC 4648 Section 4 の padding 無し）で、
`Value` は zone file と同じ text 表現です。import の方は `Raw` を `Value` より
優先し、`Raw` がない param だけ `Value` を解析します。`Value` があるのは人間が
読む JSON を書きやすくするためで、両方のフィールドが常に同じ内容になるとは限りません。
