# CNAME レコード（`RecordCNAME`）

CNAME レコード（TYPE=5、`TYPE_CNAME`）は、オーナー名が別のドメイン名（正準名、
canonical name）の別名（エイリアス）であることを示す DNS リソースレコードです
（RFC 1035 Section 3.3.1）。RDATA は DNS 名（ドメイン名）であり、RDLENGTH は
名前自身の wire format 長に依存します（ルート単独なら 1 バイト、名前の wire
format が 255 バイトを超えると構築・パースに失敗する）。

## レコードの構造

| 項目 | 内容 |
|------|------|
| Name | 別名となるドメイン名（`DomainName`） |
| Class | `CLASS_IN` (1) |
| Type | `TYPE_CNAME` (5) |
| TTL | TTL（秒） |
| RDATA | 正準名のドメイン名（RDLENGTH は名前の wire format 長。例: `www.example.com.` は非圧縮で 17 バイト、同一メッセージ内で先に `example.com` が出ていれば 6 バイト） |

`RecordCNAME` の中身フィールド `CNAME`（`DomainName`）はエクスポート済みです
（`RecordNS` の `nsname` と違い、パッケージの外から `rdata.CNAME` で直接
読める）。

## 主要な API

| API | 説明 |
|-----|------|
| `NewRecordCNAME(cname DomainName) RecordCNAME` | `DomainName` から直接構築。エラーは返さない |
| `NewRecordCNAMEFromString(s string) (RecordCNAME, error)` | 表示形式文字列から構築。`NewDomainNameFromString` によるパース（ラベル長・エスケープ等の規則は domainname.go 参照） |
| `ParseRecordCNAME(w WireFormat, begin uint32) (RecordCNAME, uint32, error)` | `w` の `begin` オフセットから（圧縮ポインタを含む）DNS 名をパース。成功時は終端オフセットを返す。ドメイン名パースのエラーは `cannot parse cname: ` の接頭辞で包まれる |
| `(RecordCNAME).Type() ResourceType` | `TYPE_CNAME` (5) |
| `(RecordCNAME).String() string` | 表示形式（`www.example.com` なら `"www.example.com."`。ルート単独は `"."`） |
| `(RecordCNAME).CanonicalWireFormat() []byte` | 名前の canonical wire format（RFC 4034: 小文字・非圧縮・末尾ゼロ 1 バイト） |
| `(RecordCNAME).AppendWireFormat(w *WireFormat, db *NameCompressionDB) uint32` | 名前を `w` に付加（`w.AppendDomainName` 経由）。`db` が nil でない場合、同じメッセージ内で先に出た共通接尾辞は圧縮ポインタに置換される |
| `(RecordCNAME).AppendCanonicalWireFormat(w *WireFormat) uint32` | canonical 形（小文字・非圧縮）を付加 |

`RecordCNAME` は `RDATA` インターフェースを実装します。
`ParseResourceRecord` の `TYPE_CNAME` case で `rr.RData` には
`RecordCNAME`（値）が格納されます。

## 構築と表示

```go
cname, err := dnsmsg.NewRecordCNAMEFromString("www.example.com")
// err == nil
fmt.Println(cname.String()) // "www.example.com."

// ルート単独（"" や "."）も合法なドメイン名
r, err := dnsmsg.NewRecordCNAMEFromString("")
// err == nil
fmt.Println(r.String()) // "."
```

エスケープ規則（3 桁の十進数エスケープ、`\.` はラベル内の文字）と
ラベル長 63 オクテットまで合法、という規則は NS と同一です
（[record-ns.md](record-ns.md) 参照。実測確認済み）。

`NewRecordCNAMEFromString` のエラー一覧（実測確認済み）:

| 条件 | エラー |
|------|--------|
| 空ラベル（`a..b` など、ドット 2 連続） | `invalid domainname(empty label)` |
| 文字列末尾に孤立したバックスラッシュ（`a\` など） | `last character of a\ is \` |

## RDATA の直接パース（`ParseRecordCNAME`）

```go
wire := []byte{0x03, 'w', 'w', 'w',
    0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
    0x03, 'c', 'o', 'm', 0x00} // 合計 17 バイト「www.example.com」
cname, end, err := dnsmsg.ParseRecordCNAME(wire, 0)
// err == nil, end == 17
fmt.Println(cname.String()) // "www.example.com."
```

`NewDomainNameFromCompressedWireFormat` を通してパースするため、
圧縮ポインタ（`0xc0xx`）も受理します。

エラー一覧（実測確認済み。`ParseRecordCNAME` はドメイン名パースの
エラーを `cannot parse cname: ` の接頭辞で包んで返します）:

| 条件 | エラー |
|------|--------|
| ルートラベル（ゼロ 1 バイト）で終わらない | `cannot parse cname: invalid domainname(not terminated)` |
| `begin` オフセットが `w` の範囲外 | `cannot parse cname: out of bound in parsing domainname` |
| 圧縮ポインタが前方または範囲外を指す（例: 2 バイトメッセージでオフセット 48 を指す `c0 30`） | `cannot parse cname: out of bound in parsing domainname(compression offset: 48)` |

## レコード全体の round-trip（`ParseResourceRecord`、実測確認済み）

`alias.example.com` の CNAME が `www.example.com` を指すレコードの
wire format の例（合計 35 バイト）:

```
05 61 6c 69 61 73 07 65 78 61 6d 70 6c 65 03 63 6f 6d 00   ;; name = alias.example.com (19 バイト)
00 05                                                ;; TYPE = CNAME (5)
00 01                                                ;; CLASS = IN (1)
00 00 01 2c                                          ;; TTL = 300
00 06                                                ;; RDLENGTH = 6
03 77 77 77                                          ;; RDATA = 「www」（3 バイト）
c0 06                                                ;; + 圧縮ポインタ → オフセット 6（「example.com」）
```

RDATA の 6 バイトのうち末尾 2 バイト `c0 06` は圧縮ポインタ
（`0xc000 | 6`。オーナー名の中で `example.com` が書き出されたオフセット 6 を
指す）。

```go
wire := []byte{
    0x05, 'a', 'l', 'i', 'a', 's', 0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x03, 'c', 'o', 'm', 0x00,
    0x00, 0x05, 0x00, 0x01, 0x00, 0x00, 0x01, 0x2c, 0x00, 0x06,
    0x03, 'w', 'w', 'w', 0xc0, 0x06,
}
rr, end, err := dnsmsg.ParseResourceRecord(wire, 0)
// err == nil, end == 35
// rr.Type == TYPE_CNAME, rr.Class == CLASS_IN, rr.TTL == 300
fmt.Println(rr.String()) // "alias.example.com. 1 5 300 www.example.com."

rdata := rr.RData.(dnsmsg.RecordCNAME)
fmt.Println(rdata.String()) // "www.example.com."
```

## シリアライズ

### 圧縮なし（`db` = nil）

名前の全体（ラベル + 末尾ゼロ 1 バイト）が書き出されます
（`www.example.com` なら 17 バイト、実測確認済み）:

```
03 77 77 77 07 65 78 61 6d 70 6c 65 03 63 6f 6d 00   ;; 「www.example.com」非圧縮
```

### 圧縮あり（`db` 非 nil）

`AppendWireFormat` は `w.AppendDomainName(cname, db)` を呼び出します。
圧縮の規則（`NameCompressionDB` への接尾辞登録、14 bit のオフセット制限、
メッセージ単位でしか機能しない）は NS と同一です（[record-ns.md](record-ns.md)
参照）。

`AppendResourceRecord` が上記のレコードから作る wire format は、上の
手書き例と完全に一致します（実測確認済み、35 バイト）:

```
05 61 6c 69 61 73 07 65 78 61 6d 70 6c 65 03 63 6f 6d 00 00 05 00 01 00 00 01 2c 00 06 03 77 77 77 c0 06
```

### canonical 形

`AppendCanonicalWireFormat` は RFC 4034 の canonical wire format
（小文字・非圧縮・末尾ゼロ 1 バイト）を書き出します（実測確認済み）。
例: `WWW.EXAMPLE.COM.` → 17 バイト

```
03 77 77 77 07 65 78 61 6d 70 6c 65 03 63 6f 6d 00
```

## JSON

`RecordCNAME` は `MarshalJSON` / `UnmarshalJSON` を持ちます。正準名は
表示形式文字列としてエンコードされます（実測確認済み）:

```go
json.Marshal(cname)
// {"CNAME":"www.example.com."}

json.Marshal(rr) // rr.Type == TYPE_CNAME の場合
// {"Class":"IN","Name":"alias.example.com.","RData":{"CNAME":"www.example.com."},"TTL":300,"Type":"CNAME"}
```

`ResourceRecord.UnmarshalJSON` は `Type` が `"CNAME"`（または 5）のとき
`RData` を `RecordCNAME` としてデコードします。不正な表示形式文字列
（`"a..b."` など）はエラーになります。

## 補足

- CNAME の RDATA は NS と同一の形（単一のドメイン名）です。圧縮ポインタの
  扱い、canonical 形、ドメイン名の規則の詳細は [record-ns.md](record-ns.md) を
  参照してください。
- `TYPE_CNAME` の `ParseResourceRecord` の case では `rr.RData` に
  `RecordCNAME` が格納されるため、`rr.RData.(dnsmsg.RecordCNAME)` で
  取り出せます（index.md の「レコードデータの取り出し」参照）。
- `dq` コマンドでも `-t CNAME` で CNAME query を送信できます（`dq.md` 参照）。
