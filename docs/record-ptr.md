# PTR レコード（`RecordPTR`）

PTR レコード（TYPE=12、`TYPE_PTR`）は、オーナー名からドメイン名空間上の別の
場所を差す DNS リソースレコードです（RFC 1035 Section 3.3.12）。IPv4 の逆引き
（`IN-ADDR.ARPA` ドメイン）や IPv6 の逆引き（`IP6.ARPA` ドメイン）、
`1.0.0.127.in-addr.arpa. PTR localhost.` のような逆引きの応答に使われます。

RDATA はドメイン名 1 個です（RFC 1035 Section 3.3.12 の PTRDNAME）。
PTR レコードは追加セクションの処理を起こしません。CNAME が別名（エイリアス）を
示すのとは異なり、PTR はドメイン名空間上の別の場所を差すだけのデータであり、
CNAME のような特別な処理は導られません。

RFC 1035 Section 3.3 は「NS、SOA、CNAME、PTR はすべてのクラスで使われ、
クラスにかかわらず同じ形式を持つ。RDATA の形式が知られているので、これらの
RR の RDATA にあるドメイン名は圧縮できる」と定めています。そのため PTR の
RDATA のドメイン名は名前圧縮のポインタで表せます。

## レコードの構造

| 項目 | 内容 |
|------|------|
| Name | オーナー名（逆引き問い合わせでは `1.0.0.127.in-addr.arpa.` のような名前） |
| Class | `CLASS_IN` (1) |
| Type | `TYPE_PTR` (12) |
| TTL | TTL（秒） |
| RDATA | 差す先のドメイン名（RDLENGTH は名前の wire format 長。例: `www.example.com.` は非圧縮で 17 バイト） |

`RecordPTR` の中身フィールド `PTR`（`DomainName`）はエクスポート済みです
（パッケージの外から `rdata.PTR` で直接読めます）。

## 主要な API

| API | 説明 |
|-----|------|
| `NewRecordPTR(ptr DomainName) RecordPTR` | `DomainName` から直接構築。エラーは返さない |
| `NewRecordPTRFromString(s string) (RecordPTR, error)` | 表示形式文字列から構築。`NewDomainNameFromString` によるパース（ラベル長・エスケープ等の規則は domainname.go 参照） |
| `ParseRecordPTR(w WireFormat, begin uint32) (RecordPTR, uint32, error)` | `w` の `begin` オフセットから（圧縮ポインタを含む）DNS 名をパース。成功時は終端オフセットを返す。ドメイン名パースのエラーは `cannot parse ptr: ` の接頭辞で包まれる |
| `(RecordPTR).Type() ResourceType` | `TYPE_PTR` (12) |
| `(RecordPTR).String() string` | 表示形式（`www.example.com.` なら `"www.example.com."`。ルート単独は `"."`） |
| `(RecordPTR).CanonicalWireFormat() []byte` | 名前の canonical wire format（RFC 4034: 小文字・非圧縮・末尾ゼロ 1 バイト） |
| `(RecordPTR).AppendWireFormat(w *WireFormat, db *NameCompressionDB) uint32` | 名前を `w` に付加（`w.AppendDomainName` 経由）。`db` が nil でない場合、同じメッセージ内で先に出た共通接尾辞は圧縮ポインタに置換される |
| `(RecordPTR).AppendCanonicalWireFormat(w *WireFormat) uint32` | canonical 形（小文字・非圧縮）を付加 |

`RecordPTR` は `RDATA` インターフェースを実装します。
`ParseResourceRecord` の `TYPE_PTR` case で `rr.RData` には `RecordPTR`（値）が
格納されます。

## 構築と表示

```go
ptr, err := dnsmsg.NewRecordPTRFromString("www.example.com")
// err == nil
fmt.Println(ptr.String()) // "www.example.com."
```

エスケープ規則（3 桁の十進数エスケープ、`\.` はラベル内の文字）と
ラベル長 63 オクテットまで合法、という規則は CNAME と同一です
（[record-cname.md](record-cname.md) 参照）。

`NewRecordPTRFromString` のエラー一覧（実測確認済み）:

| 条件 | エラー |
|------|--------|
| 空ラベル（`a..b` など、ドット 2 連続） | `invalid domainname(empty label)` |

## RDATA の直接パース（`ParseRecordPTR`）

```go
wire := []byte{3, 'w', 'w', 'w',
    7, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
    3, 'c', 'o', 'm', 0} // 合計 17 バイト「www.example.com」
ptr, end, err := dnsmsg.ParseRecordPTR(wire, 0)
// err == nil, end == 17
fmt.Println(ptr.String()) // "www.example.com."
```

`NewDomainNameFromCompressedWireFormat` を通してパースするため、
圧縮ポインタ（`0xc0xx`）も受理します。

エラー一覧（実測確認済み。`ParseRecordPTR` はドメイン名パースの
エラーを `cannot parse ptr: ` の接頭辞で包んで返します）:

| 条件 | エラー |
|------|--------|
| ルートラベル（ゼロ 1 バイト）で終わらない | `cannot parse ptr: invalid domainname(not terminated)` |
| `begin` オフセットが `w` の範囲外 | `cannot parse ptr: out of bound in parsing domainname` |
| 圧縮ポインタが前方または範囲外を指す（例: 2 バイトメッセージでオフセット 48 を指す `c0 30`） | `cannot parse ptr: out of bound in parsing domainname(compression offset: 48)` |

## レコード全体の round-trip（`ParseResourceRecord`、実測確認済み）

`1.0.0.127.in-addr.arpa` の PTR が `localhost.example.com` を差すレコードの
wire format の例（合計 57 バイト）:

```
01 31 01 30 01 30 03 31 32 37 07 69 6e 2d 61 64 64 72 04 61 72 70 61 00   ;; name = 1.0.0.127.in-addr.arpa (24 バイト)
00 0c                                                ;; TYPE = PTR (12)
00 01                                                ;; CLASS = IN (1)
00 00 01 2c                                          ;; TTL = 300
00 17                                                ;; RDLENGTH = 23
09 6c 6f 63 61 6c 68 6f 73 74 07 65 78 61 6d 70 6c 65 03 63 6f 6d 00   ;; RDATA = 「localhost.example.com」（23 バイト）
```

```go
wire := []byte{
    0x01, '1', 0x01, '0', 0x01, '0', 0x03, '1', '2', '7',
    0x07, 'i', 'n', '-', 'a', 'd', 'd', 'r', 0x04, 'a', 'r', 'p', 'a', 0x00,
    0x00, 0x0c, 0x00, 0x01, 0x00, 0x00, 0x01, 0x2c, 0x00, 0x17,
    0x09, 'l', 'o', 'c', 'a', 'l', 'h', 'o', 's', 't',
    0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x03, 'c', 'o', 'm', 0x00,
}
rr, end, err := dnsmsg.ParseResourceRecord(wire, 0)
// err == nil, end == 57
// rr.Type == TYPE_PTR, rr.Class == CLASS_IN, rr.TTL == 300
fmt.Println(rr.String()) // "1.0.0.127.in-addr.arpa. 1 12 300 localhost.example.com."

rdata := rr.RData.(dnsmsg.RecordPTR)
fmt.Println(rdata.String()) // "localhost.example.com."
```

## シリアライズ

### 圧縮なし（`db` = nil）

名前の全体（ラベル + 末尾ゼロ 1 バイト）が書き出されます
（`www.example.com` なら 17 バイト、実測確認済み）:

```
03 77 77 77 07 65 78 61 6d 70 6c 65 03 63 6f 6d 00   ;; 「www.example.com」非圧縮
```

### 圧縮あり（`db` 非 nil）

`AppendWireFormat` は `w.AppendDomainName(ptr, db)` を呼び出します。
RFC 1035 Section 3.3 は PTR の RDATA のドメイン名の圧縮を認めているため、
共通接尾辞は圧縮ポインタに置換されます。

圧縮の規則（`NameCompressionDB` への接尾辞登録、14 bit のオフセット制限、
メッセージ単位でしか機能しない）は CNAME と同一です
（[record-cname.md](record-cname.md) 参照）。

`example.com` を先に書いたメッセージに `sub.example.com` を PTR として
書くと、`sub` の 4 バイトとオフセット 0 を指す圧縮ポインタの 2 バイト、
計 6 バイトになります（実測確認済み）:

```
03 73 75 62 c0 00   ;; 「sub」+ 圧縮ポインタ → オフセット 0（「example.com」）
```

### canonical 形

`AppendCanonicalWireFormat` は RFC 4034 の canonical wire format
（小文字・非圧縮・末尾ゼロ 1 バイト）を書き出します（実測確認済み）。
例: `WWW.EXAMPLE.COM.` → 17 バイト

```
03 77 77 77 07 65 78 61 6d 70 6c 65 03 63 6f 6d 00
```

## JSON

`RecordPTR` は `MarshalJSON` / `UnmarshalJSON` を持ちます。差す先の名前は
表示形式文字列としてエンコードされます（実測確認済み）:

```go
json.Marshal(ptr)
// {"PTR":"www.example.com."}

json.Marshal(rr) // rr.Type == TYPE_PTR の場合
// {"Class":"IN","Name":"1.0.0.127.in-addr.arpa.","RData":{"PTR":"localhost.example.com."},"TTL":300,"Type":"PTR"}
```

`ResourceRecord.UnmarshalJSON` は `Type` が `"PTR"`（または 12）のとき
`RData` を `RecordPTR` としてデコードします。不正な表示形式文字列
（`"a..b."` など）はエラーになります。

## 補足

- PTR の RDATA は NS・CNAME と同一の形（単一のドメイン名）です。圧縮ポインタの
  扱い、canonical 形、ドメイン名の規則の詳細は [record-cname.md](record-cname.md) を
  参照してください。
- RFC 1035 Section 3.3.12 は PTR レコードが「追加セクションの処理を起こさない」
  と述べています。CNAME のような特別な処理はありません。
- `TYPE_PTR` の `ParseResourceRecord` の case では `rr.RData` に `RecordPTR` が
  格納されるため、`rr.RData.(dnsmsg.RecordPTR)` で取り出せます
  （index.md の「レコードデータの取り出し」参照）。
- `dq` コマンドでも `-t PTR` で PTR query を送信できます（dq.md 参照）。
