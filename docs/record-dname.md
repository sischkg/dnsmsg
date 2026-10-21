# DNAME レコード（`RecordDNAME`）

DNAME レコード（TYPE=39、`TYPE_DNAME`）は、オーナー名配下の名前サブツリーを
別のドメイン名（ターゲット）に委任（リダイレクト）する DNS リソースレコードです
（RFC 6672 Section 4）。CNAME がオーナー名 1 本の別名であるのに対し、DNAME は
オーナー名を含む名前全体がターゲット配下にマップされます（ゾーン運用では
`sub.example.com` 配下を `other.example.com` 配下へ丸ごと移す、といった用途に
使います）。RDATA は DNS 名（ドメイン名）であり、RDLENGTH は名前自身の
wire format 長に依存します（ルート単独なら 1 バイト、名前の wire format が
255 バイトを超えると構築・パースに失敗する）。

## レコードの構造

| 項目 | 内容 |
|------|------|
| Name | サブツリーの委任元となるドメイン名（`DomainName`） |
| Class | `CLASS_IN` (1) |
| Type | `TYPE_DNAME` (39) |
| TTL | TTL（秒） |
| RDATA | 委任先のターゲット名のドメイン名（RDLENGTH は名前の wire format 長。例: `www.example.com.` は非圧縮で 17 バイト、同一メッセージ内で先に `example.com` が出ていれば 6 バイト） |

`RecordDNAME` の中身フィールド `DNAME`（`DomainName`）はエクスポート済みです
（`RecordCNAME` と同じく、パッケージの外から `rdata.DNAME` で直接読める）。

## 主要な API

| API | 説明 |
|-----|------|
| `NewRecordDNAME(dname DomainName) RecordDNAME` | `DomainName` から直接構築。エラーは返さない |
| `NewRecordDNAMEFromString(s string) (RecordDNAME, error)` | 表示形式文字列から構築。`NewDomainNameFromString` によるパース（ラベル長・エスケープ等の規則は domainname.go 参照） |
| `ParseRecordDNAME(w WireFormat, begin uint32) (RecordDNAME, uint32, error)` | `w` の `begin` オフセットから（圧縮ポインタを含む）DNS 名をパース。成功時は終端オフセットを返す。ドメイン名パースのエラーは `cannot parse dname: ` の接頭辞で包まれる |
| `(RecordDNAME).Type() ResourceType` | `TYPE_DNAME` (39) |
| `(RecordDNAME).String() string` | 表示形式（`www.example.com` なら `"www.example.com."`。ルート単独は `"."`） |
| `(RecordDNAME).CanonicalWireFormat() []byte` | 名前の canonical wire format（RFC 4034: 小文字・非圧縮・末尾ゼロ 1 バイト） |
| `(RecordDNAME).AppendWireFormat(w *WireFormat, db *NameCompressionDB) uint32` | 名前を `w` に付加（`w.AppendDomainName` 経由）。`db` が nil でない場合、同じメッセージ内で先に出た共通接尾辞は圧縮ポインタに置換される |
| `(RecordDNAME).AppendCanonicalWireFormat(w *WireFormat) uint32` | canonical 形（小文字・非圧縮）を付加 |

`RecordDNAME` は `RDATA` インターフェースを実装します。
`ParseResourceRecord` の `TYPE_DNAME` case で `rr.RData` には
`RecordDNAME`（値）が格納されます。

## 構築と表示

```go
dname, err := dnsmsg.NewRecordDNAMEFromString("www.example.com")
// err == nil
fmt.Println(dname.String()) // "www.example.com."

// ルート単独（"" や "."）も合法なドメイン名
r, err := dnsmsg.NewRecordDNAMEFromString("")
// err == nil
fmt.Println(r.String()) // "."
```

エスケープ規則（3 桁の十進数エスケープ、`\.` はラベル内の文字）と
ラベル長 63 オクテットまで合法、という規則は NS と同一です
（[record-ns.md](record-ns.md) 参照。実測確認済み）。

`NewRecordDNAMEFromString` のエラー一覧（実測確認済み）:

| 条件 | エラー |
|------|--------|
| 空ラベル（`a..b` など、ドット 2 連続） | `invalid domainname(empty label)` |
| 文字列末尾に孤立したバックスラッシュ（`a\` など） | `last character of a\ is \` |

## RDATA の直接パース（`ParseRecordDNAME`）

```go
wire := []byte{0x03, 'w', 'w', 'w',
    0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
    0x03, 'c', 'o', 'm', 0x00} // 合計 17 バイト「www.example.com」
dname, end, err := dnsmsg.ParseRecordDNAME(wire, 0)
// err == nil, end == 17
fmt.Println(dname.String()) // "www.example.com."
```

`NewDomainNameFromCompressedWireFormat` を通してパースするため、
圧縮ポインタ（`0xc0xx`）も受理します。

エラー一覧（実測確認済み。`ParseRecordDNAME` はドメイン名パースの
エラーを `cannot parse dname: ` の接頭辞で包んで返します）:

| 条件 | エラー |
|------|--------|
| ルートラベル（ゼロ 1 バイト）で終わらない | `cannot parse dname: invalid domainname(not terminated)` |
| `begin` オフセットが `w` の範囲外 | `cannot parse dname: out of bound in parsing domainname` |
| 圧縮ポインタが前方または範囲外を指す（例: 2 バイトメッセージでオフセット 48 を指す `c0 30`） | `cannot parse dname: out of bound in parsing domainname(compression offset: 48)` |

## レコード全体の round-trip（`ParseResourceRecord`、実測確認済み）

`sub.example.com` の DNAME が `www.example.com` を指すレコードの
wire format の例（合計 33 バイト）:

```
03 73 75 62 07 65 78 61 6d 70 6c 65 03 63 6f 6d 00   ;; name = sub.example.com (17 バイト)
00 27                                                ;; TYPE = DNAME (39)
00 01                                                ;; CLASS = IN (1)
00 00 01 2c                                          ;; TTL = 300
00 06                                                ;; RDLENGTH = 6
03 77 77 77                                          ;; RDATA = 「www」（3 バイト）
c0 04                                                ;; + 圧縮ポインタ → オフセット 4（「example.com」）
```

RDATA の 6 バイトのうち末尾 2 バイト `c0 04` は圧縮ポインタ
（`0xc000 | 4`。オーナー名の中で `example.com` が書き出されたオフセット 4 を
指す）。

```go
wire := []byte{
    0x03, 's', 'u', 'b', 0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x03, 'c', 'o', 'm', 0x00,
    0x00, 0x27, 0x00, 0x01, 0x00, 0x00, 0x01, 0x2c, 0x00, 0x06,
    0x03, 'w', 'w', 'w', 0xc0, 0x04,
}
rr, end, err := dnsmsg.ParseResourceRecord(wire, 0)
// err == nil, end == 33
// rr.Type == TYPE_DNAME, rr.Class == CLASS_IN, rr.TTL == 300
fmt.Println(rr.String()) // "sub.example.com. 1 39 300 www.example.com."

rdata := rr.RData.(dnsmsg.RecordDNAME)
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

`AppendWireFormat` は `w.AppendDomainName(dname, db)` を呼び出します。
圧縮の規則（`NameCompressionDB` への接尾辞登録、14 bit のオフセット制限、
メッセージ単位でしか機能しない）は NS と同一です（[record-ns.md](record-ns.md)
参照）。

`AppendResourceRecord` が上記のレコードから作る wire format は、上の
手書き例と完全に一致します（実測確認済み、33 バイト）:

```
03 73 75 62 07 65 78 61 6d 70 6c 65 03 63 6f 6d 00 00 27 00 01 00 00 01 2c 00 06 03 77 77 77 c0 04
```

### canonical 形

`AppendCanonicalWireFormat` は RFC 4034 の canonical wire format
（小文字・非圧縮・末尾ゼロ 1 バイト）を書き出します（実測確認済み）。
例: `WWW.EXAMPLE.COM.` → 17 バイト

```
03 77 77 77 07 65 78 61 6d 70 6c 65 03 63 6f 6d 00
```

## JSON

`RecordDNAME` は `MarshalJSON` / `UnmarshalJSON` を持ちます。ターゲット名は
表示形式文字列としてエンコードされます（実測確認済み）:

```go
json.Marshal(dname)
// {"DNAME":"www.example.com."}

json.Marshal(rr) // rr.Type == TYPE_DNAME の場合
// {"Class":"IN","Name":"sub.example.com.","RData":{"DNAME":"www.example.com."},"TTL":300,"Type":"DNAME"}
```

`ResourceRecord.UnmarshalJSON` は `Type` が `"DNAME"`（または 39）のとき
`RData` を `RecordDNAME` としてデコードします。不正な表示形式文字列
（`"a..b."` など）はエラーになります。

## 補足

- DNAME の RDATA は NS・CNAME と同一の形（単一のドメイン名）です。圧縮
  ポインタの扱い、canonical 形、ドメイン名の規則の詳細は
  [record-ns.md](record-ns.md) を参照してください。
- `TYPE_DNAME` の `ParseResourceRecord` の case では `rr.RData` に
  `RecordDNAME` が格納されるため、`rr.RData.(dnsmsg.RecordDNAME)` で
  取り出せます（index.md の「レコードデータの取り出し」参照）。
- CNAME と違い DNAME はサブツリー全体の委任です。解決 semantics（オーナー名
  配下の名前がターゲット配下にマップされる、CNAME と同一オーナー名に DNAME
  と CNAME を共存させない、等）は RFC 6672 が定めており、このライブラリは
  レコードの読み書きのみを担当します。
- `dq` コマンドでも `-t DNAME` で DNAME query を送信できます（`dq.md` 参照）。
