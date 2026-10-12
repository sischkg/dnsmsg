# NS レコード（`RecordNS`）

NS レコード（TYPE=2、`TYPE_NS`）は、ゾーン（またはドメイン）に対する権威的な
ネームサーバ名を RDATA に持つ DNS リソースレコードです（RFC 1035 Section 4.1.2）。
RDATA は DNS 名（ドメイン名）であり、RDLENGTH は名前自身の wire format 長に
依存します（ルート単独なら 1 バイト、長すぎればパースに失敗し、上限は
255 バイト）。

## レコードの構造

| 項目 | 内容 |
|------|------|
| Name | ドメイン名（`DomainName`） |
| Class | `CLASS_IN` (1) |
| Type | `TYPE_NS` (2) |
| TTL | TTL（秒） |
| RDATA | 権威ネームサーバのドメイン名（RDLENGTH は名前の wire format 長。例: `ns1.example.com.` は 17） |

`RecordNS` の内部フィールド `nsname`（`DomainName`）は非エクスポートです。
パッケージの外からは `String()`（表示形式）または
`CanonicalWireFormat()`（wire format の byte 列）で取り出します
（index.md の「レコードデータの取り出し」の型アサーション例参照）。

## 主要な API

| API | 説明 |
|-----|------|
| `NewRecordNS(name DomainName) RecordNS` | `DomainName` から直接構築。エラーは返さない |
| `NewRecordNSFromString(n string) (RecordNS, error)` | 表示形式文字列から構築。`NewDomainNameFromString` によるパース（ラベル長・エスケープ等の規則は domainname.go 参照） |
| `ParseRecordNS(w WireFormat, begin uint32) (RecordNS, uint32, error)` | `w` の `begin` オフセットから（圧縮ポインタを含む）DNS 名をパース。成功時は終端オフセットを返す |
| `(RecordNS).Type() ResourceType` | `TYPE_NS` (2) |
| `(RecordNS).String() string` | 表示形式（`ns1.example.com` なら `"ns1.example.com."`。ルート単独は `"."`） |
| `(RecordNS).CanonicalWireFormat() []byte` | 名前の canonical wire format（RFC 4034: 小文字・非圧縮・末尾ゼロ 1 バイト） |
| `(RecordNS).AppendWireFormat(w *WireFormat, db *NameCompressionDB) uint32` | 名前を `w` に付加（`w.AppendDomainName` 経由）。`db` が nil でない場合、同じメッセージ内で先に出た共通接尾辞は圧縮ポインタに置換される |
| `(RecordNS).AppendCanonicalWireFormat(w *WireFormat) uint32` | canonical 形（小文字・非圧縮）を付加 |
| `(RecordNS).Size(w WireFormat, db *NameCompressionDB) uint32` | 常に 4 を返す定数メソッド。**`RDATA` インターフェースには含まれず**、本パッケージのシリアライズ処理でも使用されていない |

`RecordNS` は `RDATA` インターフェースを実装します。
`ParseResourceRecord` の `TYPE_NS` case で `rr.RData` には
`RecordNS`（値）が格納されます。

## 構築と表示

```go
ns, err := dnsmsg.NewRecordNSFromString("ns1.example.com")
// err == nil
fmt.Println(ns.String()) // "ns1.example.com."

// ルート単独（"" や "."）も合法なドメイン名
r, err := dnsmsg.NewRecordNSFromString("")
// err == nil
fmt.Println(r.String()) // "."（ルートは "." で表示される）
```

`NewRecordNSFromString` のエスケープ規則（実測確認済み）:

| 入力 | 結果 |
|------|------|
| `a\065bc` | 3 桁の**十進数**エスケープ（RFC 4343）。`065` は十進 65 で `'A'` になり、ラベル `aAbc`（`String()` は `"aAbc."`） |
| `a\.b` | エスケープド・ドットが**ラベル内の文字**。ラベル `a.b`（`String()` は `"a\.b."`） |

エラー一覧（実測確認済み）:

| 条件 | エラー |
|------|--------|
| 空ラベル（`a..b` など、ドット 2 連続） | `invalid domainname(empty label)` |
| 文字列末尾に孤立したバックスラッシュ（`a\` など） | `last character of a\ is \` |
| ラベルが 64 オクテット以上 | `domainname label is too long(length exceeds 63)` |
| wire format 長が 255 を超える（ラベル長 63 が 4 ラベル続くなど） | `domainname "..." is too long` |

ラベル長 63 オクテットは合法です（64 以上でエラー）。

## RDATA の直接パース（`ParseRecordNS`）

```go
wire := []byte{0x03, 'n', 's', '1',
    0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
    0x03, 'c', 'o', 'm', 0x00} // 合計 17 バイト「ns1.example.com」
ns, end, err := dnsmsg.ParseRecordNS(wire, 0)
// err == nil, end == 17
fmt.Println(ns.String()) // "ns1.example.com."
```

`NewDomainNameFromCompressedWireFormat` を通してパースするため、
圧縮ポインタ（`0xc0xx`）も受理します（round-trip の例参照）。

エラー一覧（実測確認済み）:

| 条件 | エラー |
|------|--------|
| ルートラベル（ゼロ 1 バイト）で終わらない | `invalid domainname(not terminated)` |
| `begin` オフセットが `w` の範囲外 | `out of bound in parsing domainname` |
| 圧縮ポインタが前方または範囲外を指す（例: 2 バイトメッセージでオフセット 48 を指す `c0 30`） | `out of bound in parsing domainname(compression offset: 48)` |

## レコード全体の round-trip（`ParseResourceRecord`、実測確認済み）

`www.example.com` の NS が `ns1.example.com` を指すレコードの
wire format の例（合計 33 バイト）:

```
03 77 77 77 07 65 78 61 6d 70 6c 65 03 63 6f 6d 00   ;; name = www.example.com (17 バイト)
00 02                                                ;; TYPE = NS (2)
00 01                                                ;; CLASS = IN (1)
00 00 01 2c                                          ;; TTL = 300
00 06                                                ;; RDLENGTH = 6
03 6e 73 31                                         ;; RDATA = 「ns1」（3 バイト）
c0 04                                               ;; + 圧縮ポインタ → オフセット 4（「example.com」）
```

RDATA の 6 バイトのうち末尾 2 バイト `c0 04` は圧縮ポインタ
（`0xc000 | 4`）です。

```go
wire := []byte{
    0x03, 'w', 'w', 'w', 0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x03, 'c', 'o', 'm', 0x00,
    0x00, 0x02, 0x00, 0x01, 0x00, 0x00, 0x01, 0x2c, 0x00, 0x06,
    0x03, 'n', 's', '1', 0xc0, 0x04,
}
rr, end, err := dnsmsg.ParseResourceRecord(wire, 0)
// err == nil, end == 33
// rr.Type == TYPE_NS, rr.Class == CLASS_IN, rr.TTL == 300
fmt.Println(rr.String()) // "www.example.com. 1 2 300 ns1.example.com."

rdata := rr.RData.(dnsmsg.RecordNS)
fmt.Println(rdata.String()) // "ns1.example.com."
```

## シリアライズ

### 圧縮なし（`db` = nil）

名前の全体（ラベル + 末尾ゼロ 1 バイト）が書き出されます
（`ns1.example.com` なら 17 バイト、実測確認済み）:

```
03 6e 73 31 07 65 78 61 6d 70 6c 65 03 63 6f 6d 00   ;; 「ns1.example.com」非圧縮
```

### 圧縮あり（`db` 非 nil）

`AppendWireFormat` は `w.AppendDomainName(nsname, db)` を呼び出します。
`db`（`NameCompressionDB`）はメッセージ単位で管理され、書き出された名前の
各接尾辞（`example.com` や `com` など）をオフセット付きで登録します。
その後の書き出しで同じ接尾辞を持つ名前が現れた場合、そのオフセットが
既にメッセージ内に書き出されていて 14 bit 以内
（`domainnameCompressionMaxOffset` = 16383 以下）なら、
ラベルの代わりに 2 バイトのポインタ（`0xc000 | offset`）が書かれます
（round-trip の例では `example.com` がオフセット 4 に登録済みのため `c0 04`）。

> **注**: 圧縮ポインタは単一メッセージ内でしか機能しません
> （`NameCompressionDB` はメッセージごとに新規作成します）。
> 先に出た名前を後から参照する順が逆の場合は、その接尾辞が未登録なので
> 非圧縮で書き出されます。

### canonical 形

`AppendCanonicalWireFormat` は RFC 4034 の canonical wire format
（小文字・非圧縮・末尾ゼロ 1 バイト）を書き出します（実測確認済み）。
例: `NS1.EXAMPLE.COM.` → 17 バイト

```
03 6e 73 31 07 65 78 61 6d 70 6c 65 03 63 6f 6d 00
```

## 補足

- `Size()` は常に 4 を返しますが、これは `RDATA` インターフェースに
  含まれず、本パッケージ内のシリアライズでは使用されていません。
  実際の RDLENGTH は `AppendWireFormat` の戻り値（＝名前の wire format 長）
  で決まります。
- `String()` はラベルを dot で繋いだ表示形式です。ルート単独の名前は
  `"."` になります。表示形式文字列を再度
  `NewRecordNSFromString`（＝`NewDomainNameFromString`）に渡すと、
  `""` と `.` の両方がルート単独として解析され、`String()` と
  round-trip します。
- `TYPE_NS` の `ParseResourceRecord` の case では `rr.RData` に
  `RecordNS` が格納されるため、`rr.RData.(dnsmsg.RecordNS)` で
  取り出せます（index.md の「レコードデータの取り出し」参照）。
