# TKEY レコード（`RecordTKEY`）

TKEY レコード（TYPE=249、`TYPE_TKEY`）は、DNS メッセージ上でセッション鍵
（トランザクション鍵）を negotiate するためのメタ RR です（RFC 2930）。
TSIG が共有secret鍵によるメッセージ認証であるのに対し、TKEY は GSS-API や
Diffie-Hellman 交換などを使って通信のたびに鍵を作成・破棄する用途に使います。

TKEY はゾーンには保存されずキャッシュもされないメタ RR で、Query・Response
それぞれに 1 本しか含めてはなりません（RFC 2930 Section 3）。
CLASS は無視され `CLASS_ANY` (255) であるべきで、TTL は無意味で 0 であるべきです。
このライブラリはレコードの読み書きのみを担当し、鍵 exchange のプロトコル処理は
行いません。

## レコードの構造

| 項目 | 内容 |
|------|------|
| Name | 通常はルート名 `.`（RFC 2930 Section 2） |
| Class | `CLASS_ANY` (255)（無視される。`CLASS_IN` でも解析はできる） |
| Type | `TYPE_TKEY` (249) |
| TTL | 0（ older implementations にキャッシュさせないため） |
| RDATA | 下記のフィールド列（RDLENGTH はアルゴリズム名と鍵データの長さに依存） |

`RecordTKEY` のフィールド:

| フィールド | 型 | 内容 |
|----------|----|------|
| `Algorithm` | `DomainName` | アルゴリズム名（例: `"gss-api."`）。wire format 上は常に非圧縮（RFC 3597 Section 4） |
| `Inception` | `uint32` | 鍵の有効開始時刻（Unix 時間） |
| `Expiration` | `uint32` | 鍵の有効終了時刻（Unix 時間） |
| `Mode` | `uint16` | 鍵 negotiated mode（`TKEYModeServerAssignment` 等） |
| `Error` | `uint16` | エラーコード（`TKEYErrorNoError` 等。TSIG のエラーコードと同一の値） |
| `KeyData` | `[]byte` | 鍵データ（可変長、最大 65535 オクテット） |
| `OtherData` | `[]byte` | アルゴリズム依存の追加データ（可変長、最大 65535 オクテット） |

Key Size / Other Size はワイヤフォーマット上の長さフィールドであり、
`RecordTKEY` には格納されません（長さは `len(KeyData)` / `len(OtherData)` から導かれます）。

### Mode（RFC 2930 Section 2.5）

| 定数 | 値 | 意味 |
|------|----|------|
| `TKEYModeReserved` | 0 | reserved（名前はない。数値で表示される） |
| `TKEYModeServerAssignment` | 1 | サーバーが鍵を割り当てる |
| `TKEYModeDHExchange` | 2 | Diffie-Hellman 交換 |
| `TKEYModeGSSAPI` | 3 | GSS-API |
| `TKEYModeResolverAssignment` | 4 | resolver が鍵を割り当てる |
| `TKEYModeKeyDeletion` | 5 | 鍵の削除 |

未割り当ての数値（6 以上、65535 など）もそのまま保持・表示できます。

### Error（RFC 2930 Section 2.6）

| 定数 | 値 | 名前 |
|------|----|------|
| `TKEYErrorNoError` | 0 | `NOERROR` |
| `TKEYErrorFormErr` | 1 | `FORMERR` |
| `TKEYErrorServFail` | 2 | `SERVFAIL` |
| `TKEYErrorNameError` | 3 | `NXDOMAIN` |
| `TKEYErrorNotImpl` | 4 | `NOTIMP` |
| `TKEYErrorRefused` | 5 | `REFUSED` |
| `TKEYErrorBadSig` | 16 | `BADSIG` |
| `TKEYErrorBadKey` | 17 | `BADKEY` |
| `TKEYErrorBadTime` | 18 | `BADTIME` |
| `TKEYErrorBadMode` | 19 | `BADMODE` |
| `TKEYErrorBadName` | 20 | `BADNAME` |
| `TKEYErrorBadAlg` | 21 | `BADALG` |

名前のないコードは `ERROR<number>`（例: `ERROR99`）として表示され、
その文字列はそのまま読み戻せます。

## 主要な API

| API | 説明 |
|-----|------|
| `NewRecordTKEY(algorithm DomainName, inception, expiration uint32, mode, tkeyError uint16, keyData, otherData []byte) (RecordTKEY, error)` | フィールドから直接構築。`keyData` / `otherData` が 65535 オクテットを超えるとエラー |
| `NewRecordTKEYFromString(s string) (RecordTKEY, error)` | 表示形式文字列から構築（後述） |
| `ParseRecordTKEY(w WireFormat, begin, end uint32) (RecordTKEY, uint32, error)` | `w` の `begin` から `end`（RDLENGTH の終端）までの RDATA をパース |
| `TKEYModeString(m uint16) string` | mode を名前（または数値）で表示 |
| `NewTKEYMode(s string) (uint16, error)` | mode 名または数値を値に変換 |
| `TKEYErrorString(e uint16) string` | エラーコードを名前で表示（未知名は `ERROR<n>`） |
| `NewTKEYError(s string) (uint16, error)` | 名前・`ERROR<n>`・数値を値に変換 |
| `(RecordTKEY).Type() ResourceType` | `TYPE_TKEY` (249) |
| `(RecordTKEY).String() string` | 表示形式（後述） |
| `(RecordTKEY).CanonicalWireFormat() []byte` | canonical wire format（アルゴリズム名を小文字・非圧縮） |
| `(RecordTKEY).AppendWireFormat(w *WireFormat, db *NameCompressionDB) uint32` | RDATA を `w` に付加。アルゴリズム名は RFC 3597 Section 4 に従い `db` を使わず常にフルに書き出す |
| `(RecordTKEY).AppendCanonicalWireFormat(w *WireFormat) uint32` | canonical 形を付加 |

`RecordTKEY` は `RDATA` インターフェースを実装します。
`ParseResourceRecord` の `TYPE_TKEY` case で `rr.RData` には
`RecordTKEY`（値）が格納されます。

## 表示形式

RFC 2930 は master file に現れないため表示形式を定義していません。
このパッケージは TSIG と同じ流儀で次の形式を使い、`NewRecordTKEYFromString` は
同じ形式を読み戻します（mode と error は名前でも数値でも受理）。

```
<algorithm> <inception> <expiration> <mode> <error> <base64-key>[ <base64-other>]
```

```go
r, err := dnsmsg.NewRecordTKEYFromString(
    "gss-api. 1700000000 1700001280 SERVER-ASSIGNMENT NOERROR qrvM3Q")
// err == nil
fmt.Println(r.String())
// "gss-api. 1700000000 1700001280 SERVER-ASSIGNMENT NOERROR qrvM3Q"

// mode・error は数値でも書ける（RESOLVER-ASSIGNMENT / BADNAME になる）
r, err := dnsmsg.NewRecordTKEYFromString(". 0 0 4 20 ESI 3q2+")
fmt.Println(r.String()) // ". 0 0 RESOLVER-ASSIGNMENT BADNAME ESI 3q2+"
```

Other data は空でないときだけ末尾に追加されます。
未割り当ての mode は数値、未知名の error は `ERROR<n>` で表示されます
（例: `" . 0 0 63934 ERROR99 "`）。

## RDATA の直接パース（`ParseRecordTKEY`）

```go
rdata := []byte{
    0x07, 'g', 's', 's', '-', 'a', 'p', 'i', 0x00, // algorithm = "gss-api."
    0x65, 0x53, 0xF1, 0x00,                         // inception  = 1700000000
    0x65, 0x53, 0xF6, 0x00,                         // expiration = 1700001280
    0x00, 0x01,                                     // mode       = SERVER-ASSIGNMENT
    0x00, 0x00,                                     // error      = NOERROR
    0x00, 0x04, 0xAA, 0xBB, 0xCC, 0xDD,            // key size   = 4, key data
    0x00, 0x00,                                     // other size = 0
}
r, end, err := dnsmsg.ParseRecordTKEY(rdata, 0, uint32(len(rdata)))
// err == nil, end == 29
```

`ParseRecordTKEY` は `end`（ enclosing RR の RDLENGTH の終端）までの長さを
厳密に検査します。エラー一覧（テストで確認済み）:

| 条件 | エラー |
|------|--------|
| `end` がメッセージの末尾を超える | `invalid TKEY record RDATA size` |
| RDATA が最短長（ルート名 + 4 + 4 + 2 + 2 + 2 +2 バイト）に満たない | `not enough size for TKEY record` |
| アルゴリズム名のパースに失敗 | `cannot parse algorithm name: ` prefix |
| Key Size / Other Size が残り RDATA を超える | `TKEY key data exceeds RDATA` / `TKEY other data exceeds RDATA` |
| フィールドが `end` に到達せずに終わる | `TKEY record does not fill its RDATA` |

アルゴリズム名は圧縮ポインタ展开付きで読みます（RFC 3597 Section 4 は
TKEY の圧縮ポインタを禁止していますが、乱れた入力を読むため受理します）。

## レコード全体の round-trip（`ParseResourceRecord`、テストで確認済み）

`gss-api.` mode SERVER-ASSIGNMENT の TKEY をもつレコードの wire format の例
（合計 54 バイト、Name はルート）:

```
00                                                 ;; name = .（1 バイト）
00 f9                                              ;; TYPE = TKEY (249)
00 ff                                              ;; CLASS = ANY (255)
00 00 00 00                                        ;; TTL = 0
00 1d                                              ;; RDLENGTH = 29
07 67 73 73 2d 61 70 69 00                        ;; algorithm = "gss-api."（非圧縮）
65 53 f1 00 65 53 f6 00                            ;; inception, expiration
00 01 00 00                                        ;; mode = 1, error = 0
00 04 aa bb cc dd                                  ;; key size = 4, key data
00 03 de ad be                                     ;; other size = 3, other data
```

```go
rr, pos, err := dnsmsg.ParseResourceRecord(wire, 0)
// err == nil, pos == 54
// rr.Type == TYPE_TKEY, rr.Class == CLASS_ANY, rr.TTL == 0

tkey := rr.RData.(dnsmsg.RecordTKEY)
fmt.Println(tkey.String())
// "gss-api. 1700000000 1700001280 SERVER-ASSIGNMENT NOERROR qrvM3Q 3q2+"
```

`TYPE_TKEY.String()` は `"TKEY"`、`NewType("TKEY")` は `TYPE_TKEY` (249) を
返します（テストで確認済み）。

## シリアライズ

`AppendWireFormat` はアルゴリズム名を `db` に関係なく常にフルで書き出します
（RFC 3597 Section 4。テストでは無関係な名前を圧縮 DB に登録しても
アルゴリズム名が圧縮されないことを確認しています）。

canonical 形（`AppendCanonicalWireFormat` / `CanonicalWireFormat`）は
RFC 4034 に従いアルゴリズム名を小文字・非圧縮で書き出します
（`GSS-API.Example.` → `gss-api.example.`。テストで確認済み）。

## JSON

`RecordTKEY` は `MarshalJSON` / `UnmarshalJSON` を持ちます。
mode と error は名前でエンコードされ、key data と other data は base64
（RFC 4648、パディングなし）です（テストで確認済み）:

```go
json.Marshal(tkey)
// {"Algorithm":"gss-api.","Error":"BADALG","Expiration":1700001280,
//  "Inception":1700000000,"KeyData":"qrvM3Q","Mode":"GSS-API","OtherData":"3q2+"}
```

`ResourceRecord.UnmarshalJSON` は `Type` が `"TKEY"`（または 249）のとき
`RData` を `RecordTKEY` としてデコードします。デコード時は mode と error は
名前でも数値でも受理し、`Mode` / `Error` / `OtherData` が欠落していれば
それぞれ 0（reserved / NOERROR）として扱います。

## 補足

- TKEY は authority セクションに置くことが推奨されます（RFC 2930 Section 3）。
  このライブラリはセクションの配置自体は強制しません。
- RFC 2930 Section 4.5 の鍵の破棄は、mode を `TKEYModeKeyDeletion`、
  expiration を現在時刻（RFC は 0 也可以とする）にした TKEY を送って行います。
- DNSSEC の RRSet 署名・検証や `Zone` の運用には使いません（ゾーンに
  保存されないメタ RR のため）。
- TSIG による message authentication は [tsig.md](tsig.md) を参照してください。
