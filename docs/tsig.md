# TSIG による DNS メッセージの署名と検証

TSIG（Transaction SIGnature, RFC 8945）は、DNS メッセージに鍵ベースの
認証情報（HMAC-MAC）を付加し、送受信したメッセージの正当性を確認する仕組みです。
`dnsmsg` パッケージでは `Message.SignTSIG` でメッセージに TSIG レコードを署名し、
`Message.VerifyTSIG`（またはパッケージ関数 `VerifyTSIG`）で検証できます。

## TSIG レコードの構造

TSIG レコード（TYPE=250、`TYPE_TSIG`）は additional セクションに 1 本だけ
置かれ、かつそのセクションの**最後尾**でなければなりません。
RFC 8945 Section 4.2 に従い、CLASS は `CLASS_ANY` (255)、TTL は 0 です。

| フィールド | 内容 |
|------------|------|
| Name       | 鍵名（`DomainName`、鍵識別子。ドメイン名形式） |
| Class      | `CLASS_ANY` (255) |
| Type       | `TYPE_TSIG` (250) |
| TTL        | 0 |
| RDATA      | `RecordTSIG`（後述） |

`RecordTSIG` のフィールド:

| フィールド | 型 | 内容 |
|----------|----|------|
| `Algorithm` | `DomainName` | アルゴリズム名（例: `"hmac-sha256."`） |
| `TimeSigned` | `uint64` | 署名時刻（48 bit Unix 時間） |
| `Fudge` | `uint16` | 有効期限の猶予秒（TimeSigned 前後） |
| `MAC` | `[]byte` | HMAC 鍵認証コード（可変長、最大 65535 オクテット） |
| `OriginalID` | `uint16` | メッセージ ID（レスポンスではクエリの ID） |
| `Error` | `uint16` | TSIG エラー（`TSIGErrorNoError` 等） |
| `OtherData` | `[]byte` | 可変長データ（BADTIME 応答で現在時刻など） |

MAC Size / Other Len はワイヤフォーマット上の長さフィールドであり、
`RecordTSIG` には格納されません（長さは `len(MAC)` / `len(OtherData)` から導かれます）。

## 主要な API

| API | 説明 |
|-----|------|
| `NewTSIGKey(name DomainName, algorithm TSIGAlgorithm, secret []byte) (TSIGKey, error)` | 共有鍵を構築。`secret` は空でないこと、アルゴリズムは既知であること |
| `NewTSIGKeyFromString(name, algorithm, secret string) (TSIGKey, error)` | `secret` を base64（パディングなし）プレゼンテーション形式から復号して鍵を構築 |
| `(TSIGKey).MAC(data []byte) ([]byte, error)` | データの鍵認証コードを算出（`MACLen` で切り詰め） |
| `Message.SignTSIG(key TSIGKey, opts *TSIGOptions) (ResourceRecord, error)` | メッセージに TSIG レコードを署名し、`ResourceRecord` を返す。メッセージ自体は変更しない |
| `Message.VerifyTSIG(key TSIGKey, opts *TSIGVerifyOptions) error` | メッセージの TSIG レコードを検証。成功なら nil |
| `VerifyTSIG(w WireFormat, key TSIGKey, opts *TSIGVerifyOptions) error` | ワイヤフォーマットの生メッセージを検証（パッケージ関数） |
| `NewUnsignedTSIGResponse(...) (ResourceRecord, error)` | MAC なしの TSIG エラー応答レコード（BADKEY / BADTIME 等）を作る |

### TSIGOptions（署名用）

| フィールド | 型 | 内容 |
|----------|----|------|
| `TimeSigned` | `time.Time` | 署名時刻。ゼロ値なら現在時刻 |
| `Fudge` | `uint16` | 猶予秒。ゼロなら `TSIGDefaultFudge` (300 秒) |
| `Error` | `uint16` | TSIG エラー。通常は `TSIGErrorNoError` |
| `OtherData` | `[]byte` | 可変長データ（BADTIME 応答など） |
| `RequestMAC` | `[]byte` | レスポンス署名時に含めるリクエストの MAC（リクエスト署名時は空） |
| `TimersOnly` | `bool` | `true` なら TSIG Timers のみで署名（3 番目以降のマルチメッセージ応答） |

### TSIGVerifyOptions（検証用）

| フィールド | 型 | 内容 |
|----------|----|------|
| `RequestMAC` | `[]byte` | レスポンス検証時に含めるリクエストの MAC（リクエスト検証時は空） |
| `TimersOnly` | `bool` | `true` なら TSIG Timers のみで検証 |
| `Now` | `time.Time` | 時刻チェックの基準。ゼロ値なら現在時刻 |

### TSIGAlgorithm（アルゴリズム名）

| 定数 | 文字列 | 説明 |
|------|--------|------|
| `TSIGAlgHMACMD5` | `"HMAC-MD5.SIG-ALG.REG.INT."` | HMAC-MD5（RFC 2104 / RFC 8945） |
| `TSIGAlgHMACSHA1` | `"hmac-sha1."` | HMAC-SHA1 |
| `TSIGAlgHMACSHA224` | `"hmac-sha224."` | HMAC-SHA224 |
| `TSIGAlgHMACSHA256` | `"hmac-sha256."` | HMAC-SHA256 |
| `TSIGAlgHMACSHA256_128` | `"hmac-sha256-128."` | HMAC-SHA256（MAC 128 bit 短縮） |
| `TSIGAlgHMACSHA384` | `"hmac-sha384."` | HMAC-SHA384 |
| `TSIGAlgHMACSHA384_192` | `"hmac-sha384-192."` | HMAC-SHA384（MAC 192 bit 短縮） |
| `TSIGAlgHMACSHA512` | `"hmac-sha512."` | HMAC-SHA512 |
| `TSIGAlgHMACSHA512_256` | `"hmac-sha512-256."` | HMAC-SHA512（MAC 256 bit 短縮） |

`TSIGDefaultFudge` は 300（5 分）です。

### TSIG エラー定数（`record-tsig.go`）

| 定数 | 値 | 名前 |
|------|-----|------|
| `TSIGErrorNoError` | 0 | NOERROR |
| `TSIGErrorBadSig` | 16 | BADSIG |
| `TSIGErrorBadKey` | 17 | BADKEY |
| `TSIGErrorBadTime` | 18 | BADTIME |
| `TSIGErrorBadMode` | 19 | BADMODE |
| `TSIGErrorBadName` | 20 | BADNAME |
| `TSIGErrorBadAlg` | 21 | BADALG |
| `TSIGErrorBadTrunc` | 22 | BADTRUNC |

`TSIGErrorString(e uint16) string` で定数値から名前を取得できます。
未知の値は `"ERROR<n>"` 形式で返します。

## クエリメッセージへの署名と検証

### 1) クエリメッセージを構築して署名する

```go
package main

import (
	"fmt"
	"log"

	"github.com/sischkg/dnsmsg"
)

func main() {
	// 共有鍵（name / algorithm / base64 secret）
	key, err := dnsmsg.NewTSIGKeyFromString(
		"tsig-key.example.",
		"hmac-sha256.",
		"aaaa", // base64（パディングなし）でエンコードされた秘密鍵
	)
	if err != nil {
		log.Fatal(err)
	}

	// クエリメッセージの構築
	var msg dnsmsg.Message
	msg.ID = 0xC0DE
	msg.QR = dnsmsg.QRQuery
	msg.QDCOUNT = 1
	msg.QuestionSection = []dnsmsg.QuestionSectionEntry{
		{
			QName:  testDomainName, // 実際は dnsmsg.NewDomainNameFromString("example.com.")
			Class:  dnsmsg.CLASS_IN,
			Type:   dnsmsg.TYPE_A,
		},
	}

	// 2) TSIG 署名（msg 自体は変更されない）
	rr, err := msg.SignTSIG(key, &dnsmsg.TSIGOptions{})
	if err != nil {
		log.Fatal(err)
	}

	// 3) 送信用に additional セクションに追加し ARCOUNT++ する
	msg.AdditionalSection = append(msg.AdditionalSection, rr)
	msg.ARCOUNT++

	// 4) wire format にシリアライズして送信
	var w dnsmsg.WireFormat
	w.WriteWireFormat(msg)
	// w をソケットなどで送信
	_ = w
}
```

`SignTSIG` は `msg` の内容を変更しません。戻り値の `ResourceRecord` を
`AdditionalSection` に追加し、`ARCOUNT` を 1 増やした上で
`WriteWireFormat` して送信します。

### 2) 受信側でメッセージを検証する

```go
// w は受信した wire format（[]byte）
msg, err := dnsmsg.ParseWireFormat(w)
if err != nil {
    log.Fatal(err)
}

// Message.VerifyTSIG で検証（RequestMAC はリクエスト検証時は nil で可）
err = msg.VerifyTSIG(key, &dnsmsg.TSIGVerifyOptions{})
if err != nil {
    // *dnsmsg.TSIGVerifyError としてエラー詳細を取得可能
    if verr, ok := err.(*dnsmsg.TSIGVerifyError); ok {
        log.Printf("TSIG error: %s (RCODE %d)", dnsmsg.TSIGErrorString(verr.TSIGError), verr.RCODE)
    }
    log.Fatal(err)
}
fmt.Println("TSIG verified OK")
```

`*TSIGVerifyError` には `TSIGError`（TSJ エラーコード）、`RCODE`（DNS エラーコード）、
`OtherData`（BADTIME 応答用の現在時刻など）、`Reason`（理由文字列）が含まれます。

## レスポンスメッセージへの署名と検証（RequestMAC）

レスポンスを署名する場合、`TSIGOptions.RequestMAC` にリクエストメッセージの
TSIG MAC を含めます。これにより、レスポンスが対応するリクエストに対する
ものであることを証明できます。

```go
// クエリを署名
reqRR, err := query.SignTSIG(key, &dnsmsg.TSIGOptions{})
reqTSIG := reqRR.RData.(dnsmsg.RecordTSIG)
query.AdditionalSection = append(query.AdditionalSection, reqRR)
query.ARCOUNT++

// レスポンスを署名（RequestMAC にクエリの TSIG MAC を渡す）
resp := dnsmsg.Message{
    ID: query.ID,
    QR: dnsmsg.QRResponse,
    RA: 1,
    // ... question / answer セクションを設定 ...
}
respRR, err := resp.SignTSIG(key, &dnsmsg.TSIGOptions{
    RequestMAC: reqTSIG.MAC,
})
resp.AdditionalSection = append(resp.AdditionalSection, respRR)
resp.ARCOUNT++

// 受信側では RequestMAC を指定して検証
err = resp.VerifyTSIG(key, &dnsmsg.TSIGVerifyOptions{
    RequestMAC: reqTSIG.MAC,
})
```

## 対応アルゴリズムと MAC 長

`TSIGOptions.MACLen`（`TSIGKey.MACLen`）で MAC 長を指定できます。
ゼロならアルゴリズムが許容する最長の MAC を使います。

短縮アルゴリズム（`hmac-sha256-128` 等）を使う場合は `MACLen` を
明示的に短縮後の長さに設定してください（省略するとフル長の MAC が
生成され、検証側で「MAC が長すぎる」エラーになります）。

```go
key.MACLen = key.Algorithm.MACLen() // 短縮アルゴリズムでもフル長を使う場合
// または
key.MACLen = 16 // hmac-sha256-128 などの短縮長
```

## エラーと検証順序

`Message.VerifyTSIG`（および `VerifyTSIG`）は RFC 8945 Section 5.2 の順序で
チェックします。失敗時は `*TSIGVerifyError` を返します。

| チェック順 | 内容 | エラー |
|-----------|------|--------|
| 1 | TSIG レコードの存在・位置（additional セクションの最後尾） | form error（RCODE 1）または「no TSIG record」 |
| 2 | 鍵名・アルゴリズムの一致 | BADKEY（RCODE 9） |
| 3 | MAC 長の妥当性 | form error（RCODE 1） |
| 4 | MAC の一致 | BADSIG（RCODE 9） |
| 5 | レスポンス時のエラーフィールド | ピア報告エラー（RCODE 9） |
| 6 | 時刻（TimeSigned ± Fudge） | BADTIME（RCODE 9） |
| 7 | MAC 長ポリシー（MinMACLen） | BADTRUNC（RCODE 9） |

`OtherData` は BADTIME 応答時に検証側の現在時刻（48 bit）を格納して返されます。

## TSIG レコードの直接構築と解析

`RecordTSIG` は `NewRecordTSIG` で直接構築し、`String()` / `NewRecordTSIGFromString`
でプレゼンテーション形式との相互変換ができます。

```go
// wire format への直接追加（上級者向け）
r, err := dnsmsg.NewRecordTSIG(
    dnsmsg.NewDomainNameFromString("hmac-sha256."), // algorithm
    1700000000,                                      // TimeSigned
    300,                                             // Fudge
    mac,                                             // MAC（[]byte）
    msg.ID,                                          // OriginalID
    dnsmsg.TSIGErrorNoError,                         // Error
    nil,                                             // OtherData
)

// プレゼンテーション形式
s := r.String() // "hmac-sha256. 1700000000 300 <base64> <id> NOERROR [<hex>]"
r2, err := dnsmsg.NewRecordTSIGFromString(s)
```

## 補足

- `SignTSIG` はメッセージを変更しません。戻り値の `ResourceRecord` を
  `AdditionalSection` に追加し、`ARCOUNT` を増やすのは呼び出し側の責任です。
- TSIG レコードは additional セクションに **1 本**しか置けず、**最後尾**
  でなければなりません（複数あると検証エラーになります）。
- `Message.VerifyTSIG` は構造化された `Message` に対して検証します。
  生の wire format から直接検証したい場合はパッケージ関数
  `VerifyTSIG(wire, key, opts)` を使います。
- 鍵の秘密鍵（`TSIGKey.Secret`）は平文で扱われるため、取り扱いに注意してください。
- 正規形（canonical、圧縮なし・小文字ドメイン名）のシリアライズは
  `RecordTSIG.AppendCanonicalWireFormat` / `CanonicalWireFormat` で取得できます。

## 関連リンク

- [index.md](index.md) — パッケージ概要
- [RFC 8945](https://datatracker.ietf.org/doc/html/rfc8945) — Secret Key Transaction Authentication for DNS (TSIG)
- [RFC 2104](https://datatracker.ietf.org/doc/html/rfc2104) — HMAC: Keyed-Hashing for Message Authentication
