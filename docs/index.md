# dnsmsg パッケージドキュメント

`dnsmsg` は DNS メッセージの wire format（RFC 1035）を解析・シリアライズするための
Go ライブラリです。外部依存を持たず、標準ライブラリのみで実装されています。

## 機能

- DNS メッセージ（ヘッダ + Question / Answer / Authority / Additional セクション）の
  wire format へのシリアライズとパース
- ドメイン名の表現（`DomainName` / `Label`）と wire format への読み書き
- RFC 1035 の名前圧縮（compression pointer）への対応（`NameCompressionDB` による管理）
- RFC 4034 スタイルの正規形（canonical）wire format（圧縮なし・小文字ドメイン名）
- EDNS(0) / OPT レコード（RFC 6891）と EDNS option の取り扱い:
  - DNSSEC（DO, RFC 3225）
  - NSID（RFC 7873）
  - Extended DNS Errors / EDE（RFC 8914）
  - 未定義オプショコードの生データ保持（`EDNSOptionRaw`）および
    カスタムパーサの登録（`RegisterEDNSOptionParser`）
- UDP / TCP による DNS クエリ送信（`SendQuery`）

## サポートするレコードタイプ

`ParseResourceRecord` により、以下のタイプの RDATA は型付きのレコード構造体として
取得できます。それ以外のタイプは生バイト列として `RecordRaw` に格納されます。

| タイプ   | 定数             | レコード型     |
|----------|------------------|----------------|
| A        | `TYPE_A` (1)     | `RecordA`      |
| NS       | `TYPE_NS` (2)    | `RecordNS`     |
| SOA      | `TYPE_SOA` (6)   | `RecordSOA`    |
| MX       | `TYPE_MX` (15)   | `RecordMX`     |
| AAAA     | `TYPE_AAAA` (28) | `RecordAAAA`   |
| OPT      | `TYPE_OPT` (41)  | `RecordOPT`（[edns.md](edns.md) 参照） |
| DS       | `TYPE_DS` (43)   | `RecordDS`     |
| RRSIG    | `TYPE_RRSIG` (46)| `RecordRRSIG`  |
| DNSKEY   | `TYPE_DNSKEY` (48)| `RecordDNSKEY` |

## ドキュメント目次

| ファイル | 内容 |
|----------|------|
| [index.md](index.md) | 本ページ。パッケージの概要、クイックスタート、主要な型の一覧 |
| [edns.md](edns.md) | EDNS(0) / OPT レコード、EDNS option（DO・NSID・EDE・生データ）、カスタムパーサの登録 |

## クイックスタート

### クエリメッセージの構築と送信

`example.com.` の A レコードを再帰的に問い合わせるメッセージを構築し、
UDP でネームサーバに送信する例です。

```go
package main

import (
	"fmt"
	"log"

	"github.com/sischkg/dnsmsg"
)

func main() {
	// 1) クエリメッセージの構築
	var query dnsmsg.Message
	query.ID = 0x1234
	query.QR = dnsmsg.QRQuery // QR ビット（0: クエリ）
	query.OPCODE = dnsmsg.QpcodeQuery // OPCODE: standard query
	query.RD = 1                    // Recursion Desired

	// Question セクションを設定（QDCOUNT も 1 に）
	if err := query.SetQuery("www.example.com.", dnsmsg.CLASS_IN, dnsmsg.TYPE_A); err != nil {
		log.Fatal(err)
	}

	// 2) 送信してレスポンスを受信（UDP / ポート 53）
	resp, err := dnsmsg.SendQuery(query, "8.8.8.8", 53, dnsmsg.DNSoverUDP)
	if err != nil {
		log.Fatal(err)
	}

	// 3) レスポンスの確認
	fmt.Printf("ID: %x, RCODE: %d\n", resp.ID, resp.RCODE)
	for _, q := range resp.QuestionSection {
		fmt.Println("Q:", q)
	}
	for _, rr := range resp.AnswerSection {
		fmt.Println("A:", rr) // "example.com. IN A 300 93.184.216.34" 形式
	}
}
```

### wire format でのシリアライズ / パース

メッセージを wire format に書き出し、逆のパースを行なって往復変換する例です。

```go
wire := new(dnsmsg.WireFormat)
wire.WriteWireFormat(query)
fmt.Printf("wire format size: %d bytes\n", wire.Size())

msg, err := dnsmsg.ParseWireFormat(*wire)
if err != nil {
	log.Fatal(err)
}
fmt.Println(msg)
```

### レコードデータの取り出し

`ResourceRecord.RData` は `RDATA` インターフェースの型です。
`ResourceRecord.Type` に応じて具体的な型へ type assertion します。

```go
for _, rr := range resp.AnswerSection {
    if rr.Type != dnsmsg.TYPE_A {
        continue
    }
    a, ok := rr.RData.(dnsmsg.RecordA)
    if !ok {
        // 通常 rr.Type が TYPE_A ならば RecordA になる
        continue
    }
    // RecordA は中身が非エクスポートなので、表形式（String）または
    // canonical wire format（4 バイトの IPv4 アドレス）で取り出す
    fmt.Println(rr.Name, a.String())
}
```

## 主要な型

| 型 | 説明 |
|----|------|
| `WireFormat` | `[]byte` のエイリアス。DNS メッセージの wire format（生のバイト列） |
| `Message` | DNS メッセージ全体。ヘッダの各フラグと 4 つのセクション（Question / Answer / Authority / Additional） |
| `QuestionSectionEntry` | Question セクションの 1 行（`QName` / `Class` / `Type`） |
| `ResourceRecord` | リソースレコード 1 本（`Name` / `Class` / `Type` / `TTL` / `RData`） |
| `RDATA` | RDATA のインターフェース。`RecordA` などの各レコード型が実装する |
| `Label` / `DomainName` | ドメイン名。ラベル（1〜63 バイト）の列 |
| `NameCompressionDB` | 名前圧縮ポインタ管理 DB。シリアライズ時に `AppendDomainName` と連携する |
| `RecordOPT` | EDNS(0) の OPT レコード。`Version` / `Flags` / `Options` |
| `EDNSOption` | EDNS option のインターフェース。DO / NSID / EDE / `EDNSOptionRaw` が実装する |

## 関連リンク

- [edns.md](edns.md) — EDNS(0) / OPT レコードと EDNS option の作成
