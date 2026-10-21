# dnsmsg

DNS メッセージの wire format（RFC 1035）を解析・シリアライズするための Go ライブラリ。
名前圧縮、EDNS(0)、DNSSEC（NSEC / NSEC3・RRset 署名・検証）、TSIG、ゾーン管理までを
外部依存なし（標準ライブラリのみ）で実装しています。

- モジュール: `github.com/sischkg/dnsmsg`
- Go: 1.23.2 以上
- 依存パッケージ: なし

## インストール

```sh
go get github.com/sischkg/dnsmsg
```

## クイックスタート

### クエリを送る

```go
package main

import (
	"fmt"
	"log"

	"github.com/sischkg/dnsmsg"
)

func main() {
	var query dnsmsg.Message
	query.QR = dnsmsg.QRQuery
	query.OPCODE = dnsmsg.QpcodeQuery
	query.RD = 1 // 再帰的問い合わせ

	if err := query.SetQuery("www.example.com.", dnsmsg.CLASS_IN, dnsmsg.TYPE_A); err != nil {
		log.Fatal(err)
	}

	resp, err := dnsmsg.SendQuery(query, "8.8.8.8", 53, dnsmsg.DNSoverUDP)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("ID: %x, RCODE: %d\n", resp.ID, resp.RCODE)
	for _, rr := range resp.AnswerSection {
		fmt.Println(rr) // "example.com. IN A 300 93.184.216.34" 形式
	}
}
```

`Exchange` は実際に送受信したオクテット列と送受信時刻も `QueryExchange` で返します。
TC ビットが立った応答を別トランスポートで問い直すことはしません（必要なときに `-tcp` /
`dnsmsg.DNSoverTCP` を選んでください）。

### wire format との往復

```go
wire := new(dnsmsg.WireFormat)
wire.WriteWireFormat(query)

msg, err := dnsmsg.ParseWireFormat(*wire)
if err != nil {
	log.Fatal(err)
}
```

### RDATA の取り出し

`ResourceRecord.RData` は `RDATA` インターフェースです。`ResourceRecord.Type` に対応する
具体型へ type assertion して使います。

```go
if rr.Type == dnsmsg.TYPE_A {
	if a, ok := rr.RData.(dnsmsg.RecordA); ok {
		fmt.Println(rr.Name, a.String())
	}
}
```

## dq コマンド

`cmd/dq` は指定したサーバへ 1 つの DNS クエリを送り、送信したメッセージと受信した
メッセージを送信・受信時刻とトランスポートを添えて JSON または base64 で出力します。

```sh
go build -o dq ./cmd/dq

./dq -r example.com                          # resolv.conf の nameserver へ UDP
./dq -r -s dns.google -tcp -t AAAA example.com
./dq -r -nsid example.com | jq '.response.AdditionalSection[0].RData.Options'
./dq -r -o base64 example.com
```

オプション一覧、出力形式の詳細、終了コードは [docs/dq.md](docs/dq.md) を参照してください。

## 主な機能

- DNS メッセージ（ヘッダ + Question / Answer / Authority / Additional）のシリアライズと解析
- ドメイン名（`DomainName` / `Label`）と RFC 1035 の名前圧縮（`NameCompressionDB`）
- RFC 4034 スタイルの正規形 wire format（圧縮なし・小文字）
- EDNS(0) / OPT（RFC 6891）と EDNS option（DO・NSID・EDE・生データ・カスタムパーサ登録）
- TSIG によるメッセージ認証（RFC 8945、HMAC-MD5 / SHA1 / SHA224 / SHA256 / SHA384 / SHA512）
- DNSSEC: RRSet の正規ワイヤフォーマット、`SignRRSet` による署名、`VerifyRRSet` による検証、
  NSEC / NSEC3 によるゾーン署名、BIND `dnssec-keygen` の鍵ファイル読み込み
- DNS ゾーン管理（`Zone`、`ResourceRecordsToZone`、`Zone.Sign` / `Zone.SignNSEC3`）
- UDP / TCP でのクエリ送信（`SendQuery` / `SendQueryWithTimeout` / `Exchange`）
- `Message` / `ResourceRecord` / `QuestionSectionEntry` の JSON マーシャル・アンマーシャル

## サポートするレコードタイプ

未知のタイプは生バイト列として `RecordRaw` に格納されます。

| タイプ | 定数 | レコード型 |
|--------|------|-----------|
| A | `TYPE_A` (1) | `RecordA` |
| NS | `TYPE_NS` (2) | `RecordNS` |
| SOA | `TYPE_SOA` (6) | `RecordSOA` |
| MX | `TYPE_MX` (15) | `RecordMX` |
| AAAA | `TYPE_AAAA` (28) | `RecordAAAA` |
| NSEC | `TYPE_NSEC` (32) | `RecordNSEC` |
| OPT | `TYPE_OPT` (41) | `RecordOPT` |
| DS | `TYPE_DS` (43) | `RecordDS` |
| RRSIG | `TYPE_RRSIG` (46) | `RecordRRSIG` |
| DNSKEY | `TYPE_DNSKEY` (48) | `RecordDNSKEY` |
| NSEC3 | `TYPE_NSEC3` (50) | `RecordNSEC3` |
| NSEC3PARAM | `TYPE_NSEC3PARAM` (51) | `RecordNSEC3PARAM` |
| TSIG | `TYPE_TSIG` (250) | `RecordTSIG` |

## ドキュメント

| ファイル | 内容 |
|----------|------|
| [docs/index.md](docs/index.md) | パッケージの概要、API の詳細、主要な型の一覧 |
| [docs/edns.md](docs/edns.md) | EDNS(0) / OPT レコードと EDNS option |
| [docs/tsig.md](docs/tsig.md) | TSIG による署名と検証（RFC 8945） |
| [docs/rrset.md](docs/rrset.md) | RRSet と DNSSEC 署名・検証 |
| [docs/zone.md](docs/zone.md) | ゾーン管理と NSEC / NSEC3 署名 |
| [docs/dnssec.md](docs/dnssec.md) | DNSSEC 鍵ファイル（`.key` / `.private`）の読み込み |
| [docs/dq.md](docs/dq.md) | `dq` コマンドの使い方 |
| [docs/record-a.md](docs/record-a.md) ほか | レコードタイプ別のドキュメント |

## 開発

```sh
go test ./...
go vet ./...
```

- テストやツールが作る一時ファイルは `tmp/`（git-ignored）に書き出します。
- 新しいレコードタイプを追加する手順は [AGENTS.md](AGENTS.md) に書いています:
  `ResourceType` 定数の追加 → `record-<type>.go` の実装（`Type` / `String` /
  `CanonicalWireFormat` / `AppendWireFormat` / `AppendCanonicalWireFormat` /
  `NewRecord*` / `NewRecord*FromString` / `ParseRecord*`）→ `ParseResourceRecord` の
  `switch` への追加 → `record-<type>_test.go` のテーブル駆動テスト。

## ライセンス

MIT ライセンスです。詳細は [LICENSE](LICENSE) を参照してください。
