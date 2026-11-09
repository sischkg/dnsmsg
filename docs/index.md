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
- SVCB / HTTPS サービスレコード（RFC 9460）: `RecordSVCB` / `RecordHTTPS` での
  SvcPriority・TargetName・SvcParams の読み書き、登録済み SvcParamKey
  （mandatory・alpn・no-default-alpn・port・ipv4hint・ech・ipv6hint）と
  未登録キー（`key7` などの key + 10 進数）の zone file 表現の解析・生成
  （`docs/record-svcb.md`）
- TSIG による DNS メッセージの鍵ベース認証（RFC 8945）:
  - `Message.SignTSIG` / `Message.VerifyTSIG` での署名と検証
  - 共有鍵（`TSIGKey`）、署名オプション（`TSIGOptions`）、検証オプション（`TSIGVerifyOptions`）
  - HMAC-MD5 / HMAC-SHA1 / HMAC-SHA224 / HMAC-SHA256 / HMAC-SHA384 / HMAC-SHA512
    および短縮アルゴリズム（`-128` / `-192` / `-256`）
- DNSSEC 鍵ファイル（BIND `dnssec-keygen` 生成）の読み込み（`docs/dnssec.md`）:
  - `ReadKeyFile` で `.key` ファイル（公開鍵 / DNSKEY レコード）を読み込む
  - `ReadPrivateKeyFile` で `.private` ファイル（秘密鍵 / Private-key-format v1.3）を読み込む
  - `DNSSECKey.ToDNSKEY()` で `RecordDNSKEY` に変換
  - `NewDNSSECPublicKey` で DNSKEY の公開鍵マテリアルから `crypto.PublicKey` を構築
  - `NewDNSSECSigner` で `.private` の秘密鍵を `crypto.Signer` に変換（`SignRRSet` などで使用）
  - `DNSSECKeyTag` / `(RecordDNSKEY).KeyTag` / `(*DNSSECKey).KeyTag` で DNSKEY キータグを計算
  - `NewDNSSECKeyFileNameFromString` で鍵ファイル名（`K<name>+<alg>+<tag>`）から所属ドメイン名・アルゴリズム・キータグを解析（ファイルは読まない）。`NewDNSSECKeyBaseName` で基底名を生成
- RRSet と DNSSEC 署名（`docs/rrset.md`）:
  - `RRSet` 構造体と正規ワイヤフォーマット（RFC 4034 Section 6.2）
  - `SignRRSet` で RRSet に署名し RRSIG レコードを生成
  - `SupportedDNSSECAlgorithms()` で対応アルゴリズム一覧を取得
- DNS ゾーン管理（`docs/zone.md`）:
  - `Zone` 構造体（オリジン、デフォルト TTL、RRSet コレクション）
  - `AddRRSet` / `FindRRSet` / `RemoveRRSet` / `Equal` / `CanonicalWireFormat`
  - `ResourceRecordsToZone` で `[]ResourceRecord` を RRSet にグループ化して Zone を構築
- UDP / TCP による DNS クエリ送信（`SendQuery` / `SendQueryWithTimeout` / `Exchange` /
  `ExchangeWithConnectTimeout`）
- `dq` コマンド（`cmd/dq`）: 指定したサーバへ問い合わせを送り、送信したメッセージと
  受信したメッセージを JSON または base64 で表示（`docs/dq.md`）

## サポートするレコードタイプ

`ParseResourceRecord` により、以下のタイプの RDATA は型付きのレコード構造体として
取得できます。それ以外のタイプは生バイト列として `RecordRaw` に格納されます。

| タイプ   | 定数             | レコード型     |
|----------|------------------|----------------|
| A        | `TYPE_A` (1)     | `RecordA`      |
| NS       | `TYPE_NS` (2)    | `RecordNS`     |
| CNAME    | `TYPE_CNAME` (5) | `RecordCNAME`  |
| SOA      | `TYPE_SOA` (6)   | `RecordSOA`    |
| PTR      | `TYPE_PTR` (12)  | `RecordPTR`    |
| MX       | `TYPE_MX` (15)   | `RecordMX`     |
| TXT      | `TYPE_TXT` (16)  | `RecordTXT`    |
| AAAA     | `TYPE_AAAA` (28) | `RecordAAAA`   |
| NSEC     | `TYPE_NSEC` (32) | `RecordNSEC`   |
| DNAME    | `TYPE_DNAME` (39) | `RecordDNAME`  |
| NSEC3    | `TYPE_NSEC3` (50)| `RecordNSEC3`  |
| NSEC3PARAM | `TYPE_NSEC3PARAM` (51)| `RecordNSEC3PARAM` |
| OPT      | `TYPE_OPT` (41)  | `RecordOPT`（[edns.md](edns.md) 参照） |
| DS       | `TYPE_DS` (43)   | `RecordDS`     |
| RRSIG    | `TYPE_RRSIG` (46)| `RecordRRSIG`  |
| DNSKEY   | `TYPE_DNSKEY` (48)| `RecordDNSKEY` |
| TLSA     | `TYPE_TLSA` (52) | `RecordTLSA`（[record-tlsa.md](record-tlsa.md) 参照） |
| SVCB     | `TYPE_SVCB` (64) | `RecordSVCB`（[record-svcb.md](record-svcb.md) 参照） |
| HTTPS    | `TYPE_HTTPS` (65)| `RecordHTTPS`（[record-https.md](record-https.md) 参照） |
| TKEY     | `TYPE_TKEY` (249)| `RecordTKEY`   |

## ドキュメント目次

| ファイル | 内容 |
|----------|------|
| [index.md](index.md) | 本ページ。パッケージの概要、クイックスタート、主要な型の一覧 |
| [dnssec.md](dnssec.md) | DNSSEC 鍵ファイル（BIND dnssec-keygen 生成）の読み込み（`.key` / `.private`）、公開鍵・署名鍵の構築（NewDNSSECPublicKey / NewDNSSECSigner）、DNSKEY キータグの計算、鍵ファイル名（K\<name\>+\<alg\>+\<tag\>）の解析（NewDNSSECKeyFileNameFromString） |
| [rrset.md](rrset.md) | RRSet と DNSSEC 署名（正規ワイヤフォーマット、SignRRSet、署名鍵とキータグの準備、SupportedDNSSECAlgorithms） |
| [zone.md](zone.md) | DNS ゾーン管理（Zone 構造体、RRSet コレクション、ResourceRecordsToZone） |
| [edns.md](edns.md) | EDNS(0) / OPT レコード、EDNS option（DO・NSID・EDE・生データ）、カスタムパーサの登録 |
| [record-cname.md](record-cname.md) | CNAME レコード（RFC 1035） |
| [record-ptr.md](record-ptr.md) | PTR レコード（RFC 1035） |
| [record-dname.md](record-dname.md) | DNAME レコード（RFC 6672） |
| [record-txt.md](record-txt.md) | TXT レコード（RFC 1035） |
| [record-nsec.md](record-nsec.md) | NSEC レコード（RFC 4034） |
| [record-nsec3.md](record-nsec3.md) | NSEC3 レコード（RFC 5155） |
| [record-nsec3param.md](record-nsec3param.md) | NSEC3PARAM レコード（RFC 5155） |
| [record-svcb.md](record-svcb.md) | SVCB レコード（RFC 9460） |
| [record-https.md](record-https.md) | HTTPS レコード（RFC 9460） |
| [record-tkey.md](record-tkey.md) | TKEY レコード（RFC 2930） |
| [record-tlsa.md](record-tlsa.md) | TLSA レコード（RFC 6698） |
| [tsig.md](tsig.md) | TSIG による DNS メッセージの署名と検証（RFC 8945） |
| [dq.md](dq.md) | `dq` コマンド（`cmd/dq`）: 問い合わせ送信と送信・受信メッセージの JSON / base64 表示 |

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

### 送受信したオクテット列と時刻を受け取る

`Exchange` は `SendQueryWithTimeout` の実体です。応答をパースして返すだけでなく、
実際に送受信したオクテット列と、それらを書き出し・読み出した時刻を
`QueryExchange` で返します。wire を通ったバイト列そのものが必要な場合
（base64 での出力、ログへの記録など）では `SendQueryWithTimeout` の代わりに
`Exchange` を使います。

```go
ex, err := dnsmsg.Exchange(query, "8.8.8.8", 53, dnsmsg.DNSoverTCP, 2*time.Second)
if err != nil {
	// 送信に失敗した場合にも、送信しようとしたメッセージは ex.Query と
	// ex.QueryWire に入っています。
	log.Println(err)
}
fmt.Printf("sent   %s  %d octets\n", ex.SentAt.Format(time.RFC3339Nano), ex.QueryWire.Size())
fmt.Printf("received %s  %d octets\n", ex.ReceivedAt.Format(time.RFC3339Nano), ex.ReplyWire.Size())
```

- `QueryWire` と `ReplyWire` は DNS メッセージそのもので、TCP のときに前置される
  2 オクテットのメッセージ長ヘッダは含みません。
- socket に何も書き出さなかったときは `SentAt` がゼロ時刻、応答を読み出さなかった
  ときは `ReplyWire` は nil で `Reply` は空のメッセージです。
- 受信したオクテット列のパースに失敗したときは `ReplyWire` だけが入ります。

### 接続のタイムアウトを分ける

`Exchange` は接続・送信・受信の 3 ステップに一つの timeout を適用します。接続に
だけ別の締切を設けたいプログラム（TCP で、応答を待つ時間とサーバにたどり着く
時間を分けたいクライアントなど）向けに、同じ 3 ステップを締切を分けて扱う
`ExchangeWithConnectTimeout` があります。`Exchange` は
`connectTimeout` と `queryTimeout` に同じ値を渡した呼び出しです。

```go
// 接続には 250 ms、書き出しと読み出しには 2 s
ex, err := dnsmsg.ExchangeWithConnectTimeout(query, "127.0.0.1", 53, dnsmsg.DNSoverTCP,
	250*time.Millisecond, 2*time.Second)
```

- `connectTimeout` は `net.DialTimeout` の締切としてだけ使われます。
- `queryTimeout` は接続が確立した後に `SetDeadline` で設定される締切で、送信と受信
  の両方を制限します。接続の確立にかかった時間は `queryTimeout` を減らしません。
- それぞれ 0 以下なら、そのステップに締切はありません。
- UDP には接続というステップがありません（`net.Dial` はローカルの socket を用意する
  だけ）ので、`connectTimeout` は UDP で目に見える効果を持ちません。
- 返される `QueryExchange` は `Exchange` と同じもので、`SentAt` がゼロ時刻のまま
  になるのは接続まで進まなかった場合です。

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
| `QueryExchange` | 1 回の問い合わせの送受信。`Transport` / `Query` / `QueryWire` / `SentAt` / `Reply` / `ReplyWire` / `ReceivedAt`（`Exchange` が返す） |

## 関連リンク

- [edns.md](edns.md) — EDNS(0) / OPT レコードと EDNS option の作成
- [tsig.md](tsig.md) — TSIG による DNS メッセージの署名と検証（RFC 8945）
- [dq.md](dq.md) — `dq` コマンドの使い方（問い合わせ送信、JSON / base64 出力）
