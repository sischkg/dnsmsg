# RRSet と DNSSEC 署名

RRSet（Resource Record Set）は、同じオーナー名・クラス・タイプを持つリソースレコードの集合です。
DNSSEC（RFC 4034 Section 6.2）では、同一の (Name, Class, Type) を持つレコードをまとめて
一つの署名対象（RRSet）として扱います。

`dnsmsg` パッケージでは `RRSet` 構造体で RRSet を表現し、正規ワイヤフォーマット
（canonical wire format）へのシリアライズと、秘密鍵による DNSSEC 署名（RRSIG 生成）、
RRSIG の署名検証をサポートします。ワイルドカードのドメイン名から展開された RRSet の
署名検証にも対応しています。

## RRSet 構造体

| フィールド | 型 | 内容 |
|----------|----|------|
| `Name` | `DomainName` | レコードのオーナー名 |
| `Class` | `ResourceClass` | リソースクラス（通常は `CLASS_IN`） |
| `Type` | `ResourceType` | リソースタイプ |
| `TTL` | `uint32` | レコードの有効期限（秒） |
| `RData` | `[]RDATA` | 同じタイプのレコードデータのリスト |

## 主要な API

| API | 説明 |
|-----|------|
| `NewRRSet(name DomainName, class ResourceClass, typ ResourceType, ttl uint32, rdata ...RDATA) RRSet` | RRSet を構築 |
| `(*RRSet).Add(rdata RDATA)` | レコードデータを追加 |
| `(*RRSet).Len() int` | 含まれるレコード数 |
| `(*RRSet).Equal(rhs RRSet) bool` | 同一の RRSet か比較 |
| `(*RRSet).String() string` | 人間が読める形式で返す |
| `(*RRSet).CanonicalWireFormat() []byte` | 正規ワイヤフォーマット（RFC 4034 Section 6.2）を返す |
| `(*RRSet).AppendCanonicalWireFormat(w *WireFormat) uint32` | 正規ワイヤフォーマットを追記 |
| `SignRRSet(rs *RRSet, signer crypto.Signer, algorithm uint8, keyTag uint16, signersName DomainName, inception, expiration uint32) (*RecordRRSIG, error)` | RRSet に署名して RRSIG を生成 |
| `VerifyRRSet(rs *RRSet, rrsig *RecordRRSIG, pubkey crypto.PublicKey, now time.Time) error` | RRSIG の署名を検証 |
| `VerifyRRSetWithDNSKEY(rs *RRSet, rrsig *RecordRRSIG, dnskey *RecordDNSKEY, now time.Time) error` | DNSKEY レコードから公開鍵を読み取り検証 |
| `SupportedDNSSECAlgorithms() []uint8` | 署名・検証に対応するアルゴリズム一覧 |

## 正規ワイヤフォーマット

`CanonicalWireFormat` は各レコードを以下の順序でシリアライズします：

1. オーナー名（canonical 形式：圧縮なし・小文字ドメイン名）
2. クラス（2 オクテット）
3. タイプ（2 オクテット）
4. TTL（4 オクテット、正規形では常に 0）
5. RDATA（正規形）

同一 RRSet 内の複数レコードは、RDATA のバイト列の辞書順（canonical order）でソートされます
（RFC 4034 Section 6.2）。

TTL は正規形では 0 に固定されるため、署名対象データから TTL の差異が除外されます。

## DNSSEC 署名

### SupportedDNSSECAlgorithms

```go
func SupportedDNSSECAlgorithms() []uint8
```

この実装で DNSSEC 署名に対応しているアルゴリズム番号を昇順で返します。

| アルゴリズム | 番号 | ハッシュ |
|-------------|------|----------|
| RSASHA1 | 5 | SHA1 |
| RSASHA1-NSEC3-SHA1 | 7 | SHA1 |
| RSASHA256 | 8 | SHA256 |
| RSASHA512 | 10 | SHA512 |
| ECDSAP256SHA256 | 13 | SHA256 |
| ECDSAP384SHA384 | 14 | SHA384 |
| Ed25519 | 15 | （ハッシュなし） |

### DNSSECSignOptions

| フィールド | 型 | 内容 |
|----------|----|------|
| `Inception` | `uint32` | 署名開始時刻（Unix秒）。ゼロ値なら現在時刻 |
| `Expiration` | `uint32` | 署名有効期限（Unix秒）。ゼロ値なら無期限 |
| `KeyTag` | `uint16` | 署名鍵の DNSKEY キータグ |
| `SignerName` | `DomainName` | 署名鍵のオーナー名（DNSKEY レコードのオーナー）。ゼロ値ならルートドメイン |

### SignRRSet

```go
func SignRRSet(rs *RRSet, signer crypto.Signer, algorithm uint8, keyTag uint16, signerName DomainName, inception, expiration uint32) (*RecordRRSIG, error)
```

RRSet を秘密鍵で署名し、RRSIG レコードを生成します。

- `signer` は `crypto.Signer` インターフェースを実装する秘密鍵（`*rsa.PrivateKey` や `*ecdsa.PrivateKey` など）
- `algorithm` は DNSSEC アルゴリズム番号（`SupportedDNSSECAlgorithms()` で返される値）
- `keyTag` は署名鍵の DNSKEY キータグ
- `signerName` は署名鍵のオーナー名
- `inception` / `expiration` は署名の有効期間

戻り値の `*RecordRRSIG` には、`TypeCovered`（`rs.Type`）、`Algorithm`、`Labels`（`rs.Name` のラベル数）、
`OrigTTL`（`rs.TTL`）、`KeyTag`、`SignerName`、`Inception`、`Expiration`、`Signature` が設定されます。

署名データは `rs.CanonicalWireFormat()`（正規ワイヤフォーマット）に対して計算されます。

### ワイルドカードの RRSet に署名する

`rs.Name` の左端のラベルが `*` の場合、`Labels` フィールドはそのワイルドカードラベルを
数えません（RFC 4034 Section 3.1.3）。

| オーナー名 | `labelCount` | `Labels` |
|-----------|--------------|----------|
| `*.example.com.` | 3 | 2 |
| `*.sub.example.com.` | 4 | 3 |
| `www.example.com.` | 3 | 3 |

ワイルドカードの RRSet はゾーンには展開されないままのワイルドカード名で格納され、
その名前のまま署名されます（RFC 4034 Section 6.2）。

### VerifyRRSet

```go
func VerifyRRSet(rs *RRSet, rrsig *RecordRRSIG, pubkey crypto.PublicKey, now time.Time) error
func VerifyRRSetWithDNSKEY(rs *RRSet, rrsig *RecordRRSIG, dnskey *RecordDNSKEY, now time.Time) error
```

RRSIG が RRSet に対する有効な DNSSEC 署名かを検証します。
`pubkey` は署名鍵の公開鍵（RSA なら `*rsa.PublicKey`、ECDSA なら `*ecdsa.PublicKey`、
Ed25519 なら `ed25519.PublicKey`）。`now` にゼロ値の `time.Time` を渡すと署名有効期間の検査を省略します。

### ワイルドカードの RRSet の署名を検証する

RRSet の所有者名のラベル数が RRSIG の `Labels` フィールドより大きい場合、その RRSet と
RRSIG はワイルドカード展開によって生成されたものです（RFC 4035 Section 5.3.4）。
署名は展開前のワイルドカード名に対して作られているため、`VerifyRRSet` は RFC 4035
Section 5.3.2 の擬似コードに従って元のオーナー名を復元し、その名前と RRSIG の
`OrigTTL` を使った RRSet に対して署名を検証します。

復元される名前は、ワイルドカードラベル `*` の後に `Labels` フィールドのラベル数だけ
右端のラベルを並べた名前です。

| 検証する RRSet の所有者名 | `Labels` | 署名を検証する名前 |
|--------------------------|----------|--------------------|
| `www.example.com.` | 2 | `*.example.com.` |
| `a.b.c.example.com.` | 2 | `*.example.com.` |
| `www.sub.example.com.` | 3 | `*.sub.example.com.` |
| `*.example.com.` | 2 | `*.example.com.`（展開されないためそのまま） |
| `www.example.com.` | 3 | `www.example.com.`（展開されないためそのまま） |

`Labels` フィールドが所有者名のラベル数より大きい RRSIG は使えません（RFC 4035
Section 5.3.2）。その場合は `VerifyRRSet` はエラーを返します。

ワイルドカードは同じ接末の任意の深さの展開を覆うため（RFC 1034 Section 4.3.3）、
`*.example.com.` の RRSIG は `www.example.com.` も `www.sub.example.com.` も検証します。
接末が異なる名前（`www.example.org.` など）は復元される名前が RRSIG のオーナー名と
一致しないため検証に失敗します。ある名前が実際に署名済みワイルドカードで覆われるかの
保証は NSEC によるワイルドカード閉包の証明が必要で（RFC 4035 Section 5.3.1）、
この機能では行いません。

## 使用例

### 1) RRSet を構築して正規ワイヤフォーマットを取得する

```go
package main

import (
	"fmt"
	"log"

	"github.com/sischkg/dnsmsg"
)

func main() {
	// オーナー名
	name, err := dnsmsg.NewDomainNameFromString("www.example.com.")
	if err != nil {
		log.Fatal(err)
	}

	// A レコード 2 件の RRSet を構築
	rs := dnsmsg.NewRRSet(
		name,
		dnsmsg.CLASS_IN,
		dnsmsg.TYPE_A,
		3600,
		dnsmsg.NewRecordA([4]byte{192, 0, 2, 1}),
		dnsmsg.NewRecordA([4]byte{192, 0, 2, 2}),
	)

	// 正規ワイヤフォーマット（DNSSEC 署名の対象データ）
	wire := rs.CanonicalWireFormat()
	fmt.Printf("canonical wire format: %x\n", wire)
}
```

### 2) RSA 鍵で RRSet に署名し RRSIG を生成する

```go
package main

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"log"

	"github.com/sischkg/dnsmsg"
)

func main() {
	// テスト用 RSA 秘密鍵を生成（実際は dnssec-keygen の .private ファイルから読み込む）
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatal(err)
	}

	name, _ := dnsmsg.NewDomainNameFromString("www.example.com.")
	rs := dnsmsg.NewRRSet(
		name,
		dnsmsg.CLASS_IN,
		dnsmsg.TYPE_A,
		3600,
		dnsmsg.NewRecordA([4]byte{192, 0, 2, 1}),
	)

	// RSASHA256 (アルゴリズム 8) で署名
	rrsig, err := dnsmsg.SignRRSet(
		&rs,
		privateKey, // *rsa.PrivateKey は crypto.Signer を実装
		8,           // RSASHA256
		12345,       // キータグ
		name,        // 署名鍵のオーナー名
		1700000000,  // inception
		1800000000,  // expiration
	)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("RRSIG: %s\n", rrsig.String())
	fmt.Printf("Signature: %x\n", rrsig.Signature)
}
```

### 3) 対応アルゴリズム一覧を取得する

```go
for _, alg := range dnsmsg.SupportedDNSSECAlgorithms() {
	fmt.Printf("DNSSEC algorithm %d is supported\n", alg)
}
```

### 4) dnssec-keygen の鍵ファイルを読み込んで署名する

```go
// .key ファイルから公開鍵情報を読み込む
key, err := dnsmsg.ReadKeyFile("Kexample.com.+008+12345.key")
if err != nil {
    log.Fatal(err)
}

// signer は crypto.Signer を実装する秘密鍵（dnssec-keygen の .private ファイルから
// 復元した鍵など）
// signer := ...

rs := dnsmsg.NewRRSet(...)
rrsig, err := dnsmsg.SignRRSet(&rs, signer, key.Algorithm, keyTag, key.Name, inception, expiration)
```

## エラーハンドリング

| ケース | エラー |
|------|--------|
| `rs` が nil | `RRSet is nil` |
| `signer` が nil | `signer is nil` |
| 非対応アルゴリズム | `unsupported DNSSEC algorithm N for signing` |
| 署名失敗 | `cannot sign RRSet: <原因>` |

## 補足

- `SignRRSet` は `crypto.Signer` を受け取るため、`crypto/rsa` や `crypto/ecdsa` の秘密鍵をそのまま渡せます。
- `crypto/rsa` や `crypto/ecdsa` の `Sign` は `crypto.SHA256` などの `crypto.SignerOpts` を受け取るとデータを「すでにハッシュ済み」とみなすため、`SignRRSet` の内部で RRSet の正規ワイヤフォーマットをハッシュしてから署名します。呼び出し側は生の `[]byte` データを渡す必要はありません。
- Ed25519（アルゴリズム 15）はハッシュを指定しないアルゴリズムで、生データに対して署名されます。
- 鍵ファイルの読み込み（`.key` / `.private`）については [dnssec.md](dnssec.md) を参照してください。
- 署名検証は [zone.md](zone.md) の `Zone.Sign` で生成した RRSIG にもそのまま使えます。
  署名時と同じオーナー名（ワイルドカードは展開前の名前）で検証してください。

## 関連リンク

- [index.md](index.md) — パッケージ概要
- [dnssec.md](dnssec.md) — DNSSEC 鍵ファイル（BIND dnssec-keygen 生成）の読み込み
- [RFC 4034](https://datatracker.ietf.org/doc/html/rfc4034) — DNS Security (DNSSEC) Resource Records
- [RFC 4034 Section 3.1.3](https://datatracker.ietf.org/doc/html/rfc4034#section-3.1.3) — The RRSIG RR
- [RFC 4034 Section 6.2](https://datatracker.ietf.org/doc/html/rfc4034#section-6.2) — Canonical RR Set Form
- [RFC 4035 Section 5.3.2](https://datatracker.ietf.org/doc/html/rfc4035#section-5.3.2) — Verifying a Zone Signed with a Wildcard
- [RFC 4035 Section 5.3.4](https://datatracker.ietf.org/doc/html/rfc4035#section-5.3.4) — Reconstructing the Original Owner Name
