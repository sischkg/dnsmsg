# DNSSEC の鍵ファイル・署名鍵・キータグ（dnssec-keygen 鍵ファイル対応）

`dnsmsg` パッケージでは、BIND に付属する `dnssec-keygen` で生成した DNSSEC 鍵ファイル（`.key` / `.private`）を読み込み、`DNSSECKey` 構造体として取得できます。読み込んだ鍵は `RecordDNSKEY` に変換してゾーンファイルに公開でき、`NewDNSSECSigner` で `crypto.Signer` に変換して `SignRRSet` の署名鍵にできます。`KeyTag` 系の API は RFC 4034 Appendix B の DNSKEY キータグを計算します。

## `DNSSECKey` 構造体

| フィールド | 型 | 内容 |
|----------|----|------|
| `Name` | `DomainName` | 鍵の所属ドメイン名（DNSKEY レコードのオーナー名） |
| `Flags` | `uint16` | DNSKEY フラグ（256 = ゾーンキー ZSK、257 = セキュアエントリポイント KSK） |
| `Protocol` | `uint8` | セキュリティプロトコル（DNSSEC では常に 3） |
| `Algorithm` | `uint8` | DNSSEC アルゴリズム番号（RFC 4034 Section 5.1.1） |
| `PublicKey` | `[]byte` | 公開鍵データ（`.key` ファイル読み込み時に設定。`.private` では nil） |
| `PrivateKey` | `[]byte` | 主要な秘密鍵データ（`.private` ファイル読み込み時に設定。アルゴリズム依存） |
| `PrivateParams` | `map[string][]byte` | 名前付き秘密パラメータ（Modulus, PrivateExponent, PrivateKey 等。`.private` のみ） |

## 主要な API

| API | 説明 |
|-----|------|
| `ReadKeyFile(filename string) (*DNSSECKey, error)` | `.key` ファイルを読み込み、最初の DNSKEY レコード行をパースして `DNSSECKey` を返す |
| `ReadPrivateKeyFile(filename string) (*DNSSECKey, error)` | `.private` ファイル（Private-key-format v1.3）を読み込み、アルゴリズム番号と秘密パラメータを抽出する |
| `(*DNSSECKey).ToDNSKEY() RecordDNSKEY` | 鍵を `RecordDNSKEY` に変換（公開鍵のみ。秘密鍵は DNSKEY レコードに含まれない） |
| `NewDNSSECPublicKey(algorithm uint8, material []byte) (crypto.PublicKey, error)` | DNSKEY の公開鍵マテリアルから `crypto.PublicKey` を構築（`VerifyRRSet` の `pubkey` に渡せます） |
| `NewDNSSECSigner(key *DNSSECKey) (crypto.Signer, error)` | 鍵ファイルから復元した秘密鍵を `crypto.Signer` に変換（`SignRRSet` の署名鍵として使えます） |
| `DNSSECKeyTag(rdata []byte) uint16` | DNSKEY RDATA（wire フォーマット）から RFC 4034 Appendix B のキータグを計算 |
| `(r RecordDNSKEY).KeyTag() uint16` | `RecordDNSKEY` のキータグ（`CanonicalWireFormat()` に対して `DNSSECKeyTag` を適用） |
| `(*DNSSECKey).KeyTag() (uint16, error)` | 鍵の公開鍵材料からキータグを計算。公開鍵がない場合はエラー |

## キーファイル形式

### `.key` ファイル（公開鍵）

`dnssec-keygen` が生成する `.key` ファイルは、ゾーンファイル形式の DNSKEY レコードを含みます。

```
example.com. IN DNSKEY 256 3 5 AQO=
```

書式：`<name> IN DNSKEY <flags> <protocol> <algorithm> <base64-public-key>`

- `name` — 鍵の所属ドメイン名（末尾に `.` を付けた完全修飾ドメイン名）
- `flags` — 256（ZSK）または 257（KSK）
- `protocol` — 3
- `algorithm` — DNSSEC アルゴリズム番号（5 = RSASHA1、8 = RSASHA256、13 = ECDSAP256SHA256 等）
- `base64-public-key` — 公開鍵を base64（パディングなし、RFC 4634）でエンコードした文字列

コメント行（`;` または `#` で始まる行）と空行、および `$ORIGIN` / `$TTL` などのディレクティブ行はスキップされます。ファイル内の最初の DNSKEY レコード行が返されます。

### `.private` ファイル（秘密鍵）

`dnssec-keygen` が生成する `.private` ファイルは、Private-key-format v1.3 形式です。

```
Private-key-format: v1.3
Algorithm: 5 (RSASHA1)
Modulus: AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8
PublicExponent: AQAB
PrivateExponent: q83v
Prime1: AAAA
Prime2: BBBB
Exponent1: CCCC
Exponent2: DDDD
Coefficient: EEEE
Created: 20230101000000
Publish: 20230101000000
Activate: 20230101000000
```

- `Algorithm: <n> (<name>)` — アルゴリズム番号（必須。これが読み込まれます）
- その他の行（`Modulus`, `PrivateExponent` 等）は base64 でエンコードされたパラメータとして `PrivateParams` マップに格納されます
- `PrivateExponent`（または `PrivateKey`）は `PrivateKey` フィールドにもコピーされます
- `Created` / `Publish` / `Activate` などの時刻行は情報目的のみで無視されます

## 公開鍵の構築（`NewDNSSECPublicKey`）

```go
func NewDNSSECPublicKey(algorithm uint8, material []byte) (crypto.PublicKey, error)
```

DNSKEY レコードの公開鍵マテリアル（`PublicKey` フィールド、すなわち DNSKEY RDATA の末尾）から
`crypto.PublicKey` を構築します。`VerifyRRSet` の `pubkey` 引数に渡せます。

| アルゴリズム | 返される型 | 公開鍵マテリアルの形式 |
|--------------|-----------|----------------------|
| 5・7・8・10 | `*rsa.PublicKey` | 公開指数の長さ（1 オクテット。0 は指数 65537 を意味する）→ 指数 → 法（すべて big-endian、RFC 4034 Section 2.1） |
| 13・14 | `*ecdsa.PublicKey` | X 座標 → Y 座標（各 32 または 48 オクテット、0 の詰めなし。RFC 6605 Section 4） |
| 15 | `ed25519.PublicKey` | 32 オクテット（RFC 8080 Section 6） |

`RecordDNSKEY` をもっている場合は `VerifyRRSetWithDNSKEY` が内部でこの変換を行うため、
明示的に呼び出す必要はありません。`.private` ファイルだけでは公開鍵マテリアルを持たないため、
`.key` ファイルも読んでください（[rrset.md](rrset.md) の使用例 4）。

## 署名鍵の構築（`NewDNSSECSigner`）

`SignRRSet` は `crypto.Signer` を受け取ります。`NewDNSSECSigner` は `.private` ファイルから読み込んだ `DNSSECKey` の秘密パラメータから `crypto.Signer` を組み立てるので、鍵ファイルから直接署名鍵を作れます。

```go
key, err := dnsmsg.ReadPrivateKeyFile("Kexample.com.+013+39506.private")
if err != nil {
	log.Fatal(err)
}

signer, err := dnsmsg.NewDNSSECSigner(key)
if err != nil {
	log.Fatal(err)
}
// signer は crypto.Signer。SignRRSet にそのまま渡せる。
```

受け付けるアルゴリズムと、それぞれの秘密鍵に必要なパラメータ（RFC 4034 Appendix D、RFC 6605、RFC 8080）:

| アルゴリズム | 必要な秘密パラメータ | 返される型 |
|-------------|--------------------|-----------|
| 5, 7, 8, 10 (RSA) | `Modulus` / `PublicExponent` / `PrivateExponent`（`Prime1` と `Prime2` は任意） | `*rsa.PrivateKey` |
| 13, 14 (ECDSA P-256 / P-384) | `PrivateKey`（秘密スカラー。32 / 48 オクテット） | `*ecdsa.PrivateKey` |
| 15 (Ed25519) | `PrivateKey`（32 オクテットの seed） | `ed25519.PrivateKey` |

- 受け付けるアルゴリズムは `SupportedDNSSECAlgorithms()`（`5, 7, 8, 10, 13, 14, 15`）と同じです。それ以外は `unsupported DNSSEC algorithm N for signing` を返します。
- 秘密パラメータは `ReadPrivateKeyFile` が base64 からデコード済みのオクテット列として `PrivateParams` に入れています。`NewDNSSECSigner` は再度のデコード（16 進数や base64 の再解釈）を行いません。
- パラメータ名は大文字・小文字を区別しません（`Privatekey` のような綴りも受け付けます）。名前で見つからない場合は `DNSSECKey.PrivateKey`（`ReadPrivateKeyFile` が秘密指数・秘密スカラーを写すフィールド）が使われます。RSA の素数 2 つは 1 つのオクテット列にまとめられないため、名前付きパラメータからのみ読まれます。
- 秘密スカラーと seed の長さは固定です（ECDSA は曲線の位数のオクテット数、Ed25519 は 32 オクテット）。長さが違う鍵は、鍵を組み立てる前に検出されます（`ed25519.NewKeyFromSeed` は短い入力で panic するため、先に検査します）。
- `DNSKEY` の公開鍵（`PublicKey`）が設定されている場合は、秘密鍵から導出した公開鍵と比較し、一致しなければエラーにします。`.private` ファイル単体で読んだ鍵は公開鍵を持たないため、この比較は行われません。
- RSA の `Prime1` / `Prime2` は任意です。両方揃っている場合は `Validate` と `Precompute`（CRT 値の事前計算。多くの RRSet に署名する場合に速くなります）を通します。両方ない場合は `Modulus` / `PublicExponent` / `PrivateExponent` だけを検査し、`rsa.PrivateKey` は一般経路で署名します。`Exponent1` / `Exponent2` / `Coefficient` は読みません。これらの値は素数と秘密指数から導出できるので、ファイルに書かれていても署名には使いません。
- 乱数は使いません。同じ秘密パラメータからは常に同じ鍵が得られます。

## DNSKEY のキータグ（`KeyTag`）

DNSKEY のキータグ（RFC 4034 Appendix B）は、その DNSKEY レコードの **RDATA だけ**（flags / protocol / algorithm / public key。名前・クラス・タイプ・TTL は含まない）をオクテット列として受け取り、16 ビット big-endian の語として足し合わせた下 16 ビットです。末尾で 1 オクテット余る場合は、そのオクテットを最後の語の上位バイトとして扱います。最終的なあふれ（キャリー）はもう一度加算します。

```go
key, err := dnsmsg.ReadKeyFile("Kexample.com.+013+39506.key")
if err != nil {
	log.Fatal(err)
}

dnskey := key.ToDNSKEY()
fmt.Println(dnskey.KeyTag())        // DNSKEY レコード自身のキータグ
fmt.Println(key.KeyTag())           // 同じ値（.key を読んだ鍵なので公開鍵がある）
fmt.Println(dnsmsg.DNSSECKeyTag(dnskey.CanonicalWireFormat())) // 生の RDATA から計算
```

| API | 説明 |
|-----|------|
| `DNSSECKeyTag(rdata []byte) uint16` | DNSKEY RDATA のオクテット列から計算。RDATA ではないオクテット（名前や TTL）を渡さないでください |
| `(r RecordDNSKEY).KeyTag() uint16` | `CanonicalWireFormat()` の RDATA に対して計算するため、常にそのレコードの正しいキータグを返します |
| `(*DNSSECKey).KeyTag() (uint16, error)` | `ToDNSKEY()` 経由で計算。公開鍵材料を持たない `.private` 単体の鍵はエラー |

- `SignRRSet` は `keyTag` を引数として受け取るため、値は呼び出し側が決めます。`(*DNSSECKey).KeyTag()` で計算した値をそのまま渡せば、生成される RRSIG の `KeyTag` フィールドが署名鍵の実際のキータグと一致します。
- 検証側が使う `VerifyRRSetWithDNSKEY` は渡された `RecordDNSKEY` をそのまま使い、アルゴリズムが RRSIG と違う場合だけエラーにします（`DNSKEY algorithm N does not match RRSIG algorithm M`）。複数の DNSKEY があるゾーンでどの鍵で検証するかを選ぶのは呼び出し側の仕事です。その判断には `RecordDNSKEY.KeyTag()` と `RecordRRSIG.KeyTag` を比較するのが定石です（RFC 4034 Section 3.1.1）。
- `(*DNSSECKey).KeyTag()` が公開鍵のない鍵でエラーにするのは、flags・protocol・algorithm の 4 オクテットだけの合計は見た目はキータグですが実際のキータグではないためです。`.private` 単体の鍵でキータグが必要な場合は、同じ名前の `.key` ファイルの公開鍵を `PublicKey` に設定してから計算してください。

## 使用例

### 1) `.key` ファイルから公開鍵を読み込み、`RecordDNSKEY` に変換する

```go
package main

import (
	"fmt"
	"log"

	"github.com/sischkg/dnsmsg"
)

func main() {
	// BIND dnssec-keygen で生成した .key ファイルを読み込む
	key, err := dnsmsg.ReadKeyFile("Kexample.com.+005+12345.key")
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Name: %s\n", key.Name)        // 例: example.com.
	fmt.Printf("Flags: %d\n", key.Flags)       // 256 (ZSK) / 257 (KSK)
	fmt.Printf("Protocol: %d\n", key.Protocol) // 3
	fmt.Printf("Algorithm: %d\n", key.Algorithm)
	fmt.Printf("PublicKey: %x\n", key.PublicKey)

	// RecordDNSKEY に変換してゾーンファイルに公開できる
	dnskey := key.ToDNSKEY()
	fmt.Println(dnskey.String()) // 例: "256 3 5 YWJj"
}
```

### 2) `.private` ファイルから秘密鍵を読み込む

```go
package main

import (
	"fmt"
	"log"

	"github.com/sischkg/dnsmsg"
)

func main() {
	// dnssec-keygen で生成した .private ファイルを読み込む
	key, err := dnsmsg.ReadPrivateKeyFile("Kexample.com.+005+12345.private")
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Algorithm: %d\n", key.Algorithm)
	fmt.Printf("PrivateKey: %x\n", key.PrivateKey)

	// 個別のパラメータにもアクセス可能
	if modulus, ok := key.PrivateParams["Modulus"]; ok {
		fmt.Printf("Modulus: %x\n", modulus)
	}
	if privExp, ok := key.PrivateParams["PrivateExponent"]; ok {
		fmt.Printf("PrivateExponent: %x\n", privExp)
	}

	// 公開鍵は .private ファイルには含まれないため nil
	if key.PublicKey == nil {
		fmt.Println("PublicKey: (not present in .private file)")
	}
}
```

### 3) `.key` ファイルで読み込んだ鍵を使ってレコードを構築する

```go
// .key ファイルを読み込み
key, err := dnsmsg.ReadKeyFile("Kexample.com.+008+54321.key")
if err != nil {
    log.Fatal(err)
}

// DNSKEY レコードとして追加
rr := dnsmsg.ResourceRecord{
    Name:  key.Name,
    Class: dnsmsg.CLASS_IN,
    Type:  dnsmsg.TYPE_DNSKEY,
    TTL:   3600,
    RData: key.ToDNSKEY(),
}

// ワイヤフォーマットにシリアライズ
var w dnsmsg.WireFormat
db := dnsmsg.NewNameCompressionDB()
rr.AppendWireFormat(&w, db)
```

### 4) `.private` と `.key` を組み合わせて署名し、DNSKEY で検証する

```go
package main

import (
	"fmt"
	"log"
	"time"

	"github.com/sischkg/dnsmsg"
)

func main() {
	// dnssec-keygen の同一接頭辞を持つ .private と .key を読む
	base := "Kexample.com.+013+39506"
	private, err := dnsmsg.ReadPrivateKeyFile(base + ".private")
	if err != nil {
		log.Fatal(err)
	}
	keyFile, err := dnsmsg.ReadKeyFile(base + ".key")
	if err != nil {
		log.Fatal(err)
	}

	// 公開鍵マテリアルを合わせると NewDNSSECSigner が秘密鍵と照合する
	private.PublicKey = keyFile.PublicKey

	signer, err := dnsmsg.NewDNSSECSigner(private)
	if err != nil {
		log.Fatal(err)
	}

	// SignRRSet はキータグを引数として受け取る。DNSKEY から計算した値を渡す
	tag, err := private.KeyTag()
	if err != nil {
		log.Fatal(err)
	}

	name, err := dnsmsg.NewDomainNameFromString("example.com.")
	if err != nil {
		log.Fatal(err)
	}
	rs := dnsmsg.NewRRSet(
		name,
		dnsmsg.CLASS_IN,
		dnsmsg.TYPE_A,
		3600,
		dnsmsg.NewRecordA([4]byte{192, 0, 2, 1}),
	)

	now := time.Now()
	rrsig, err := dnsmsg.SignRRSet(
		&rs,
		signer,
		private.Algorithm,
		tag,
		name,
		uint32(now.Unix())-3600,
		uint32(now.Unix())+86400,
	)
	if err != nil {
		log.Fatal(err)
	}

	// 同じ鍵の DNSKEY で検証する。キータグが RRSIG と一致していることも確認できる
	dnskey := private.ToDNSKEY()
	if dnskey.KeyTag() != tag {
		log.Fatalf("key tag mismatch: %d != %d", dnskey.KeyTag(), tag)
	}
	if err := dnsmsg.VerifyRRSetWithDNSKEY(&rs, rrsig, &dnskey, now); err != nil {
		log.Fatal(err)
	}

	fmt.Printf("verified %s with key tag %d\n", name, tag)
}
```

## エラーハンドリング

| ケース | エラー内容 |
|------|-----------|
| ファイルが存在しない | `os.ReadFile` のエラーをラップして返す |
| DNSKEY レコードが見つからない | `no DNSKEY record found in <filename>` |
| 行のフィールド数が不足 | `invalid DNSKEY key line ...: expected at least 7 fields` |
| クラスが `IN` 以外 | `invalid DNSKEY key line ...: expected class IN` |
| タイプが `DNSKEY` 以外 | `invalid DNSKEY key line ...: expected type DNSKEY` |
| ドメイン名が不正 | `invalid DNSKEY name ...: <reason>` |
| フラグ/プロトコル/アルゴリズムが数値でない | `invalid <field> ...: <reason>` |
| 公開鍵の base64 が不正 | `invalid DNSKEY public key ...: illegal base64 data...` |
| `.private` に `Algorithm` 行がない | `no algorithm found in private key file <filename>` |
| `.private` のパラメータの base64 が不正 | `cannot decode private key parameter ...: illegal base64 data...` |
| `NewDNSSECSigner` に `nil` を渡す | `DNSSEC key is nil` |
| 公開鍵のみ（`.key` だけ）の鍵を署名に使う | `DNSSEC key <name> has no private key material: read the .private file` |
| 未対応アルゴリズムで署名しようとする | `unsupported DNSSEC algorithm <n> for signing` |
| 必要な秘密パラメータがない | `DNSSEC key <name> has no RSA private key parameter "<name>"`、`... has no ECDSA private key parameter "PrivateKey"`、`... has no Ed25519 private key parameter "PrivateKey"` |
| 秘密鍵のパラメータ長や値が不正 | `invalid RSA private key in DNSSEC key <name>: ...`、`invalid ECDSA private key in DNSSEC key <name>: the private scalar must be <n> octets, got <n>`、`invalid Ed25519 private key in DNSSEC key <name>: the seed must be 32 octets, got <n>` |
| 公開指数が DNSKEY と一致しない | `invalid RSA public exponent in DNSSEC key <name>: it must be at least 2 and less than 2^31` |
| 秘密鍵から導出した公開鍵が DNSKEY の公開鍵と違う | `DNSSEC key <name>: its private key does not match its DNSKEY public key` |
| `KeyTag` を公開鍵マテリアルなしで呼ぶ | `cannot compute the key tag of DNSSEC key <name>: no public key material` |

## 補足

- `ReadKeyFile` / `ReadPrivateKeyFile` はファイルの **最初の一致レコード** しか返しません。複数の鍵を含むファイルがある場合は、ファイルを分割するか、独自に複数行をパースしてください。
- base64 の **出力**（`RecordDNSKEY.String()` など）はパディングなし（RawStdEncoding）でエンコードされます。**入力**（`.key` / `.private` の読み取り）はパディングの有無を問わず受け付けます（まずパディングありで復号を試み、失敗した場合にパディングなしで復号します）。
- 秘密鍵（`PrivateKey` / `PrivateParams`）は平文で扱われるため、ファイルのアクセス権限（例: `0600`）など取り扱いに注意してください。
- `.private` の鍵から `crypto.Signer` を作って RRSet に署名し、DNSKEY で検証する一連の手順は [rrset.md](rrset.md) の「DNSSEC 署名と検証」にあります。ゾーン全体に署名する場合は [zone.md](zone.md) の `Zone.Sign` を参照してください。

## 関連リンク

- [index.md](index.md) — パッケージ概要
- [rrset.md](rrset.md) — DNSSEC 署名と検証（`SignRRSet` / `VerifyRRSet`）
- [zone.md](zone.md) — `Zone.Sign` によるゾーン全体の署名と NSEC
- [RFC 4034](https://datatracker.ietf.org/doc/html/rfc4034) — DNS Security (DNSSEC) Resource Records
- [RFC 4034 Appendix B](https://datatracker.ietf.org/doc/html/rfc4034#appendix-B) — DNSKEY のキータグの計算例
- [RFC 5910](https://datatracker.ietf.org/doc/html/rfc5910) — Use of DNSSEC Algorithms and Security Algorithm
- [RFC 6605](https://datatracker.ietf.org/doc/html/rfc6605) — ECDSA DNSSEC Operations（楕円曲鍵のパラメータ表記）
- [RFC 8080](https://datatracker.ietf.org/doc/html/rfc8080) — Edwards-Curve Digital Security Algorithm (Ed25519) DNSSEC
- [BIND dnssec-keygen](https://www.isc.org/bind/) — BIND に付属する DNSSEC 鍵生成ツール
