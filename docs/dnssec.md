# DNSSEC 鍵の読み込み（dnssec-keygen 鍵ファイル対応）

`dnsmsg` パッケージでは、BIND に付属する `dnssec-keygen` で生成した DNSSEC 鍵ファイル（`.key` / `.private`）を読み込み、`DNSSECKey` 構造体として取得できます。読み込んだ鍵は `RecordDNSKEY` に変換してゾーンファイルに公開したり、RRSet の署名に使用したりできます（署名処理自体は別途実装予定です）。

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

## 補足

- `ReadKeyFile` / `ReadPrivateKeyFile` はファイルの **最初の一致レコード** しか返しません。複数の鍵を含むファイルがある場合は、ファイルを分割するか、独自に複数行をパースしてください。
- base64 は **パディングなし（RawStdEncoding, RFC 4634）** でエンコード/デコードされます。`dnssec-keygen` の出力に `=` パディングが含まれている場合は、デコード前にパディングを除去する必要があります（本実装ではそのままデコードを試みるため、パディング付きの文字列はエラーになります）。
- 秘密鍵（`PrivateKey` / `PrivateParams`）は平文で扱われるため、ファイルのアクセス権限（例: `0600`）など取り扱いに注意してください。
- 現在のところ **RRSet への実際の DNSSEC 署名機能は含まれていません**。`ReadKeyFile` / `ReadPrivateKeyFile` で鍵を読み込む機能のみです。署名・検証は別ステップで追加予定です。

## 関連リンク

- [index.md](index.md) — パッケージ概要
- [RFC 4034](https://datatracker.ietf.org/doc/html/rfc4034) — DNS Security (DNSSEC) Resource Records
- [RFC 5910](https://datatracker.ietf.org/doc/html/rfc5910) — Use of DNSSEC Algorithms and Security Algorithm
- [BIND dnssec-keygen](https://www.isc.org/bind/) — BIND に付属する DNSSEC 鍵生成ツール
