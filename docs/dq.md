# dq — クエリを送信して送受信メッセージを表示するコマンド

`cmd/dq` は `dnsmsg` パッケージの上で動くコマンドラインツールです。
コマンドラインから DNS クエリを組み立てて指定したサーバへ送信し、
**送信したクエリメッセージ**と**受信した応答メッセージ**を、送受信の時刻と
トランスポートを添えて JSON または base64 で出力します。

出力は実際に送受信したメッセージそのものです。応答が切り詰められていても
（TC=1）別のトランスポートで問い直すことはしません。

## 構築

```sh
go build -o dq ./cmd/dq
```

## 使い方

```
usage: dq [options] <domain-name>

  -s <server>   問い合わせ先サーバのアドレスまたはホスト名
                (既定: /etc/resolv.conf の最初の nameserver)
  -p <port>     問い合わせ先のポート番号 (既定: 53)
  -c <class>    QCLASS (既定: IN)
  -t <type>     QTYPE (既定: A)
  -r            RD=1 (再帰的問い合わせ) を設定する
  -tcp          トランスポートに TCP を使う
  -udp          トランスポートに UDP を使う (既定)
  -o <format>   出力形式: json または base64 (既定: json)
  -edns         EDNS0 を問い合わせに含める (既定)
  -no-edns      EDNS0 を問い合わせに含めない
  -nsid         問い合わせに長さ 0 の NSID オプションを含める
  -timeout <n>  接続・送信・応答待ちの上限を秒で指定する (既定: 5)
                0 は無制限
```

- ドメイン名は位置引数を 1 つだけ指定します（`-h` を除いて位置引数が 0 個または
  2 個以上のときは使い方を出て終了コード 2 になります）。
- オプションはドメイン名の前後のどちらに置いても同じ意味になります。
  `dq example.com -r` は `dq -r example.com` と同じです。
- オプション名は `-` 1 つで始めます（`-tcp`、`-timeout` など）。`--tcp` のように
  `-` を 2 つ書いても同じオプションです。
- `--` より後ろはすべて位置引数として扱われます。`-` で始まるドメイン名を
  渡すときに使います（`dq -- -example.com`）。
- `-h` は使い方を表示して終了コード 0 で終わります。

## オプション

| オプション | 意味 | 既定 |
|------------|------|------|
| `-s <server>` | 問い合わせ先サーバ。IPv4 / IPv6 アドレスまたはホスト名 | `/etc/resolv.conf` の最初の `nameserver` |
| `-p <port>` | 問い合わせ先のポート番号。0 と 65535 より大はエラー | `53` |
| `-c <class>` | QCLASS | `IN` |
| `-t <type>` | QTYPE | `A` |
| `-r` | ヘッダの RD ビットを 1 にする（再帰的問い合わせ） | RD=0 |
| `-tcp` | トランスポートに TCP を使う | — |
| `-udp` | トランスポートに UDP を使う | 既定のトランスポート |
| `-o <format>` | 出力形式。`json` または `base64` | `json` |
| `-edns` | 問い合わせに OPT レコード（EDNS0）を含める | 含む |
| `-no-edns` | 問い合わせに OPT レコードを含めない | — |
| `-nsid` | 問い合わせの OPT に長さ 0 の NSID オプションを含める | 含めない |
| `-timeout <n>` | 接続・送信・応答待ちの上限を秒で指定する。0 は無制限、小数も可（`-timeout 0.5`） | `5` 秒（`dnsmsg.DefaultQueryTimeout`） |

`-tcp` と `-udp`、`-edns` と `-no-edns` を同時に指定するとエラーになります。
`-nsid` は OPT を使わない `-no-edns` と同時に指定できません。
`-edns=false` と書いても EDNS0 は使われません。
`-timeout` に負の数を与えるとエラーになります。

### 指定できる QCLASS・QTYPE

`-c` と `-t` は `dnsmsg` が名前を知っている値と、10 進の数値を受け付けます。

- クラス: `IN` / `CH` / `HS` / `ANY` または数値（`-c 3` は CH）
- タイプ: `A` / `NS` / `SOA` / `MX` / `AAAA` / `OPT` / `DS` / `RRSIG` /
  `DNSKEY` / `TSIG` / `NSEC` / `NSEC3` / `NSEC3PARAM`、`TYPE<n>` または数値
  （`-t 255` は TYPE255）

分からない値はエラーになります。

```console
$ ./dq -s 172.16.253.81 -c XX -r example.com
dq: QCLASS "XX" が分かりません
```

## 出力形式

`-o` で出力形式を選びます。`json`（既定）と `base64` が使えます。

### json（既定）

`-o json` では 2 スペースでインデントした 1 つの JSON オブジェクトを
stdout に出します。`query` と `response` の中身は `dnsmsg.Message` の JSON 表現
（`MarshalJSON`）そのままで、`Message` の JSON の鍵（`ID` / `QR` / `OPCODE` /
`QuestionSection` …）がそのまま使われます。

```json
{
  "transport": "udp",
  "query":    { … 送信したクエリメッセージ … },
  "sent":     "<送信した時刻>",
  "response": { … 受信した応答メッセージ … },
  "received": "<受信した時刻>"
}
```

- この JSON の鍵は上の順序のままです（`transport` が先頭で、各時刻は対応する
  メッセージの直後に出します）。`query` と `response` の中の鍵の順序は
  `Message.MarshalJSON` のもので、この JSON の順序ではありません。
- `transport` は実際に使ったトランスポートで、`tcp` または `udp` です。
- `sent`・`received` は `time.RFC3339Nano` 形式の UTC の時刻で、base64 形式が
  出す時刻と同じ値です。送信時刻はメッセージを socket に書き出した後、受信時刻は
  応答のオクテット列を読み出した後に取った値です。
- 書き出していないときは `"sent": null`、何も読み出していないときは
  `"received": null` になります。
- 応答を受信できなかったときは `"response": null` になります（この場合終了コード 1）。
  応答を読み出したのに解析できなかったときは `"response": null` のまま
  `"received"` には時刻が入ります。
- ドメイン名は末尾のドット付きで表示されます（`"example.com."`、root は `"."`）。
- OPT レコードは in-memory の形で表示されます。つまり `"Class": "IN"`、
  `"TTL"` は拡張 UDP ペイロードサイズ、`RData` は `Version` / `Flags` / `Options` です。
  wire format での CLASS・TTL の使い方との対応は [edns.md](edns.md) を参照してください。
- 問い合わせ先サーバを決めたこと、エラーの内容は stderr に出ます。
  stdout は JSON だけなので `jq` などにそのままパイプできます。

#### 例: 基本的な問い合わせ

```console
$ ./dq -r -s 172.16.253.81 example.com
{
  "transport": "udp",
  "query": {
    "AA": 0,
    "AD": 0,
    "ANCOUNT": 0,
    "ARCOUNT": 1,
    "AdditionalSection": [
      {
        "Class": "IN",
        "Name": ".",
        "RData": {
          "Flags": 0,
          "Options": null,
          "Version": 0
        },
        "TTL": 1232,
        "Type": "OPT"
      }
    ],
    "AnswerSection": null,
    "AuthoritySection": null,
    "CD": 0,
    "ID": 23357,
    "NSCOUNT": 0,
    "OPCODE": 0,
    "QDCOUNT": 1,
    "QR": 0,
    "QuestionSection": [
      {
        "Class": "IN",
        "QName": "example.com.",
        "Type": "A"
      }
    ],
    "RA": 0,
    "RCODE": 0,
    "RD": 1,
    "TC": 0,
    "Z": 0
  },
  "sent": "2026-10-19T12:23:23.951037015Z",
  "response": {
    "AA": 0,
    "AD": 0,
    "ANCOUNT": 2,
    "ARCOUNT": 1,
    "AdditionalSection": [
      {
        "Class": "IN",
        "Name": ".",
        "RData": {
          "Flags": 0,
          "Options": null,
          "Version": 0
        },
        "TTL": 1232,
        "Type": "OPT"
      }
    ],
    "AnswerSection": [
      {
        "Class": "IN",
        "Name": "example.com.",
        "RData": {
          "address": "104.20.23.154"
        },
        "TTL": 180,
        "Type": "A"
      },
      {
        "Class": "IN",
        "Name": "example.com.",
        "RData": {
          "address": "172.66.147.243"
        },
        "TTL": 180,
        "Type": "A"
      }
    ],
    "AuthoritySection": null,
    "CD": 0,
    "ID": 23357,
    "NSCOUNT": 0,
    "OPCODE": 0,
    "QDCOUNT": 1,
    "QR": 1,
    "QuestionSection": [
      {
        "Class": "IN",
        "QName": "example.com.",
        "Type": "A"
      }
    ],
    "RA": 1,
    "RCODE": 0,
    "RD": 1,
    "TC": 0,
    "Z": 0
  },
  "received": "2026-10-19T12:23:23.955522153Z"
}
```

`Message.MarshalJSON` は JSON オブジェクトを作るので、フィールドはアルファベット順に
並びます（ヘッダのビット順ではありません）。`ID` は問い合わせごとに乱数で決まるので
実際の値は毎回違います。TTL やアドレスなどの応答の内容はサーバによります。

#### 例: NSID を要求する

```console
$ ./dq -r -nsid example.com | jq '.query.AdditionalSection[0].RData.Options'
[
  {
    "Code": 3,
    "ID": ""
  }
]
```

クエリ側に載せる NSID は長さ 0 のオプションです（RFC 7873 Section 3 の
「応答にあなたの NSID を載せてください」という要求）。サーバが NSID を返さないと
応答側の `Options` は `null` になります。

#### 例: TCP で問い合わせる

```console
$ ./dq -tcp -r example.com | jq '.response.ANCOUNT'
2
```

TCP では RFC 1035 Section 4.2 の 2 オクテットの長さプレフィックスでフレーミングされ、
応答は複数セグメントに分かれて届いても最後まで読まれます。

#### 例: EDNS0 を使わない

```console
$ ./dq -no-edns -r example.com | jq '{query_arcount: .query.ARCOUNT, response_arcount: .response.ARCOUNT}'
{
  "query_arcount": 0,
  "response_arcount": 0
}
```

#### 例: 応答を受信できなかったとき

送信に失敗しても、受信できなかったときにも送信しようとしたクエリは出力されます。
応答を読み出せなかったときは `received` が `null` になります。

```console
$ ./dq -s 127.0.0.1 -p 9 -r example.com
dq: cannot receive message from 127.0.0.1:9(read udp 127.0.0.1:34839->127.0.0.1:9: read: connection refused)
{
  "transport": "udp",
  "query": { … 送信したクエリ … },
  "sent": "2026-10-19T12:23:34.846142918Z",
  "response": null,
  "received": null
}
$ echo $?
1
```

socket に何も書いていないときは `sent` も `null` になります。

```console
$ ./dq -tcp -s 127.0.0.1 -p 9 -r example.com
dq: cannot send message to 127.0.0.1:9(dial tcp 127.0.0.1:9: connect: connection refused)
{
  "transport": "tcp",
  "query": { … 送信しようとしたクエリ … },
  "sent": null,
  "response": null,
  "received": null
}
```

### base64

`-o base64` では、送受信したメッセージのオクテット列を base64 で 1 行ずつ出します。
JSON のように構造化せず、実際に wire を通ったバイト列そのものを残す形式です。

```
sent,<送信時刻>,<transport>,<DNS メッセージの base64>
recv,<受信時刻>,<transport>,<DNS メッセージの base64>
```

- 1 行目は送信したメッセージ、2 行目は受信したメッセージです。
- `<送信時刻>`・`<受信時刻>` は `time.RFC3339Nano` 形式（`2006-01-02T15:04:05.999999999Z07:00`）
  の UTC の時刻です。送信時刻はメッセージを socket に書き出した後、受信時刻は応答の
  オクテット列を読み出した後に取った値です。
- `<transport>` は `tcp` または `udp` です。
- base64 は標準字母表（`base64.StdEncoding`）で、行の折り返しはありません。
- 復号したものは DNS メッセージそのものです。TCP のときに前置される 2 オクテットの
  メッセージ長ヘッダは含みません。
- 応答を受信できなかったときは `sent,` の行だけを出します（JSON の `"response": null` に
  対応します）。この場合の終了コードは 1 です。
- 送信そのものに失敗したとき（TCP の接続が拒否されたなど）は stdout には何も出しません。
  socket に何も書いていないためです。エラーは stderr に出ます。

#### 例: base64 で受け取る

```console
$ ./dq -r -s 172.16.253.81 -o base64 example.com
sent,2026-10-19T11:24:28.444907309Z,udp,HDIBAAABAAAAAAABB2V4YW1wbGUDY29tAAABAAEAACkE0AAAAAAAAA==
recv,2026-10-19T11:24:28.45815058Z,udp,HDKBgAABAAIAAAABB2V4YW1wbGUDY29tAAABAAHADAABAAEAAAEsAASsQpPzwAwAAQABAAABLAAEaBQXmgAAKQTQAAAAAAAA
```

4 番目のフィールドを復号すると、実際に送受信したメッセージのオクテット列になります。
先頭の 2 オクテットはメッセージ ID なので実行するたびに変わります。

```console
$ ./dq -r -s 172.16.253.81 -o base64 example.com 2>/dev/null | tail -1 | cut -d, -f4 | base64 -d | od -An -tx1 -N8
 84 3e 81 80 00 01 00 02
```

TCP のときもメッセージ長ヘッダは付きません。このクエリメッセージは 40 オクテットで、
TCP で実際に流れるオクテット数はそこに 2 を足した 42 になります。

```console
$ ./dq -r -s 172.16.253.81 -o base64 -tcp example.com 2>/dev/null | head -1 | cut -d, -f4 | base64 -d | wc -c
40
```

応答を受信できなかったときは `sent,` の行だけになります。

```console
$ ./dq -s 192.0.2.1 -timeout 1 -o base64 -r example.com
dq: cannot receive message from 192.0.2.1:53(read udp 172.17.0.2:49875->192.0.2.1:53: i/o timeout)
sent,2026-10-19T11:24:35.365182818Z,udp,1EoBAAABAAAAAAABB2V4YW1wbGUDY29tAAABAAEAACkE0AAAAAAAAA==
$ echo $?
1
```

## 動作の詳細

### 問い合わせ先サーバ

`-s` を省略すると `/etc/resolv.conf` の最初の `nameserver` の行を使い、
どのサーバに問い合わせたかを stderr に出します。

```console
$ ./dq -r example.com
dq: -s が指定されていないので 172.16.253.81 に問い合わせます
```

resolv.conf が読めない、または `nameserver` が無いときは `127.0.0.1` を使い、
その旨を stderr に出します。

サーバはホスト名でもよく、接続時に解決されます（`-s dns.google` など）。

### タイムアウト

`-timeout <n>` は接続・送信・応答待ちの上限を秒で指定します。
既定は `dnsmsg.DefaultQueryTimeout`（5 秒）です。

- 秒は小数でもよく（`-timeout 0.5`）、上限はありません。
- `0` は無制限です。応答を返すまで待ち続けます。
- 上限は接続（`net.DialTimeout`）と、その接続の送受信の両方に適用されます
  （`dnsmsg.Exchange` が `SetDeadline` で締切を設定します）。
  接続にかかった時間も待ち時間に含まれます。
- 負の数はエラーになります。

タイムアウトで失敗したときも送信したクエリは出力され、JSON では `"response": null`、
base64 では `sent,` の行だけになります。

```console
$ ./dq -s 192.0.2.1 -timeout 1 -r example.com
dq: cannot receive message from 192.0.2.1:53(read udp 172.17.0.2:50061->192.0.2.1:53: i/o timeout)
{ "query": { … 送信したクエリ … }, "response": null }
$ ./dq -timeout -1 example.com
dq: -timeout -1 は 0 秒以上で指定してください
```

`-timeout` を省略したときの待ち時間は `dnsmsg.DefaultQueryTimeout` そのものなので、
応答を返さないサーバへの問い合わせは 5 秒で失敗します。

```console
$ ./dq -s 192.0.2.1 -r example.com
dq: cannot receive message from 192.0.2.1:53(read udp 172.17.0.2:34972->192.0.2.1:53: i/o timeout)
{ "query": { … 送信したクエリ … }, "response": null }
```

### EDNS0 と NSID

既定で OPT レコードを付けます（dig と同じ挙動です）。
ペイロードサイズは `dnsmsg.EDNS0DefaultPayloadSize`（1232）、FLAGS は 0 です。
DNSSEC を要求する DO ビットを付けるオプションはありません。

`-nsid` は OPT に NSID オプションを 1 つ追加します。
OPT を付けない `-no-edns` とは同時に使えません。

### 切り詰められた応答

応答の TC ビットが 1 でも、そのまま出力します。TCP で問い直すことはしません。
必要なら `-tcp` を明示してください。

### 終了コード

| 終了コード | 意味 |
|------------|------|
| 0 | 成功。`-h` で表示を終えるときも 0 |
| 1 | QCLASS / QTYPE が分からない、送信・受信・出力に失敗した |
| 2 | 使い方のエラー（位置引数が 1 つではない、オプションの組み合わせが不正、ポート番号が範囲外、タイムアウトの値が不正、未対応の出力形式） |

### 使い方のエラーの例

```console
$ ./dq -o yaml example.com
dq: 出力形式 "yaml" には対応していません (base64, json のみ)
$ ./dq -tcp -udp example.com
dq: -tcp と -udp は同時に指定できません
$ ./dq -nsid -no-edns example.com
dq: -nsid は -no-edns と同時に指定できません
$ ./dq -p 0 example.com
dq: ポート番号 0 が範囲外です
```

## 内部で使っている API

| 段階 | 使っている API |
|------|----------------|
| クエリの構築 | `Message.SetQuery`（Question セクション）、`Message.SetEDNS0`（OPT と EDNS option） |
| メッセージ ID | `crypto/rand` による 16 bit の乱数 |
| 送信・受信 | `dnsmsg.Exchange`（送受信したオクテット列と時刻を `QueryExchange` で返す。`SendQuery` / `SendQueryWithTimeout` はこれを呼ぶ。[index.md](index.md) 参照） |
| json 出力 | `jsonDocument`（`transport` / `query` / `sent` / `response` / `received`）を `json.MarshalIndent` 経由で出力。`query`・`response` は `Message.MarshalJSON`、`sent`・`received` は `QueryExchange` の `SentAt` / `ReceivedAt` を `time.RFC3339Nano` 形式で |
| base64 出力 | `QueryExchange` の `QueryWire` / `ReplyWire` を `base64.StdEncoding` で、`SentAt` / `ReceivedAt` を `time.RFC3339Nano` で出力 |

出力形式は `outputFormat` インターフェース（`write(w io.Writer, ex *exchange) error`）で
受け、`outputFormats` の map で `-o` の名前に対応づけています。
形式を増やすときは `outputFormat` を実装して map に追加します。
`exchange` は `dnsmsg.QueryExchange` といっしょに失敗の情報も持つ、CLI 側の型です。

`cmd/dq/main.go` はテストしやすくなるように、引数の解析（`parseArgs`）、
クエリの構築（`buildQuery`）、処理全体（`run(args, stdout, stderr) int`）に
分かれています。`main` は `run(os.Args[1:], os.Stdout, os.Stderr)` の終了コードを
`os.Exit` に渡すだけです。

## 関連リンク

- [index.md](index.md) — パッケージの概要、`SendQuery` によるクエリ送信
- [edns.md](edns.md) — EDNS(0) / OPT レコードと EDNS option（NSID の wire 表現を含む）
