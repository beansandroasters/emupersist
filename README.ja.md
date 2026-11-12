# emupersist

[English](README.md) | 日本語

[AWS Emulator](https://github.com/aws/aws-emulator) は状態をメモリにしか持たないので、止めるとすべて消えます。
emupersist はエミュレータの前に置く HTTP プロキシで、**状態を変えたリクエストを記録し、次に起動したときに同じ順で流し直します**。
記録(ジャーナル)の保存先はローカルファイル、SQLite、DynamoDB、S3 から選べます。

```
SDK / CLI ──HTTP──▶ emupersist :4566 ──HTTPS──▶ aws-emulator (-a off, 子プロセス)
                       │  2xx で終わった書き込み系のリクエストを追記する
                       ▼
                 ジャーナル (file / sqlite / dynamodb / s3)
```

- 実行ファイルは1つで、x86_64 Linux の release ビルドで 4.5 MB
- 依存は少なく、非同期ランタイム・HTTP フレームワーク・AWS SDK を使わない([依存](#依存))
- リプレイのたびに変わる乱数の ID も、クライアントからは変わらないように見せる([再起動で変わる ID](#再起動で変わる-id))

> AWS Emulator は Amazon Web Services の製品で、このツールは AWS とは関係のない独立したものです。
> AWS Emulator と同じく開発とテストのためのもので、本番での利用は想定していません。

## リクエストを記録する理由

エミュレータの状態をまるごと保存する方式(スナップショット)は取りませんでした。
状態はサービスごとの Rust の構造体としてメモリ上にあり、その多くはシリアライズできる形になっていません。
シリアライズできるように手を入れると、エミュレータのフォークを抱え続けることになり、頻繁なリリースに追従できません。

一方で、HTTP の口は全サービスに共通で、署名の検証を外す `-a off` という起動オプションもあります。
そこで emupersist はエミュレータの内部に触れず、外から HTTP で状態を作り直します(イベントソーシング)。
エミュレータにサービスが増えても、この方式はそのまま使えます。

## ビルド

```bash
cargo build --release                         # SQLite 込み(C コンパイラが要る)
cargo build --release --no-default-features   # SQLite なし(純 Rust の依存だけ)
```

Rust 1.89 以上が必要です(依存クレートが求める最低バージョンのうち、最も新しいもの)。
aws-emulator は[公式の手順](https://docs.aws.amazon.com/emulator/latest/userguide/getting-started-linux.html)に従って入れてください。

## 使い方

```bash
# aws-emulator を PATH に置くか、--emulator で場所を渡す
./target/release/emupersist run --store file:.emupersist/journal.jsonl -- -t off

# 別のシェルで
export AWS_ENDPOINT_URL=http://127.0.0.1:4566 AWS_REGION=us-east-1
export AWS_ACCESS_KEY_ID=AKIATEST AWS_SECRET_ACCESS_KEY=dummy
aws dynamodb list-tables
```

`--` より後ろの引数はそのまま aws-emulator に渡ります(上の例ではテレメトリを切っています)。
Ctrl-C で止めてもう一度 `run` すると、emupersist はジャーナルを流し直してから待ち受けを始めます。

| コマンド | 働き |
|---|---|
| `emupersist run` | aws-emulator を子プロセスとして起動し(`-b 127.0.0.1 -p 0 -a off`)、リプレイしてから待ち受ける |
| `emupersist proxy --upstream URL --ca FILE` | 自分で起動したエミュレータの前に立つ。エミュレータは `-a off` で起動し、空の状態から始めてください |
| `emupersist inspect` | 記録したリクエストの一覧を表示する |
| `emupersist reset` | ジャーナルを全部消す |
| `emupersist init-store` | ジャーナルを置く DynamoDB のテーブルを作る |

主なオプションは次のとおりです。すべてのオプションは `emupersist --help` で見られます。

- `--store URL`(環境変数 `EMUPERSIST_STORE`)
- `--namespace NAME`
- `--port`(既定は 4566。0 を渡すと空いているポートを使う)
- `--bind`(既定は 127.0.0.1)
- `--allow-origin ORIGIN`(このオリジンのブラウザからのリクエストを受け付ける。[セキュリティ](#セキュリティ)を参照)
- `--max-body-bytes N`(受け付けるリクエストボディの上限。既定は 512 MiB)
- `--write-op OP` / `--read-op OP`(その操作を書き込みとして扱うかどうかの判定を上書きする)
- `--replay-retry-seconds`(リプレイ中のリトライに使う時間の合計。既定は 30)
- `--strict`(1件でもリプレイに失敗したら起動しない)

起動中は次の管理用の口が使えます。

- `GET /__persist/status` は記録の件数、保存先、ID の対応の数、記録に失敗したかどうかを返す
- `GET /__persist/journal` は記録の一覧をボディを除いて返す
- `POST /__persist/reset` はジャーナルを消してエミュレータを起動し直す(`run` のときだけ)

## 保存先

設定ファイルはありません。保存先は URL で渡します。

```bash
emupersist run --store file:.emupersist/journal.jsonl
emupersist run --store sqlite:./state.db --namespace feature-x
emupersist init-store --store "dynamodb://my-journal?region=ap-northeast-1"   # テーブルを作る
emupersist run        --store "dynamodb://my-journal?region=ap-northeast-1"
emupersist run        --store "s3://my-bucket/emupersist?region=ap-northeast-1&profile=dev"
```

| 保存先 | 向いている場面 | 複数の書き手 | 補足 |
|---|---|---|---|
| `file:` | 手元での開発。中身を人が読める | 検知しない | 1件ごとに fsync する。書きかけの最終行は読み込み時に切り詰める。ファイルは 0600 で作る |
| `sqlite:` | 手元で複数の状態(`--namespace`)を切り替える | 主キーで検知する | WAL モードで開く。ファイルは 0600 で作る。feature `sqlite`(既定で有効) |
| `dynamodb://` | チームや CI で状態を共有する | 条件付き書き込みで検知する | 400 KB を超えるレコードは分けて書く。追記は1件あたり約 5 ms |
| `s3://` | CI の実行のあいだで状態を引き継ぐ。大きな S3 オブジェクトを含む状態 | `If-None-Match: *` で検知する | 起動時にレコード1件ごとに GET を送る。追記は1件あたり約 26 ms |

追記の時間は ap-northeast-1 の EC2 インスタンスから同じリージョンへ 10 件書いたときの平均です。

ネームスペースに使える文字は英字、数字、`.`、`_`、`-` だけです。
DynamoDB と S3 への書き込みはネットワークのエラー、5xx のレスポンス、スロットリングのときに、間隔を空けながらやり直します。
条件付き書き込みが既存の項目やオブジェクトにぶつかっても、その中身が書こうとした内容と同じなら成功として扱います。レスポンスだけが失われた、このプロセス自身の前回の試みだからです。

DynamoDB と S3 の URL には `region=`、`profile=`、`endpoint=`、`ca=` を付けられます。
クレデンシャルは環境変数、`~/.aws/credentials` の静的なキー、`credential_process` の順に探します。
SSO と `role_arn` の連鎖には対応していません。その場合は `aws configure export-credentials --profile NAME --format env` の出力を環境変数に入れて使ってください。

検討したが入れなかった保存先は次のとおりです。

- Redis / ElastiCache: 追記には向きますが、手元で動かすサーバが1つ増えます
- PostgreSQL / Aurora: 共有はできますが、ドライバの分だけ依存が増えます
- 共有ファイルシステム上の SQLite: ネットワーク越しのファイルロックは信頼できません。共有するなら DynamoDB を使ってください
- Git リポジトリ: リクエストごとにコミットするのは重すぎます。`file:` のジャーナルを自分でコミットすれば、同じことができます

## 再起動で変わる ID

エミュレータの ID には連番で振られるものと乱数で振られるものがあります。
たとえば EC2 の VPC ID は連番で振られます(`vpc-00000000000000080`)。
Secrets Manager の ARN の末尾、KMS のキー ID、IAM のアクセスキーは乱数で振られます。
乱数の ID はリプレイのたびに変わるので、クライアントが再起動の前に控えた ARN は、再起動の後には使えなくなります。

そこで emupersist はレスポンスも記録しておきます。リプレイでは、記録したレスポンスと新しいレスポンスを構造で突き合わせ、
同じ位置にあって値だけが違う文字列を、記録時の ID から今の ID への対応として覚えます。
それ以降はリクエストを今の ID に書き換えてからエミュレータに送り、レスポンスを記録時の ID に書き戻してからクライアントに返します。
クライアントから見ると、ID は最初に見たときのまま変わりません。
IAM で作ったアクセスキーで署名したリクエストも今のキーに書き換えるので、`GetCallerIdentity` は正しいユーザーを返します。

書き換えるのはパス、ヘッダ、テキストのボディ(JSON / XML / フォーム)だけです。
S3 のオブジェクトのボディには、content type が JSON でも手を付けません。利用者のデータで、チェックサムで守られているからです。
バケットの設定のボディ(`?encryption`、`?policy`、`?notification` など)には ID が入りうるので、書き換えます。
ボディを書き換えたときは、そのボディに結び付いた整合性のヘッダ、`x-amz-crc32`(DynamoDB)、`Content-MD5`、`x-amz-checksum-*`、`x-amz-content-sha256` を計算し直します。

状態(`PENDING` から `RUNNING` へ)のように変わるのが正しい値まで覚えると、関係のないリクエストまで書き換えてしまいます。
そのため、次のものは覚えません。

- 時刻、数値、真偽値、HTTP の日付、6文字未満の値
- 数字も `:` も `/` も含まず、語の途中で大文字と小文字が混ざらず、16 文字以上の英数字の並びでもない値(`available` や `CREATE_IN_PROGRESS` のような英単語や列挙値)
- 名前が RequestId、Token、Status、State、Message などで終わる項目

## わかっている制約

- 時刻で決まる状態はリプレイした時刻を起点に作り直されます。SQS の保持期間、DynamoDB の TTL、クレデンシャルの有効期限などは、リクエストを記録した時点ではなく起動した時点から数えます。
- 非同期に変わる状態はリトライして待ちます。CreateTable の直後のテーブルは `CREATING` なので、続く PutItem はリプレイ中に一度失敗します。
  記録したときに成功し、今回は失敗したリクエストは、間隔を伸ばしながらリトライします。
  リプレイ全体でリトライに使う時間の合計は `--replay-retry-seconds` までです。バージョンが変わって食い違いが大量に出ても、起動が長く止まらないようにしています。
  失敗したリクエストは状態を変えていないので、リトライしても二重には適用されません。
- 同時に来た書き込みは、レスポンスが返った順に記録します。並行して走った2つのリクエストが、エミュレータが適用した順とは違う順で記録されることがあります。
- ジャーナルは伸び続けます。内部の状態をシリアライズできないので、ジャーナルを縮めること(compaction)はできません。必要なら `reset` で作り直してください。
- リクエストが書き込みかどうかは推測で決めています。RPC の操作は名前の先頭(`Describe*` / `List*` / `Get*` …)で、REST の操作は HTTP メソッドで判断します。
  迷ったときは書き込みとして記録します。推測が外れたら、`--write-op` / `--read-op` で上書きしてください。
  SQS の ReceiveMessage はメッセージを1件も返さなかったときだけ記録しません。ポーリングでジャーナルが伸びないようにするためです。
- ID の対応づけも推測です。ID らしくない値は対象から外している([上の説明](#再起動で変わる-id))が、覚えた ID とたまたま一致した文字列が書き換えられる可能性は残ります。
- エミュレータのバージョンが変わると、リプレイの結果も変わることがあります。記録にはエミュレータのバージョンを添えていて、起動時に違えば警告を出します。
- エミュレータが状態として持つ副作用は、元のリクエストを流し直すことで再現します。たとえば Lambda の Invoke は関数をもう一度実行します。
- 前段は平文の HTTP しか話しません。SDK は `http://` のエンドポイントを受け付けるが、HTTPS を必須とするクライアントは emupersist を使えません。
- リクエストボディはメモリに載せます。`--max-body-bytes`(既定 512 MiB)を超えるボディは 413 で断ります。
- 異常終了したときに子プロセスを片付けるのは Linux だけです。Linux では、emupersist が SIGKILL で止められても、エミュレータに SIGTERM が届きます(`PR_SET_PDEATHSIG`)。macOS では、emupersist が SIGTERM か Ctrl-C で終わったときだけエミュレータを止めます。

## セキュリティ

- emupersist の後ろのエミュレータは署名を検証しません(`-a off`)。エミュレータのクレデンシャルは起動のたびに変わるので、記録した署名は再起動の後には検証を通らないからです。
  emupersist は既定で 127.0.0.1 だけで待ち受けます。`--bind` で外に開くと、届く人は誰でも状態を変えたり reset したりできます(管理用の口にも認証はありません)。
- 127.0.0.1 で待ち受けるだけでは足りません。ブラウザで開いた悪意あるページからも、リクエストは届きます。emupersist はこの種の攻撃のうち次の2つを防ぎます。
  - CSRF: `Origin` ヘッダの付いたリクエストは 403 で断ります。ブラウザは別のオリジンへの POST や fetch にこのヘッダを付けるからです。ブラウザ用の SDK を使うときは、`--allow-origin http://localhost:3000` のようにそのオリジンを許してください(繰り返し指定でき、`*` ならすべてを許します)。
  - DNS rebinding: `Host` がループバックの名前(127.0.0.1、localhost、::1)でも待ち受けアドレスでもないリクエストは断ります。0.0.0.0 のような特定しないアドレスで待ち受けるときは、この確認をしません。
- 壊れた入力は信用せずに断ります。大きすぎるボディ(413)、大きすぎるヘッダ(431)、途中で切れた chunked のボディ、`Transfer-Encoding` と `Content-Length` を両方持つリクエストが対象です。同時に受け付ける接続は 512 までで、何も送ってこない接続は 300 秒で閉じます。
- 記録では Authorization の署名と署名付き URL の署名を伏せ、`X-Amz-Security-Token` を捨てています。
- CI(`.github/workflows/security.yml`)では、push と pull request のたびと毎週 1 回、`cargo deny check` と CodeQL を回します。`cargo deny check` は RustSec のアドバイザリ、取り下げられた版、ライセンス、crates.io 以外からの依存を検査します(設定は `deny.toml`)。CodeQL は Rust のコードとワークフロー自体を検査します。アクションはコミット SHA で固定し、Dependabot は公開から 7 日経った版だけを提案します。
- 脆弱性の報告の方法は [SECURITY.md](SECURITY.md) にあります。
- **ジャーナルにはリクエストボディがそのまま入ります**(シークレットの値、アクセスキー ID など)。テスト用の値だけを入れてください。
  `.gitignore` は既定の置き場所 `.emupersist/` と `*.jsonl`、`*.db` を除外しています。

## 依存

エミュレータと話すには TLS が欠かせないので、TLS は rustls に任せました。それ以外は標準ライブラリで書いています。

| 直接の依存 | 用途 | 代わりに使わなかったもの |
|---|---|---|
| `rustls`(ring、std、tls12 のみ) | エミュレータと AWS への HTTPS | OpenSSL(システムに依存する) |
| `webpki-roots` | AWS につなぐときのルート証明書(データだけ) | `rustls-native-certs`(OS ごとの依存が増える) |
| `ring` | SigV4 の SHA-256 / HMAC。rustls が既に使っている | `sha2` + `hmac` |
| `serde_json` | JSON。`Value` だけを使い、derive マクロは使わない | `serde_derive`(proc-macro 一式) |
| `miniz_oxide` | DynamoDB / S3 に置くレコードの zlib | `flate2` |
| `libc` | SIGTERM の送受信。ring が既に使っている | `signal-hook`、`nix` |
| `rusqlite`(bundled、feature `sqlite`) | SQLite の保存先 | なし |

次の部分は標準ライブラリだけで書きました。

- HTTP/1.1 のサーバとクライアント(keep-alive、chunked、`Expect: 100-continue`)
- 引数の解析
- base64、URI のエンコード、日付、CRC32
- ListObjectsV2 の XML の読み取り

依存の木(`cargo tree -e normal`、このクレート自身を除く)は、既定で 28 クレート、`--no-default-features` で 19 クレートです。

## 実測値

2026-11-12 に、aws-emulator 1.0.322 と EC2 r6a.2xlarge で測りました。クライアントは1つで、keep-alive の接続を1本だけ使いました。

| 項目 | 値 |
|---|---|
| emupersist を通した PutItem(記録と fsync を含む) | 1件あたり 0.56 ms |
| emupersist を通した GetItem(記録しない) | 1件あたり 0.50 ms |
| 参考: エミュレータに直接送った PutItem / GetItem | 1件あたり 0.40 / 0.41 ms |
| 2,001 件のリプレイ(CreateTable が ACTIVE になるまでの約 3 秒の待ちを含む) | 3.8 秒 |
| 2,000 件分のジャーナル(1件 200 バイトの項目) | 2.3 MB |

## テスト

```bash
cargo test                                                  # 単体テスト
EMUPERSIST_TEST_EMULATOR=/path/to/aws-emulator cargo test   # 本物のエミュレータを相手にした往復テストも回す
```

CI(`.github/workflows/ci.yml`)では、fmt、clippy、単体テストを回し、最低対応の Rust(1.89)でビルドできるかも確かめます。往復テストには、公式の配布元から取得した aws-emulator を使います。取得したパッケージは、GPG の署名が固定した鍵の指紋で検証できたときだけ使います。

往復テストでは次のことを確かめます。

- DynamoDB の項目、KMS のキー ID とエイリアス、S3 のバイナリ(1バイト単位で)が、再起動の後も残っている
- 対応を覚えた ID を JSON の中身に含む S3 オブジェクトが、変わらずに返ってくる
- HEAD が正しい Content-Length を返し、空振りの受信を記録しない
- reset が効き、reset を頼んだ接続が閉じた後も新しいエミュレータが動き続ける
- 形式 v1 のジャーナル(`tests/fixtures/journal-v1.jsonl`)を、そのままリプレイできる
- 悪意のある入力(巨大な Content-Length、CSRF、DNS rebinding、途中で切れた chunked のボディ)を、落ちずに断り、何も記録しない
- Linux では、emupersist を SIGKILL で止めたときに、エミュレータが残らない

## ライセンス

次のどちらかを選んで使えます。

- Apache License 2.0([LICENSE-APACHE](LICENSE-APACHE))
- MIT License([LICENSE-MIT](LICENSE-MIT))

明示しない限り、このプロジェクトに含めるために意図して送られた貢献は、Apache-2.0 の定義に従い、追加の条件なしに上の2つのライセンスで提供されたものとして扱います。
