# Prism
Prism is a reverse proxy that enables stateless session management.

## Project Directory Overview
```text
prism
├── api     ... Example backend API server
├── client  ... Example backend Web server that hosts application in `react` directory
├── dev     ... Development environment source codes
├── envs    ... Environment files for docker compose
├── pkg     ... Public package which can be used from other projects
├── proxy   ... Reverse proxy that can be used as a product
└── react   ... Example frontend application
```

## Example App
Tested on:
* Ubuntu 24.04.2 LTS
* Docker version 28.3.1, build 38b7060
* GNU Make 4.3

Example app consists from 3 components:
* `prism-proxy`: reverse proxy
* `prism-client`: frontend Web server
* `prism-api`: backend api server

`/api` および `/api/*` へのアクセスは `prism-api` へとルーティングされ、それ以外は `prism-client` にルーティングされる。

### Build Example
```
make build
```

デバッギングコードを抑制したリリースモードでビルドしたい場合は以下。

```
MODE=release make build
```


### Run Example
```
make dev
```

## Development Environment
Tested on:
* Ubuntu 24.04.2 LTS
* Docker version 28.3.1, build 38b7060
* GNU Make 4.3

### Building a Development Environment
```
make image
```

上記コマンドは `go-prism-dev:202507` という開発環境を作成し、これは `Prism` のビルドに十分な構成である。
このイメージのデフォルトユーザーは、ビルドしたユーザーの UID, GID を持ったユーザーになる。

### Entering into a Development Environment
```
make shell
```

上記コマンドは `make image` で作成した開発環境にエンターする。
カレントディレクトリを `/work` にバインドマウントするため、引き続き `Makefile` 内のコマンドを使用できる。

### Using Development Commands
```
# Build product reverse proxy
make proxy

# Format codes
make format

# Test codes
make test

```

## Stateless Session

──────────────────────────────────────────────────────────────────────────────
 Double-Submit Cookie (AES-GCM 暗号化付き)
──────────────────────────────────────────────────────────────────────────────


Prism の Double-Submit Cookie は独自に拡張した JWT である AES-GCM JWT を用いる。
将来的な拡張を見込んで暗号化アルゴリズムは AAD が使えるアルゴリズムであればなんでも使えるようになっている。
クライアントには以下の２種類のトークンが保存される。
  - SecretCookie ... HttpOnly: true
  - AccessCookie ... HttpOnly: false
クライアントはサーバーの状態を変更しうるリクエストを投げる場合、
AccessCookie を JavaScript から読み取り、リクエストヘッダーに SubmitHeader として付与する。
CSRF ではヘッダーを書き換えることができないため、Prism は SecretCookie と SubmitHeader の中にある
トークンIDを比較することで正規の処理であることを検証できる。
XSS は防ぐことができないが、これは他の CSRF 対策と変わらない。
Prism の SecretCookie, AccessCookie に用いられる AES-GCM JWT のフォーマットは以下である。

--- SecretCookie ---
  base64url(AES-GCM([ base64url(json(JwtHeader)) ] . [ base64url(json(JwtClaims{base64url(secretPayload)})) ]))

--- AccessCookie ---
  base64url(AES-GCM([ base64url(json(JwtHeader)) ] . [ base64url(json(JwtClaims{base64url(accessPayload)})) ])) . [ base64url(publicPayload) ]

仕様の詳細は以下である。
  - AES-GCM JWT の JwtHeader, JwtClaims は JSON -> base64url でエンコードされ、"." で結合されたのち全体が AES-GCM で暗号化され、base64url で再エンコードされる。
  - AES-GCM JWT は全体が AES-GCM で暗号化される際、AAD を付加してよい。付加した AAD は AES-GCM -> base64url で暗号化された文字列に、"." で結合して付加する。
  - secretPayload, accessPayload, publicPayload は Prism によって base64url でエンコードされる。
  - SecretCookie の JwtClaims は Usr という拡張フィールドを持ち、secretPayload を保存できる。
  - AccessCookie の JwtClaims は Usr という拡張フィールドを持ち、accessPayload を保存できる。
  - AccessCookie は publicPayload を AAD として付加できる。すなわち publicPayload は改ざんを検知できる。
  - SecretCookie と AccessCookie の JwtClaims.Jti は常に同じ値を持つ。

Prism はクライアントから以下の３種類の経路でトークンを受け取ることができる。
それぞれの経路と取得されたトークンの呼称の対応は以下である。
  - SecretCookie -> SecretToken
  - AccessCookie -> AccessToken
  - SubmitHeader -> SubmitToken
Prism の Double-Submit Cookie の方式においては、
原理的に AccessToken と SubmitToken はまったく同じ文字列であることが期待される。
また SecretToken と AccessToken は同じ Jti を持つため、SecretToken と SubmitToken の Jti を比較すると一致することが期待される。
Prism はそれぞれのトークンから以下の情報を取り出してリクエストヘッダに付与し、バックエンドに送信する。
  - SecretToken -> secretPayload
  - AccessToken -> accessPayload, publicPayload
ただしユーザーが SubmitHeader をリクエストに付与しなかった場合、accessPayload だけはバックエンドに送信されない。
また、オプションで SecretToken, AccessToken で共通の Jti をリクエストヘッダに付与することができ、
バックエンドはこの Jti をセッション管理用の ID として扱ってもよい。
バックエンド側はリクエストヘッダに accessPayload が付与されているか否かで Double-Submit Cookie が行われたかどうかを知ることができる。
バックエンド側は以下のようにペイロードを使い分けることができる。
  - secretPayload ... Cookie が存在する限り常にバックエンドに送信される情報で、クライアント側からは暗号化されていて読み取れない。
  - accessPayload ... Double-Submit Cookie が行われた場合にのみバックエンドに送信される情報で、クライアント側からは暗号化されていて読み取れない。
  - publicPayload ... Cookie が存在する限り常にバックエンドに送信される情報で、クライアント側から読み取れるが、改ざんはできない。
たとえばユーザーIDは secretPayload、アプリに表示するユーザー名は publicPayload に保存しておくのがよいだろう。

バックエンド側はレスポンスヘッダに secretPayload, accessPayload, publicPayload を付与することで、
Prism は自動的にそれらを読み取り、既に Cookie に保存されているペイロードと比較して変更がある場合に Cookie を更新する。
バックエンド側にサーバーが複数存在する場合、複数のサーバーがペイロードを更新しようとすると競合することがある。
すなわちサーバー１のレスポンスによって更新されたペイロードがサーバー２によって更新されることがあり、
その次にサーバー１に対して送られたリクエストに付与された Cookie が、サーバー１がかつて想定したものとはならない可能性がある。
これを防ぐために、Prism は IdentityCenter として登録されたバックエンド以外からのペイロードを無視することができる。
バックエンド側はブラウザに設定されている Cookie 更新のレートリミット及び Cookie の 4KB 制限にも留意すべきである。

Prism は SecretCookie と AccessCookie に異なる MaxAge を指定し、一般に AccessCookie の有効期間のほうが長い状態を想定する。
目安としてはおおよそ以下である。
  - SecretCookie ... ７日ほど
  - AccessCookie ... 30日ほど
この措置により、Prism は AccessCookie を SecretCookie 更新用のトークンとみなすことができる。
すなわち SecretCookie の有効期限が切れていても、AccessCookie が有効であれば、
その情報をもとに SecretCookie と AccessCookie を自動更新することができる。
オプションで、自動更新されたかどうかを PRISM-PROXY-STATUS のような名前をキーとしてリクエストヘッダーに付与することができる。

クライアントからの GET リクエスト時は、多くの場合ブラウザが自動送信するもので SubmitHeader が付加されない。
したがって GET 時は SecretCookie さえ指定されていれば認証済みとみなしてよい。
POST や PUT などのサーバーの状態を改変する重要な操作や、機密度の高い情報を取得するための一部の GET リクエスト時には、
CSRF を防ぐためにクライアントは SubmitHeader をリクエストに付加することが推奨される。
バックエンド側は SubmitHeader を解凍した accessPayload がリクエストヘッダに付加されているかどうかを
必要に応じて確認し、リクエストを許可するかどうかを判断すべきである。
