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