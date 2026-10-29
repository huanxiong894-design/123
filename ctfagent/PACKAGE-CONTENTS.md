# ctf-agent package contents

This archive contains the current Go source, tests, embedded prompt/knowledge files, clean example suite, deployment/build documentation, and a Linux AMD64 executable built from this source snapshot on 2026-10-29.

## Build and verify

```sh
go test ./...
go test -race ./...
go vet ./...
make build
```

The prebuilt executable is `bin/ctfagent-linux-amd64`.

## Exclusions

This package omits historical optimization/audit notes, previous release archives and binaries, generated example work directories, runtime logs, mailbox/checkpoint data, uploaded attachments, VPN configuration, and credentials. No benchmark token, model API key, or VPN private key is included. Runtime credentials must be supplied through the deployment environment.
