GO ?= go
BIN ?= ctfagent

.PHONY: all build test race vet fmt check demo clean run-examples

all: check build

build:
	CGO_ENABLED=0 $(GO) build -trimpath -o $(BIN) ./cmd/ctfagent

test:
	$(GO) test ./...

race:
	$(GO) test -race ./...

vet:
	$(GO) vet ./...

fmt:
	gofmt -w .

check: vet
	@test -z "$$(gofmt -l .)" || { echo "gofmt 不干净："; gofmt -l .; exit 1; }
	$(GO) test ./...

demo: build
	./$(BIN) demo

# 用真实模型跑示例题库（需要 CTFAGENT_API_KEY）
run-examples: build
	./$(BIN) run --platform local --suite examples/suite --concurrency 2 --out report.json

clean:
	rm -f $(BIN) report.json
	rm -rf examples/suite/.work
