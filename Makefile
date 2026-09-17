BIN := agent-proxy
# VCS stamping is not worth failing a build over.
GOFLAGS := -buildvcs=false

.PHONY: build test vet fmt install clean dist

build:
	go build $(GOFLAGS) -o $(BIN) .

test:
	go test $(GOFLAGS) ./... -count=1

vet:
	go vet ./...

fmt:
	gofmt -w main.go internal

install: build
	install -m 0755 $(BIN) $(or $(PREFIX),/usr/local)/bin/$(BIN)

clean:
	rm -rf $(BIN) dist

dist: clean
	@mkdir -p dist
	@for target in darwin/arm64 darwin/amd64 linux/arm64 linux/amd64; do \
	  os=$${target%/*}; arch=$${target#*/}; \
	  GOOS=$$os GOARCH=$$arch go build $(GOFLAGS) -o dist/$(BIN)-$$os-$$arch . || exit 1; \
	done
	@ls -1 dist
