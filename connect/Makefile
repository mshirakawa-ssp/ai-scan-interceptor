# AI-Scan-Connect — build & cross-compile
#
# Targets:
#   make           build for the host
#   make test      run unit tests
#   make linux     build linux/amd64 -> dist/ai-scan-connect-linux-amd64
#   make windows   build windows/amd64 -> dist/ai-scan-connect-windows-amd64.exe
#   make darwin    build darwin/amd64 + arm64 -> dist/ai-scan-connect-darwin-*
#   make all       build all three OSes
#   make clean

BIN      := ai-scan-connect
DIST_DIR := dist
PKG      := ./...
LDFLAGS  := -s -w
GOFLAGS  := -trimpath
CGO      := CGO_ENABLED=0

.PHONY: all build test linux windows darwin clean tidy vet

build:
	$(CGO) go build $(GOFLAGS) -ldflags="$(LDFLAGS)" -o $(BIN) .

test:
	go test $(PKG)

vet:
	go vet $(PKG)

tidy:
	go mod tidy

$(DIST_DIR):
	mkdir -p $(DIST_DIR)

linux: | $(DIST_DIR)
	$(CGO) GOOS=linux  GOARCH=amd64 go build $(GOFLAGS) -ldflags="$(LDFLAGS)" \
	    -o $(DIST_DIR)/$(BIN)-linux-amd64 .

windows: | $(DIST_DIR)
	$(CGO) GOOS=windows GOARCH=amd64 go build $(GOFLAGS) -ldflags="$(LDFLAGS)" \
	    -o $(DIST_DIR)/$(BIN)-windows-amd64.exe .

darwin: | $(DIST_DIR)
	$(CGO) GOOS=darwin GOARCH=amd64 go build $(GOFLAGS) -ldflags="$(LDFLAGS)" \
	    -o $(DIST_DIR)/$(BIN)-darwin-amd64 .
	$(CGO) GOOS=darwin GOARCH=arm64 go build $(GOFLAGS) -ldflags="$(LDFLAGS)" \
	    -o $(DIST_DIR)/$(BIN)-darwin-arm64 .

all: linux windows darwin

clean:
	rm -rf $(DIST_DIR) $(BIN)
