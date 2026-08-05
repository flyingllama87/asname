VERSION = 0.2.0
BUILDDIR ?= build
BINDIR ?= /usr/local/bin
GOOS ?= $(shell go env GOOS)
GOARCH ?= $(shell go env GOARCH)
DATE = $(shell date -u +%Y%m%d)

.PHONY: build
build: $(BUILDDIR)/asname

.PHONY: clean
clean:
	rm -f $(BUILDDIR)/*

.PHONY: deps
deps:
	go mod download

$(BUILDDIR)/asname: deps
	CGO_ENABLED=0 GOOS=$(GOOS) GOARCH=$(GOARCH) go build -ldflags '-extldflags "-static" -X main.version=$(VERSION)' -o $(BUILDDIR)/asname .

.PHONY: release
release:
	$(MAKE) clean
	$(MAKE)
	tar -zcf asname-$(GOOS)-$(GOARCH)-v$(VERSION).tar.gz -C $(BUILDDIR) .

release-all:
	$(MAKE) release GOOS=linux GOARCH=amd64
	$(MAKE) release GOOS=linux GOARCH=arm64
	$(MAKE) release GOOS=linux GOARCH=386
	$(MAKE) release GOOS=darwin GOARCH=amd64
	$(MAKE) release GOOS=darwin GOARCH=arm64

.PHONY: test
test:
	go test -race ./...

.PHONY: install
install:
	cp -f $(BUILDDIR)/asname $(BINDIR)/

.PHONY: uninstall
uninstall:
	rm -f $(BINDIR)/asname
