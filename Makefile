VERSION ?= 0.9.0
BUILDDIR ?= build
BINDIR ?= /usr/local/bin
GOOS ?= $(shell go env GOOS)
GOARCH ?= $(shell go env GOARCH)
DATE = $(shell date -u +%Y%m%d)

# Terminal color support (disabled if NO_COLOR is set)
ifeq ($(NO_COLOR),)
CYAN  := \033[36m
BOLD  := \033[1m
RESET := \033[0m
else
CYAN  :=
BOLD  :=
RESET :=
endif

.DEFAULT_GOAL := help

.PHONY: help
help:
	@printf "\n$(BOLD)Usage:$(RESET) make $(CYAN)<target>$(RESET) [VARIABLE=value]\n\n"
	@printf "$(BOLD)Build & Install Targets:$(RESET)\n"
	@printf "  $(CYAN)%-14s$(RESET) %s\n" "build" "Build the asname binary ($(BUILDDIR)/asname)"
	@printf "  $(CYAN)%-14s$(RESET) %s\n" "install" "Install binary to BINDIR (default: $(BINDIR))"
	@printf "  $(CYAN)%-14s$(RESET) %s\n" "uninstall" "Remove binary from BINDIR"
	@printf "  $(CYAN)%-14s$(RESET) %s\n" "clean" "Remove build artifacts ($(BUILDDIR)/*)"
	@printf "  $(CYAN)%-14s$(RESET) %s\n\n" "deps" "Download Go dependencies"
	@printf "$(BOLD)Testing Targets:$(RESET)\n"
	@printf "  $(CYAN)%-14s$(RESET) %s\n\n" "test" "Run tests with race detection"
	@printf "$(BOLD)Packaging & Release Targets:$(RESET)\n"
	@printf "  $(CYAN)%-14s$(RESET) %s\n" "release" "Create release tarball for current platform ($(GOOS)/$(GOARCH))"
	@printf "  $(CYAN)%-14s$(RESET) %s\n\n" "release-all" "Build release tarballs for all platforms"
	@printf "$(BOLD)Help Targets:$(RESET)\n"
	@printf "  $(CYAN)%-14s$(RESET) %s\n\n" "help" "Display this list of options (default)"
	@printf "$(BOLD)Configurable Variables$(RESET) (e.g. make install BINDIR=~/.local/bin):\n"
	@printf "  %-14s %s\n" "BINDIR" "Installation directory (current: $(BINDIR))"
	@printf "  %-14s %s\n" "BUILDDIR" "Build output directory (current: $(BUILDDIR))"
	@printf "  %-14s %s\n" "VERSION" "Version string (current: $(VERSION))"
	@printf "  %-14s %s\n" "GOOS" "Target operating system (current: $(GOOS))"
	@printf "  %-14s %s\n\n" "GOARCH" "Target architecture (current: $(GOARCH))"

.PHONY: build
build: $(BUILDDIR)/asname

.PHONY: clean
clean:
	rm -f $(BUILDDIR)/*

.PHONY: deps
deps:
	go mod download

$(BUILDDIR)/asname: deps
	CGO_ENABLED=0 GOOS=$(GOOS) GOARCH=$(GOARCH) go build -ldflags '-extldflags "-static" -X main.version=$(VERSION)' -o $(BUILDDIR)/asname ./cmd/asname

.PHONY: release
release:
	$(MAKE) clean
	$(MAKE) build
	tar -zcf asname-$(GOOS)-$(GOARCH)-v$(VERSION).tar.gz -C $(BUILDDIR) .

.PHONY: release-all
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
install: build
	mkdir -p $(DESTDIR)$(BINDIR)
	cp -f $(BUILDDIR)/asname $(DESTDIR)$(BINDIR)/

.PHONY: uninstall
uninstall:
	rm -f $(DESTDIR)$(BINDIR)/asname
