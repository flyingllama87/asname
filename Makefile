VERSION ?= 0.16.0
BUILDDIR ?= build
BINDIR ?= /usr/local/bin
PREFIX ?= /usr/local
WEBDIR ?= $(PREFIX)/share/asname/web
LISTEN ?= 127.0.0.1:8086
# MAX_AGE, when set (e.g. 168h), fixes the service's refresh age; empty lets
# the web UI choose it.
MAX_AGE ?=
UNITDIR ?= /etc/systemd/system
USERUNITDIR ?= $(HOME)/.config/systemd/user
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
	@printf "  $(CYAN)%-14s$(RESET) %s\n" "install" "Install built binary to BINDIR (default: $(BINDIR)); run build first"
	@printf "  $(CYAN)%-14s$(RESET) %s\n" "uninstall" "Remove binary from BINDIR"
	@printf "  $(CYAN)%-14s$(RESET) %s\n" "clean" "Remove build artifacts ($(BUILDDIR)/*)"
	@printf "  $(CYAN)%-14s$(RESET) %s\n\n" "deps" "Download Go dependencies"
	@printf "$(BOLD)Web UI & Service Targets:$(RESET)\n"
	@printf "  $(CYAN)%-22s$(RESET) %s\n" "web" "Build the web UI into web/dist (needs Node.js and npm)"
	@printf "  $(CYAN)%-22s$(RESET) %s\n" "install-web" "Install the built web UI to WEBDIR (default: $(WEBDIR)); run web first"
	@printf "  $(CYAN)%-22s$(RESET) %s\n" "uninstall-web" "Remove the web UI from WEBDIR"
	@printf "  $(CYAN)%-22s$(RESET) %s\n" "install-service" "Install and start the system service (as root; databases in /var/lib/asname)"
	@printf "  $(CYAN)%-22s$(RESET) %s\n" "uninstall-service" "Stop and remove the system service, keeping its databases"
	@printf "  $(CYAN)%-22s$(RESET) %s\n" "install-user-service" "Install and start a systemd user service sharing ~/.asname"
	@printf "  $(CYAN)%-22s$(RESET) %s\n\n" "uninstall-user-service" "Stop and remove the user service"
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
	@printf "  %-14s %s\n" "WEBDIR" "Web UI installation directory (current: $(WEBDIR))"
	@printf "  %-14s %s\n" "LISTEN" "Address the service listens on (current: $(LISTEN))"
	@printf "  %-14s %s\n" "MAX_AGE" "Service refresh age, e.g. 168h; empty lets the web UI set it (current: $(if $(MAX_AGE),$(MAX_AGE),empty))"
	@printf "  %-14s %s\n" "UNITDIR" "System unit directory (current: $(UNITDIR))"
	@printf "  %-14s %s\n" "USERUNITDIR" "User unit directory (current: $(USERUNITDIR))"
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
	cp -f README.md CHEATSHEET.md LICENSE NOTICE $(BUILDDIR)/
	tar -zcf asname-$(GOOS)-$(GOARCH)-v$(VERSION).tar.gz -C $(BUILDDIR) asname README.md CHEATSHEET.md LICENSE NOTICE

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
install:
	@test -f $(BUILDDIR)/asname || { echo "$(BUILDDIR)/asname not found; run 'make build' first"; exit 1; }
	mkdir -p $(DESTDIR)$(BINDIR)
	cp -f $(BUILDDIR)/asname $(DESTDIR)$(BINDIR)/

.PHONY: uninstall
uninstall:
	rm -f $(DESTDIR)$(BINDIR)/asname

.PHONY: web
web:
	cd web && npm ci && npm run build

.PHONY: install-web
install-web:
	@test -f web/dist/index.html || { echo "web/dist not found; run 'make web' first"; exit 1; }
	@test -n "$(WEBDIR)" || { echo "WEBDIR is empty"; exit 1; }
	rm -rf "$(DESTDIR)$(WEBDIR)"
	mkdir -p "$(DESTDIR)$(WEBDIR)"
	cp -R web/dist/. "$(DESTDIR)$(WEBDIR)/"

.PHONY: uninstall-web
uninstall-web:
	@test -n "$(WEBDIR)" || { echo "WEBDIR is empty"; exit 1; }
	rm -rf "$(DESTDIR)$(WEBDIR)"

# The services run the installed binary and web UI; install them first with
# `make build web && sudo make install install-web`. With DESTDIR set (when
# packaging), the unit is written but systemctl is not run.
define check_installed
	@test -x "$(DESTDIR)$(BINDIR)/asname" || { echo "$(BINDIR)/asname not found; run 'make build' and 'make install' first"; exit 1; }
	@test -f "$(DESTDIR)$(WEBDIR)/index.html" || { echo "$(WEBDIR) not found; run 'make web' and 'make install-web' first"; exit 1; }
endef

define render_unit
	@test -z "$(MAX_AGE)" || echo "$(MAX_AGE)" | grep -Eq '^([0-9]+(\.[0-9]+)?(h|m|s))+$$' || { echo "MAX_AGE must be a duration in hours, minutes or seconds, such as 168h for a week (not $(MAX_AGE))"; exit 1; }
	sed -e 's|@BINDIR@|$(BINDIR)|g' -e 's|@WEBDIR@|$(WEBDIR)|g' -e 's|@LISTEN@|$(LISTEN)|g' \
		-e 's|@EXTRA_ARGS@|$(if $(MAX_AGE), --max-age $(MAX_AGE))|g' $(1) > $(2)
	chmod 644 $(2)
endef

.PHONY: install-service
install-service:
	$(check_installed)
	mkdir -p "$(DESTDIR)$(UNITDIR)"
	$(call render_unit,contrib/systemd/asname.service.in,"$(DESTDIR)$(UNITDIR)/asname.service")
	@if [ -z "$(DESTDIR)" ]; then \
		systemctl daemon-reload && systemctl enable --now asname.service && \
		echo "asname is starting on http://$(LISTEN)/ (the first start downloads the core databases; follow it with 'journalctl -u asname -f')"; \
	fi

.PHONY: uninstall-service
uninstall-service:
	@if [ -z "$(DESTDIR)" ]; then systemctl disable --now asname.service 2>/dev/null || true; fi
	rm -f "$(DESTDIR)$(UNITDIR)/asname.service"
	@if [ -z "$(DESTDIR)" ]; then \
		systemctl daemon-reload; \
		echo "The service's databases are kept in /var/lib/private/asname; remove them with 'sudo rm -rf /var/lib/private/asname'"; \
	fi

.PHONY: install-user-service
install-user-service:
	$(check_installed)
	mkdir -p "$(DESTDIR)$(USERUNITDIR)"
	$(call render_unit,contrib/systemd/asname-user.service.in,"$(DESTDIR)$(USERUNITDIR)/asname.service")
	@if [ -z "$(DESTDIR)" ]; then \
		systemctl --user daemon-reload && systemctl --user enable --now asname.service && \
		echo "asname is starting on http://$(LISTEN)/ with the databases in ~/.asname (follow it with 'journalctl --user -u asname -f'; run 'loginctl enable-linger' to keep it running after you log out)"; \
	fi

.PHONY: uninstall-user-service
uninstall-user-service:
	@if [ -z "$(DESTDIR)" ]; then systemctl --user disable --now asname.service 2>/dev/null || true; fi
	rm -f "$(DESTDIR)$(USERUNITDIR)/asname.service"
	@if [ -z "$(DESTDIR)" ]; then systemctl --user daemon-reload; fi
