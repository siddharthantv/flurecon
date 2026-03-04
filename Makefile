# flurecon Makefile
# Build runs as the current user (uses rustup cargo).
# Only the install + setcap steps require sudo.

INSTALL_DIR := /usr/local/bin
BINARY      := flurecon

.PHONY: all build release install uninstall clean check-setcap

# Default target: build debug binary
all: build

# Build debug binary using cargo
build:
	cargo build

# Build optimized release binary
release:
	cargo build --release

# Build release as current user, then elevate privileges only for install + capability setup
# Prerequisites: check-setcap, release
install: check-setcap release
	@echo "[*] Installing $(BINARY) to $(INSTALL_DIR)..."
	sudo install -m 755 target/release/$(BINARY) $(INSTALL_DIR)/$(BINARY)
	@echo "[*] Granting CAP_NET_RAW + CAP_NET_ADMIN via setcap..."
	sudo setcap cap_net_raw,cap_net_admin=eip $(INSTALL_DIR)/$(BINARY)
	@echo ""
	@echo "[+] Done. Run without sudo:"
	@echo "    $(BINARY) --interface eth0"
	@echo ""
	@getcap $(INSTALL_DIR)/$(BINARY)

# Remove installed binary from system
uninstall:
	sudo rm -f $(INSTALL_DIR)/$(BINARY)
	@echo "[+] Uninstalled."

# Clean build artifacts
clean:
	cargo clean

# Verify setcap is available; required for CAP_NET_RAW and CAP_NET_ADMIN capabilities
check-setcap:
	@which setcap > /dev/null 2>&1 || { \
		echo "[!] setcap not found. Install it with:"; \
		echo "    sudo apt install libcap2-bin"; \
		exit 1; \
	}
	@echo "[*] setcap found: $$(which setcap)"