REGISTRY ?= local
OUT_DIR ?= out
ENCLAVE_PACKAGE ?= nautilus-example-hash-attestor
ENCLAVE_BIN ?= $(ENCLAVE_PACKAGE)
EIF_INPUTS := Cargo.toml Cargo.lock rust-toolchain.toml Containerfile.eif .dockerignore $(shell find crates examples eif scripts -type f)

.DEFAULT_GOAL := eif

.PHONY: eif
eif: $(OUT_DIR)/nitro.eif

$(OUT_DIR):
	mkdir -p $(OUT_DIR)

$(OUT_DIR)/nitro.eif: $(EIF_INPUTS) | $(OUT_DIR)
	docker build \
		--pull \
		--tag $(REGISTRY)/nautilus-rust-enclave \
		--progress=plain \
		--platform linux/amd64 \
		--provenance=false \
		--output type=local,rewrite-timestamp=true,dest=$(OUT_DIR) \
		-f Containerfile.eif \
		--build-arg ENCLAVE_PACKAGE=$(ENCLAVE_PACKAGE) \
		--build-arg ENCLAVE_BIN=$(ENCLAVE_BIN) \
		.

.PHONY: run-eif
run-eif: $(OUT_DIR)/nitro.eif
	sudo nitro-cli run-enclave \
		--cpu-count 2 \
		--memory 512M \
		--eif-path $(OUT_DIR)/nitro.eif

.PHONY: run-eif-debug
run-eif-debug: $(OUT_DIR)/nitro.eif
	sudo nitro-cli run-enclave \
		--cpu-count 2 \
		--memory 512M \
		--eif-path $(OUT_DIR)/nitro.eif \
		--debug-mode \
		--attach-console
