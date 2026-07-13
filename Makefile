# KPMDynaLab build
# =================
# Portable policy tests: make test
# KPM (requires KernelPatch SDK + matching kernel headers): make kpm

HOST_CC ?= cc
TARGET_COMPILE ?= aarch64-linux-gnu-
CC := $(TARGET_COMPILE)gcc
KP_DIR ?= $(HOME)/KernelPatch
KDIR ?=

BUILD := build
POLICY_TEST := $(BUILD)/policy_test

.PHONY: all test kpm clean

all: test

$(BUILD):
	mkdir -p $@

$(POLICY_TEST): src/policy.c tests/policy_test.c include/dl_policy.h | $(BUILD)
	$(HOST_CC) -std=c11 -Wall -Wextra -Werror -O2 \
		-Iinclude src/policy.c tests/policy_test.c -o $@

test: $(POLICY_TEST)
	./$(POLICY_TEST)

# The KPM adapter dereferences version-dependent block-layer structures.
# Refuse to build it without the target's matching kernel headers.
kpm:
	@if [ ! -d "$(KP_DIR)/kernel" ]; then \
		echo "error: KP_DIR must point to KernelPatch SDK"; exit 1; \
	fi
	@if [ -z "$(KDIR)" ] || [ ! -d "$(KDIR)" ]; then \
		echo "error: KDIR must point to matching target kernel source/headers"; exit 1; \
	fi
	@echo "KPM adapter build is gated until the target ABI adapter is selected."
	@echo "Run make test for the v0.2 policy prototype."
	@exit 2

clean:
	rm -rf $(BUILD)
	find . -name '*.o' -delete
	rm -f *.kpm
