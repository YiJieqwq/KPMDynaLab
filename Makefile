# KPMDynaLab build
# =================
# Portable policy tests: make test
# KPM (requires KernelPatch SDK + matching kernel headers): make kpm

HOST_CC ?= cc
TARGET_COMPILE ?= aarch64-linux-gnu-
CLI_CC ?= aarch64-linux-gnu-gcc
CC := $(TARGET_COMPILE)gcc
KP_DIR ?= $(HOME)/KernelPatch
KDIR ?=

BUILD := build
POLICY_TEST := $(BUILD)/policy_test

.PHONY: all test kpm cli clean

all: test

$(BUILD):
	mkdir -p $@

$(POLICY_TEST): src/policy.c tests/policy_test.c include/dl_policy.h | $(BUILD)
	$(HOST_CC) -std=c11 -Wall -Wextra -Werror -O2 \
		-Iinclude src/policy.c tests/policy_test.c -o $@

test: $(POLICY_TEST)
	./$(POLICY_TEST)

CLI_OUT := $(BUILD)/dynalab-arm64

cli: $(CLI_OUT)
	@file $(CLI_OUT)
	@echo "Built: $(CLI_OUT)"

$(CLI_OUT): cli/dynalab.c include/dl_rpc.h | $(BUILD)
	$(CLI_CC) -std=c11 -Wall -Wextra -Werror -O2 -static \
		-Iinclude cli/dynalab.c -o $@

# Build the device-test KPM against Android 16 / Linux 6.12 headers.
KPM_SRC := kpm/dynalab_kpm.c
KPM_OBJ := $(BUILD)/dynalab_kpm.o
KPM_OUT := $(BUILD)/KPMDynaLab-0.8.13-session-scoped-block-policy-test.kpm
KPM_INCLUDES := \
	-I$(KDIR)/arch/arm64/include \
	-I$(KDIR)/arch/arm64/include/generated \
	-I$(KDIR)/include \
	-I$(KDIR)/arch/arm64/include/uapi \
	-I$(KDIR)/arch/arm64/include/generated/uapi \
	-I$(KDIR)/include/uapi \
	-I$(KDIR)/include/generated/uapi
KPM_CFLAGS := -D__KERNEL__ -DMODULE '-DKBUILD_MODNAME="KPMDynaLab"' \
	-O2 -fno-pic -fno-stack-protector -fno-builtin -fno-asynchronous-unwind-tables \
	-fno-unwind-tables -mgeneral-regs-only -mno-outline-atomics \
	-Wno-address-of-packed-member $(KPM_INCLUDES) \
	-include $(KDIR)/include/linux/compiler-version.h \
	-include $(KDIR)/include/linux/kconfig.h

kpm: $(KPM_OUT)
	@file $(KPM_OUT)
	@echo "Built: $(KPM_OUT)"

$(KPM_OBJ): $(KPM_SRC) | $(BUILD)
	@if [ -z "$(KDIR)" ] || [ ! -f "$(KDIR)/include/generated/autoconf.h" ]; then \
		echo "error: prepare KDIR first: make ARCH=arm64 gki_defconfig prepare"; exit 1; \
	fi
	$(CC) $(KPM_CFLAGS) -c $< -o $@

$(KPM_OUT): $(KPM_OBJ)
	$(CC) -r -o $@ $<

clean:
	rm -rf $(BUILD)
	find . -name '*.o' -delete
	rm -f *.kpm
