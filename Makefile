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

# Build the device-test KPM against Android 16 / Linux 6.12 headers.
KPM_SRC := kpm/dynalab_kpm.c
KPM_OBJ := $(BUILD)/dynalab_kpm.o
KPM_OUT := $(BUILD)/KPMDynaLab-0.3.1-test.kpm
KPM_INCLUDES := \
	-I$(KDIR)/arch/arm64/include \
	-I$(KDIR)/arch/arm64/include/generated \
	-I$(KDIR)/include \
	-I$(KDIR)/arch/arm64/include/uapi \
	-I$(KDIR)/arch/arm64/include/generated/uapi \
	-I$(KDIR)/include/uapi \
	-I$(KDIR)/include/generated/uapi
KPM_CFLAGS := -D__KERNEL__ -DMODULE '-DKBUILD_MODNAME="KPMDynaLab"' \
	-O2 -fno-pic -fno-stack-protector -mgeneral-regs-only \
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
