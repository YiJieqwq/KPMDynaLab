# KPMDynaLab Makefile
# ====================
# 依赖: KernelPatch SDK (bmax121/KernelPatch)
# 编译: make KDIR=/path/to/kernel
#
# 输出: build/kpm_dynalab.kpm

KPM_NAME := kpm_dynalab

# KernelPatch SDK 路径 (需修改)
KP_SDK  ?= $(HOME)/KernelPatch
KERNEL_SRC ?= $(HOME)/android-kernel

# 源文件
SRCS := src/main.c \
        hook/blkdev.c \
        procfs/interface.c

OBJS := $(SRCS:.c=.o)

# 编译选项
CFLAGS := -Iinclude -I$(KP_SDK)/include \
          -Wall -Werror -O2 -fno-stack-protector \
          -DKPM_NAME=\"$(KPM_NAME)\"

# 使用 KernelPatch 的构建系统
include $(KP_SDK)/kpm.mk

all: $(KPM_NAME).kpm

clean:
	rm -f src/*.o hook/*.o procfs/*.o
	rm -f $(KPM_NAME).kpm $(KPM_NAME).ko

.PHONY: all clean
