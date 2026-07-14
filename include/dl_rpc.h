/* SPDX-License-Identifier: GPL-2.0 */
#ifndef KPM_DYNALAB_RPC_H
#define KPM_DYNALAB_RPC_H

#define DL_RPC_VERSION 1
#define DL_EVENT_MAGIC 0x444c4556u /* DLEV */
#define DL_EVENT_CAPACITY 256

enum dl_wire_event_type {
    DL_WIRE_BLOCK_WRITE = 1,
    DL_WIRE_BLOCK_IOCTL = 2,
    DL_WIRE_BLOCK_FALLOCATE = 3,
    DL_WIRE_REBOOT = 4,
};

enum dl_wire_action {
    DL_WIRE_PASS = 0,
    DL_WIRE_SIMULATE = 1,
    DL_WIRE_SUPPRESS = 2,
};

/* Fixed-width binary ABI shared by KPM and CLI. */
struct dl_wire_event {
    unsigned int magic;
    unsigned short version;
    unsigned short type;
    unsigned short action;
    unsigned short reserved;
    unsigned int pid;
    unsigned int tgid;
    unsigned int major;
    unsigned int minor;
    unsigned long long offset;
    unsigned long long length;
    unsigned int command;
    unsigned int sequence;
};

#endif
