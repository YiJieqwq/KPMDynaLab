/* SPDX-License-Identifier: GPL-2.0-only */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/io_uring.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/syscall.h>
#include <sys/un.h>
#include <unistd.h>

#define TEST_LEN 4096

static int open_safe_loop(const char *path)
{
    struct stat st;
    int fd = open(path, O_RDWR | O_CLOEXEC);
    if (fd < 0) return -1;
    if (fstat(fd, &st) || !S_ISBLK(st.st_mode) || major(st.st_rdev) != 7) {
        fprintf(stderr, "REFUSED: target must be a major=7 loop block device\n");
        close(fd);
        errno = EPERM;
        return -1;
    }
    return fd;
}

static void make_different(unsigned char *out, const unsigned char *in)
{
    size_t i;
    for (i = 0; i < TEST_LEN; i++) out[i] = in[i] ^ 0xff;
}

static int setup_ring(unsigned entries, struct io_uring_params *p)
{
    memset(p, 0, sizeof(*p));
    return (int)syscall(__NR_io_uring_setup, entries, p);
}

static int io_uring_probe(const char *loop)
{
    struct io_uring_params p = {0};
    unsigned char before[TEST_LEN], payload[TEST_LEN], after[TEST_LEN];
    void *sq_ring = MAP_FAILED, *cq_ring = MAP_FAILED, *sqes_map = MAP_FAILED;
    size_t sq_size, cq_size, sq_map_size;
    unsigned *sq_tail, *sq_mask, *sq_array;
    unsigned *cq_head, *cq_tail, *cq_mask;
    struct io_uring_sqe *sqes;
    struct io_uring_cqe *cqes;
    unsigned tail, index;
    int ring = -1, target = -1, rc = 1, cqe_res;
    long entered;

    if (!getenv("DYNALAB_WORKDIR")) {
        fprintf(stderr, "REFUSED: run this probe through DynaLab analyze/run\n");
        return 2;
    }
    target = open_safe_loop(loop);
    if (target < 0) { perror(loop); return 2; }
    if (pread(target, before, TEST_LEN, 0) != TEST_LEN) {
        perror("pread before"); goto out;
    }
    make_different(payload, before);
    ring = setup_ring(8, &p);
    if (ring < 0) {
        printf("SKIP io_uring_setup: %s (%d)\n", strerror(errno), errno);
        rc = 77; goto out;
    }
    sq_size = p.sq_off.array + p.sq_entries * sizeof(unsigned);
    cq_size = p.cq_off.cqes + p.cq_entries * sizeof(struct io_uring_cqe);
    sq_map_size = sq_size;
    if (p.features & IORING_FEAT_SINGLE_MMAP) {
        size_t size = sq_size > cq_size ? sq_size : cq_size;
        sq_map_size = size;
        sq_ring = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED,
                       ring, IORING_OFF_SQ_RING);
        cq_ring = sq_ring;
    } else {
        sq_ring = mmap(NULL, sq_size, PROT_READ | PROT_WRITE, MAP_SHARED,
                       ring, IORING_OFF_SQ_RING);
        cq_ring = mmap(NULL, cq_size, PROT_READ | PROT_WRITE, MAP_SHARED,
                       ring, IORING_OFF_CQ_RING);
    }
    sqes_map = mmap(NULL, p.sq_entries * sizeof(struct io_uring_sqe),
                    PROT_READ | PROT_WRITE, MAP_SHARED, ring, IORING_OFF_SQES);
    if (sq_ring == MAP_FAILED || cq_ring == MAP_FAILED || sqes_map == MAP_FAILED) {
        perror("mmap io_uring"); goto out;
    }
    sq_tail = (unsigned *)((char *)sq_ring + p.sq_off.tail);
    sq_mask = (unsigned *)((char *)sq_ring + p.sq_off.ring_mask);
    sq_array = (unsigned *)((char *)sq_ring + p.sq_off.array);
    cq_head = (unsigned *)((char *)cq_ring + p.cq_off.head);
    cq_tail = (unsigned *)((char *)cq_ring + p.cq_off.tail);
    cq_mask = (unsigned *)((char *)cq_ring + p.cq_off.ring_mask);
    cqes = (struct io_uring_cqe *)((char *)cq_ring + p.cq_off.cqes);
    sqes = (struct io_uring_sqe *)sqes_map;

    tail = __atomic_load_n(sq_tail, __ATOMIC_ACQUIRE);
    index = tail & *sq_mask;
    memset(&sqes[index], 0, sizeof(sqes[index]));
    sqes[index].opcode = IORING_OP_WRITE;
    sqes[index].fd = target;
    sqes[index].off = 0;
    sqes[index].addr = (uint64_t)(uintptr_t)payload;
    sqes[index].len = TEST_LEN;
    sqes[index].user_data = 0x44594e414c414255ULL;
    sq_array[index] = index;
    __atomic_store_n(sq_tail, tail + 1, __ATOMIC_RELEASE);

    entered = syscall(__NR_io_uring_enter, ring, 1, 1,
                      IORING_ENTER_GETEVENTS, NULL, 0);
    if (entered < 0) { perror("io_uring_enter"); goto out; }
    while (__atomic_load_n(cq_tail, __ATOMIC_ACQUIRE) == *cq_head) usleep(1000);
    index = *cq_head & *cq_mask;
    cqe_res = cqes[index].res;
    printf("io_uring completion: res=%d\n", cqe_res);
    __atomic_store_n(cq_head, *cq_head + 1, __ATOMIC_RELEASE);
    if (cqe_res != TEST_LEN) {
        if (cqe_res < 0)
            printf("INDETERMINATE: async write failed: %s (%d)\n",
                   strerror(-cqe_res), -cqe_res);
        else
            printf("INDETERMINATE: short async write: %d/%d\n", cqe_res, TEST_LEN);
        rc = 78;
        goto out;
    }

    if (pread(target, after, TEST_LEN, 0) != TEST_LEN) {
        perror("pread after"); goto out;
    }
    if (!memcmp(before, after, TEST_LEN)) {
        puts("CONTAINED: completion returned, loop backing data unchanged");
        rc = 0;
    } else if (!memcmp(payload, after, TEST_LEN)) {
        puts("BYPASS OBSERVED: io_uring worker changed disposable loop data");
        rc = 10;
    } else {
        puts("INDETERMINATE: loop data changed to an unexpected value");
        rc = 11;
    }
out:
    if (sqes_map != MAP_FAILED)
        munmap(sqes_map, p.sq_entries * sizeof(struct io_uring_sqe));
    if (sq_ring != MAP_FAILED) munmap(sq_ring, sq_map_size);
    if (!(p.features & IORING_FEAT_SINGLE_MMAP) && cq_ring != MAP_FAILED)
        munmap(cq_ring, cq_size);
    if (ring >= 0) close(ring);
    if (target >= 0) close(target);
    return rc;
}

static int make_server_socket(const char *path)
{
    struct sockaddr_un addr;
    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) return -1;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", path);
    unlink(path);
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) || listen(fd, 1)) {
        close(fd); return -1;
    }
    chmod(path, 0600);
    return fd;
}

static int deputy_server(const char *socket_path, const char *loop)
{
    unsigned char before[TEST_LEN], payload[TEST_LEN], after[TEST_LEN];
    char request = 0;
    int listen_fd = -1, client = -1, target = -1, result = 1;
    target = open_safe_loop(loop);
    if (target < 0) { perror(loop); return 2; }
    listen_fd = make_server_socket(socket_path);
    if (listen_fd < 0) { perror("deputy socket"); close(target); return 2; }
    printf("DEPUTY READY pid=%d socket=%s target=%s\n", getpid(), socket_path, loop);
    fflush(stdout);
    client = accept4(listen_fd, NULL, NULL, SOCK_CLOEXEC);
    if (client < 0 || read(client, &request, 1) != 1 || request != 'W') {
        perror("deputy request"); goto out;
    }
    if (pread(target, before, TEST_LEN, 0) != TEST_LEN) goto out;
    make_different(payload, before);
    if (pwrite(target, payload, TEST_LEN, 0) != TEST_LEN || fsync(target)) goto out;
    if (pread(target, after, TEST_LEN, 0) != TEST_LEN) goto out;
    result = !memcmp(after, payload, TEST_LEN) ? 10 : 0;
    /* Always restore the disposable loop content from the untracked deputy. */
    if (pwrite(target, before, TEST_LEN, 0) != TEST_LEN || fsync(target)) result = 12;
    {
        unsigned char reply = (unsigned char)result;
        if (write(client, &reply, 1) != 1) result = 12;
    }
out:
    if (client >= 0) close(client);
    if (listen_fd >= 0) close(listen_fd);
    if (target >= 0) close(target);
    unlink(socket_path);
    printf("DEPUTY RESULT=%d (10 means provenance bypass reached the loop device)\n", result);
    return result == 12 ? 1 : 0;
}

static int deputy_client(const char *socket_path)
{
    struct sockaddr_un addr;
    unsigned char reply = 255;
    int fd;
    if (!getenv("DYNALAB_WORKDIR")) {
        fprintf(stderr, "REFUSED: run the client through DynaLab analyze/run\n");
        return 2;
    }
    fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) { perror("socket"); return 2; }
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", socket_path);
    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr))) {
        perror("connect deputy"); close(fd); return 2;
    }
    if (write(fd, "W", 1) != 1 || read(fd, &reply, 1) != 1) {
        perror("deputy exchange"); close(fd); return 2;
    }
    close(fd);
    if (reply == 10) {
        puts("BYPASS OBSERVED: untracked deputy performed the write and restored data");
        return 10;
    }
    if (reply == 0) {
        puts("CONTAINED: deputy write did not change loop data");
        return 0;
    }
    printf("INDETERMINATE: deputy result=%u\n", reply);
    return 11;
}

static void usage(const char *name)
{
    fprintf(stderr,
        "Usage:\n"
        "  %s io-uring <loop-device>\n"
        "  %s deputy-server <socket> <loop-device>\n"
        "  %s deputy-client <socket>\n", name, name, name);
}

int main(int argc, char **argv)
{
    if (argc == 3 && !strcmp(argv[1], "io-uring"))
        return io_uring_probe(argv[2]);
    if (argc == 4 && !strcmp(argv[1], "deputy-server"))
        return deputy_server(argv[2], argv[3]);
    if (argc == 3 && !strcmp(argv[1], "deputy-client"))
        return deputy_client(argv[2]);
    usage(argv[0]);
    return 2;
}
