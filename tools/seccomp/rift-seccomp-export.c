// Build a conservative seccomp BPF deny-list for the plugin process.
// Bubblewrap applies this filter only after it has created the namespaces and
// filesystem, so denying mount/unshare/setns here does not stop bwrap itself.
#include <errno.h>
#include <fcntl.h>
#include <linux/net.h>
#include <sched.h>
#include <seccomp.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>

static int deny_name(scmp_filter_ctx ctx, const char *name) {
    int nr = seccomp_syscall_resolve_name(name);
    if (nr == __NR_SCMP_ERROR) return 0; // syscall absent on this architecture
    int rc = seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), nr, 0);
    if (rc < 0) {
        fprintf(stderr, "failed adding seccomp rule for %s: %d\n", name, rc);
        return rc;
    }
    return 0;
}

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "usage: rift-seccomp-export <output.bpf>\n");
        return 2;
    }

    scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_ALLOW);
    if (!ctx) {
        fprintf(stderr, "seccomp_init failed\n");
        return 1;
    }

    const char *deny[] = {
        "ptrace",
        "mount", "umount2", "pivot_root",
        "setns", "unshare",
        "clone3",
        "reboot", "kexec_load", "kexec_file_load",
        "swapon", "swapoff",
        "keyctl", "add_key", "request_key",
        "bpf", "perf_event_open", "userfaultfd",
        "open_by_handle_at", "name_to_handle_at",
        "move_mount", "fsopen", "fsconfig", "fsmount", "fspick", "open_tree",
        "init_module", "finit_module", "delete_module",
        "iopl", "ioperm",
        "process_vm_readv", "process_vm_writev",
        NULL
    };

    for (const char **p = deny; *p; ++p) {
        if (deny_name(ctx, *p) < 0) {
            seccomp_release(ctx);
            return 1;
        }
    }

    int clone_nr = seccomp_syscall_resolve_name("clone");
    if (clone_nr != __NR_SCMP_ERROR) {
        if (seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), clone_nr, 1,
                             SCMP_A0(SCMP_CMP_MASKED_EQ, CLONE_NEWUSER, CLONE_NEWUSER)) < 0) {
            fprintf(stderr, "failed adding CLONE_NEWUSER seccomp rule\n");
            seccomp_release(ctx);
            return 1;
        }
    }

    // No AF_PACKET sockets even inside the isolated network namespace.
    int socket_nr = seccomp_syscall_resolve_name("socket");
    if (socket_nr != __NR_SCMP_ERROR) {
        if (seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), socket_nr, 1,
                            SCMP_A0(SCMP_CMP_EQ, AF_PACKET)) < 0) {
            fprintf(stderr, "failed adding AF_PACKET seccomp rule\n");
            seccomp_release(ctx);
            return 1;
        }
        if (seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), socket_nr, 1,
                            SCMP_A1(SCMP_CMP_MASKED_EQ, SOCK_RAW, SOCK_RAW)) < 0) {
            fprintf(stderr, "failed adding SOCK_RAW seccomp rule\n");
            seccomp_release(ctx);
            return 1;
        }
    }

    int fd = open(argv[1], O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
    if (fd < 0) {
        perror("open output");
        seccomp_release(ctx);
        return 1;
    }

    int rc = seccomp_export_bpf(ctx, fd);
    close(fd);
    seccomp_release(ctx);
    if (rc < 0) {
        fprintf(stderr, "seccomp_export_bpf failed: %d\n", rc);
        return 1;
    }
    return 0;
}
