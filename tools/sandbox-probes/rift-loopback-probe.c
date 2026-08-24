#define _POSIX_C_SOURCE 200809L

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

enum {
    DefaultIntervalMs = 100,
    DefaultConnectTimeoutMs = 250,
    MaximumPort = 65535,
};

static int64_t monotonic_ms(void) {
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) return 0;
    return ((int64_t)now.tv_sec * 1000) + (now.tv_nsec / 1000000);
}

static void sleep_ms(int milliseconds) {
    struct timespec pause = {
        .tv_sec = milliseconds / 1000,
        .tv_nsec = (long)(milliseconds % 1000) * 1000000L,
    };
    while (nanosleep(&pause, &pause) != 0 && errno == EINTR) { }
}

static bool parse_positive_int(const char* value, int* output) {
    char* end = NULL;
    long parsed = strtol(value, &end, 10);
    if (*value == '\0' || *end != '\0' || parsed <= 0 || parsed > 600000) return false;
    *output = (int)parsed;
    return true;
}

static void attempt_loopback_connect(int family, uint16_t port, int timeout_ms) {
    int socket_fd = socket(family, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (socket_fd < 0) return;

    int original_flags = fcntl(socket_fd, F_GETFL, 0);
    if (original_flags < 0 || fcntl(socket_fd, F_SETFL, original_flags | O_NONBLOCK) != 0) {
        close(socket_fd);
        return;
    }

    int connect_result;
    if (family == AF_INET) {
        struct sockaddr_in address = {
            .sin_family = AF_INET,
            .sin_port = htons(port),
            .sin_addr = { .s_addr = htonl(INADDR_LOOPBACK) },
        };
        connect_result = connect(socket_fd, (const struct sockaddr*)&address, sizeof(address));
    } else {
        struct sockaddr_in6 address = {
            .sin6_family = AF_INET6,
            .sin6_port = htons(port),
            .sin6_addr = IN6ADDR_LOOPBACK_INIT,
        };
        connect_result = connect(socket_fd, (const struct sockaddr*)&address, sizeof(address));
    }

    if (connect_result != 0 && errno == EINPROGRESS) {
        struct pollfd descriptor = { .fd = socket_fd, .events = POLLOUT };
        (void)poll(&descriptor, 1, timeout_ms);
        int socket_error = 0;
        socklen_t socket_error_length = sizeof(socket_error);
        (void)getsockopt(socket_fd, SOL_SOCKET, SO_ERROR, &socket_error, &socket_error_length);
    }

    (void)shutdown(socket_fd, SHUT_RDWR);
    close(socket_fd);
}

static void discover_and_probe(const char* proc_file, int family, bool* seen_ports, int timeout_ms) {
    FILE* stream = fopen(proc_file, "r");
    if (stream == NULL) return;

    char line[512];
    (void)fgets(line, sizeof(line), stream);
    while (fgets(line, sizeof(line), stream) != NULL) {
        char local_address[80] = {0};
        char state[8] = {0};
        if (sscanf(line, " %*u: %79s %*s %7s", local_address, state) != 2 || strcmp(state, "0A") != 0)
            continue;

        char* separator = strrchr(local_address, ':');
        if (separator == NULL) continue;
        char* end = NULL;
        long port = strtol(separator + 1, &end, 16);
        if (separator[1] == '\0' || *end != '\0' || port <= 0 || port > MaximumPort || seen_ports[port])
            continue;

        seen_ports[port] = true;
        attempt_loopback_connect(family, (uint16_t)port, timeout_ms);
    }

    fclose(stream);
}

static int run_probe(int duration_ms, int interval_ms, int connect_timeout_ms) {
    bool seen_ipv4[MaximumPort + 1] = {false};
    bool seen_ipv6[MaximumPort + 1] = {false};
    const int64_t deadline = monotonic_ms() + duration_ms;

    while (monotonic_ms() < deadline) {
        discover_and_probe("/proc/net/tcp", AF_INET, seen_ipv4, connect_timeout_ms);
        discover_and_probe("/proc/net/tcp6", AF_INET6, seen_ipv6, connect_timeout_ms);
        sleep_ms(interval_ms);
    }

    return 0;
}

int main(int argc, char** argv) {
    int duration_ms = 20000;
    int interval_ms = DefaultIntervalMs;
    int connect_timeout_ms = DefaultConnectTimeoutMs;
    int index = 1;
    bool probe_worker = false;

    if (index < argc && strcmp(argv[index], "--probe-worker") == 0) {
        probe_worker = true;
        index++;
    }

    while (index < argc && strcmp(argv[index], "--") != 0) {
        if (index + 1 >= argc) return 2;
        int* destination = NULL;
        if (strcmp(argv[index], "--duration-ms") == 0) destination = &duration_ms;
        else if (strcmp(argv[index], "--interval-ms") == 0) destination = &interval_ms;
        else if (strcmp(argv[index], "--connect-timeout-ms") == 0) destination = &connect_timeout_ms;
        else return 2;
        if (!parse_positive_int(argv[index + 1], destination)) return 2;
        index += 2;
    }

    if (probe_worker) return index == argc ? run_probe(duration_ms, interval_ms, connect_timeout_ms) : 2;
    if (index >= argc || strcmp(argv[index], "--") != 0 || index + 1 >= argc) return 2;

    pid_t child = fork();
    if (child < 0) return 1;
    if (child == 0) {
        char duration_text[16];
        char interval_text[16];
        char timeout_text[16];
        (void)snprintf(duration_text, sizeof(duration_text), "%d", duration_ms);
        (void)snprintf(interval_text, sizeof(interval_text), "%d", interval_ms);
        (void)snprintf(timeout_text, sizeof(timeout_text), "%d", connect_timeout_ms);
        execl(argv[0], argv[0], "--probe-worker", "--duration-ms", duration_text,
              "--interval-ms", interval_text, "--connect-timeout-ms", timeout_text, (char*)NULL);
        return 127;
    }

    execvp(argv[index + 1], &argv[index + 1]);
    return 127;
}
