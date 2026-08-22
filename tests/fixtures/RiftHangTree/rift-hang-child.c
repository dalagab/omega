#include <signal.h>
#include <unistd.h>

int main(void) {
    /*
     * Ignore SIGTERM intentionally. Rift's trusted outer supervisor has a
     * two-second TimeoutStopSec and SendSIGKILL=yes, so this proves the cgroup
     * process tree cannot keep a stubborn child alive.
     */
    signal(SIGTERM, SIG_IGN);
    for (;;) pause();
    return 0;
}
