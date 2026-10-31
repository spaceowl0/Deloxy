/* A blocking console read is interruptible: EINTR without SA_RESTART; with SA_RESTART it restarts and a partly typed
 * line survives repeated interruptions. */
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <sys/time.h>

static volatile int handled;
static void h_plain(int s) { (void)s; handled++; }
static void h_say(int s) { (void)s; handled++; if (handled == 1) write(1, "sig\n", 4); }

int main(void) {
  char buf[128];
  struct sigaction sa; memset(&sa, 0, sizeof sa);
  struct itimerval once = { { 0, 0 }, { 0, 40000 } }, rep = { { 0, 30000 }, { 0, 30000 } }, off = { { 0, 0 }, { 0, 0 } };

  sa.sa_handler = h_plain; sigaction(SIGALRM, &sa, 0);
  setitimer(ITIMER_REAL, &once, 0);
  ssize_t r = read(0, buf, sizeof buf); int e = errno;
  printf("tty1: ret=%ld errno=%s handled=%d\n", (long)r, e == EINTR ? "EINTR" : "other", handled);

  handled = 0; sa.sa_handler = h_say; sa.sa_flags = SA_RESTART; sigaction(SIGALRM, &sa, 0);
  setitimer(ITIMER_REAL, &rep, 0);
  r = read(0, buf, sizeof buf - 1);
  setitimer(ITIMER_REAL, &off, 0);
  if (r > 0) { buf[r] = 0; if (buf[r - 1] == '\n') buf[r - 1] = 0; }
  printf("tty2: got='%s' interrupted_several_times=%d\n", r > 0 ? buf : "", handled >= 3);
  printf("done\n");
  return 0;
}
