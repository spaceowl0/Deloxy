/* FUTEX_WAIT must be interruptible by signals; FUTEX_WAKE must still work. */
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <pthread.h>
#include <time.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <linux/futex.h>

static volatile int w, handled;
static long fwait(volatile int *a, int v, const struct timespec *to) { return syscall(SYS_futex, a, FUTEX_WAIT, v, to, 0, 0); }
static long fwake(volatile int *a, int n) { return syscall(SYS_futex, a, FUTEX_WAKE, n, 0, 0, 0); }
static void h_plain(int s) { (void)s; handled++; }
static void h_set(int s) { (void)s; handled++; w = 1; }
static long ms_since(struct timespec *t0) { struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t); return (t.tv_sec - t0->tv_sec) * 1000 + (t.tv_nsec - t0->tv_nsec) / 1000000; }

static void *waiter(void *arg) { (void)arg; long r = fwait(&w, 0, 0); return (void *)(r == 0 ? 1 : 2); }

int main(void) {
  struct sigaction sa; memset(&sa, 0, sizeof sa);
  struct itimerval it = { { 0, 0 }, { 0, 40000 } }, off = { { 0, 0 }, { 0, 0 } };

  /* 1. no SA_RESTART: an untimed wait fails with EINTR after the handler ran */
  sa.sa_handler = h_plain; sigaction(SIGALRM, &sa, 0);
  w = 0; handled = 0; setitimer(ITIMER_REAL, &it, 0);
  long r = fwait(&w, 0, 0); int e = errno;
  setitimer(ITIMER_REAL, &off, 0);
  printf("untimed: ret=%ld errno=%s handled=%d\n", r, e == EINTR ? "EINTR" : "other", handled);

  /* 2. SA_RESTART: the wait is restarted; the handler changed the word, so the restart sees EAGAIN */
  sa.sa_handler = h_set; sa.sa_flags = SA_RESTART; sigaction(SIGALRM, &sa, 0);
  w = 0; handled = 0; setitimer(ITIMER_REAL, &it, 0);
  r = fwait(&w, 0, 0); e = errno;
  setitimer(ITIMER_REAL, &off, 0);
  printf("restart: ret=%ld errno=%s handled=%d\n", r, e == EAGAIN ? "EAGAIN" : "other", handled);

  /* 3. timed wait (3 s) is cut short by a signal */
  sa.sa_handler = h_plain; sa.sa_flags = 0; sigaction(SIGALRM, &sa, 0);
  w = 0; handled = 0; struct timespec to = { 3, 0 }, t0; clock_gettime(CLOCK_MONOTONIC, &t0);
  setitimer(ITIMER_REAL, &it, 0);
  r = fwait(&w, 0, &to); e = errno; long el = ms_since(&t0);
  setitimer(ITIMER_REAL, &off, 0);
  printf("timed: ret=%ld errno=%s quick=%d handled=%d\n", r, e == EINTR ? "EINTR" : "other", el < 1500, handled);

  /* 4. timeout still works without a signal */
  w = 0; to.tv_sec = 0; to.tv_nsec = 80 * 1000 * 1000;
  r = fwait(&w, 0, &to); e = errno;
  printf("timeout: ret=%ld errno=%s\n", r, e == ETIMEDOUT ? "ETIMEDOUT" : "other");

  /* 5. FUTEX_WAKE wakes a blocked thread, and a signal sent while another thread waits does not disturb the wake path */
  w = 0; pthread_t t; pthread_create(&t, 0, waiter, 0);
  usleep(60000);
  w = 1; long woke = fwake(&w, 1);
  void *res; pthread_join(t, &res);
  printf("wake: woke=%ld thread_ok=%d\n", woke, res == (void *)1);

  /* 6. a signal while a *thread* is blocked in an untimed wait: the process handler runs, the thread's wait is
     restarted (SA_RESTART) and is then woken normally */
  sa.sa_handler = h_plain; sa.sa_flags = SA_RESTART; sigaction(SIGALRM, &sa, 0);
  w = 0; handled = 0; pthread_create(&t, 0, waiter, 0);
  usleep(40000);
  setitimer(ITIMER_REAL, &it, 0); usleep(100000); setitimer(ITIMER_REAL, &off, 0);
  int ran = handled > 0;
  w = 1; fwake(&w, 1); pthread_join(t, &res);
  printf("thread-signal: handler_ran=%d thread_ok=%d\n", ran, res == (void *)1);
  printf("done\n");
  return 0;
}
