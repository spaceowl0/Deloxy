/* Thread-directed signals: pthread_kill/tgkill reach exactly the named thread; masks are per thread. */
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <pthread.h>
#include <sys/syscall.h>
#include <linux/futex.h>

static volatile int w, spin_stop, handled;
static volatile long ran_on, wtid, started;
static long gettid_(void) { return syscall(SYS_gettid); }
static void h(int s) { (void)s; handled++; ran_on = gettid_(); }
static void h2(int s) { (void)s; handled += 100; ran_on = gettid_(); }
static long fwait(volatile int *a, int v) { return syscall(SYS_futex, a, FUTEX_WAIT, v, 0, 0, 0); }

static void *futex_worker(void *a) { (void)a; wtid = gettid_(); started = 1; while (!w) fwait(&w, 0); return 0; }
static void *spin_worker(void *a) { (void)a; wtid = gettid_(); started = 1; while (!spin_stop) { asm volatile("" ::: "memory"); } return 0; }
static void *blocked_worker(void *a) {
  (void)a; wtid = gettid_();
  sigset_t m; sigemptyset(&m); sigaddset(&m, SIGUSR1); pthread_sigmask(SIG_BLOCK, &m, 0);
  started = 1; while (!w) usleep(2000);
  pthread_sigmask(SIG_UNBLOCK, &m, 0);          /* the pending signal must now arrive on this thread */
  usleep(30000);
  return 0;
}
static void *unblocked_worker(void *a) {
  (void)a; wtid = gettid_();
  sigset_t u; sigemptyset(&u); sigaddset(&u, SIGUSR2); pthread_sigmask(SIG_UNBLOCK, &u, 0);   /* threads inherit the creator's mask */
  started = 1; while (!w) fwait(&w, 0); return 0; }
static void wait_started(void) { while (!started) usleep(2000); usleep(20000); started = 0; }

int main(void) {
  struct sigaction sa; memset(&sa, 0, sizeof sa); sa.sa_handler = h; sa.sa_flags = SA_RESTART;
  sigaction(SIGUSR1, &sa, 0);
  sa.sa_handler = h2; sigaction(SIGUSR2, &sa, 0);
  pthread_t t; long main_tid = gettid_();

  /* 1. thread blocked in an untimed FUTEX_WAIT */
  w = 0; handled = 0; ran_on = 0; pthread_create(&t, 0, futex_worker, 0); wait_started();
  pthread_kill(t, SIGUSR1); usleep(40000);
  printf("futex-thread: handled=%d on_worker=%d\n", handled, ran_on == wtid && ran_on != main_tid);
  w = 1; syscall(SYS_futex, &w, FUTEX_WAKE, 1, 0, 0, 0); pthread_join(t, 0);

  /* 2. thread spinning in user mode (asynchronous delivery to that thread) */
  spin_stop = 0; handled = 0; ran_on = 0; pthread_create(&t, 0, spin_worker, 0); wait_started();
  pthread_kill(t, SIGUSR1); usleep(40000);
  printf("spin-thread: handled=%d on_worker=%d\n", handled, ran_on == wtid && ran_on != main_tid);
  spin_stop = 1; pthread_join(t, 0);

  /* 3. pthread_kill(self) runs the handler before returning */
  handled = 0; ran_on = 0; pthread_kill(pthread_self(), SIGUSR1);
  printf("self: handled=%d on_main=%d\n", handled, ran_on == main_tid);

  /* 4. blocked in the target stays pending, arrives on unblock */
  w = 0; handled = 0; ran_on = 0; pthread_create(&t, 0, blocked_worker, 0); wait_started();
  pthread_kill(t, SIGUSR1); usleep(40000);
  int early = handled;
  w = 1; pthread_join(t, 0);
  printf("blocked: early=%d late=%d on_worker=%d\n", early, handled, ran_on == wtid);

  /* 5. process-directed kill(): main blocks SIGUSR2, so the thread that unblocked it must take it */
  sigset_t m; sigemptyset(&m); sigaddset(&m, SIGUSR2); pthread_sigmask(SIG_BLOCK, &m, 0);
  w = 0; handled = 0; ran_on = 0; pthread_create(&t, 0, unblocked_worker, 0); wait_started();
  kill(getpid(), SIGUSR2); usleep(40000);
  printf("process-signal: handled=%d on_worker=%d\n", handled, ran_on == wtid && ran_on != main_tid);
  w = 1; syscall(SYS_futex, &w, FUTEX_WAKE, 1, 0, 0, 0); pthread_join(t, 0);

  /* 6. tgkill argument checks */
  printf("checks: bad_tid=%s sig0=%ld bad_tgid=%s\n",
         syscall(SYS_tgkill, getpid(), 999999, SIGUSR1) == -1 && errno == ESRCH ? "ESRCH" : "other",
         syscall(SYS_tgkill, getpid(), main_tid, 0),
         (syscall(SYS_tgkill, 424242, main_tid, SIGUSR1) == -1 && errno == ESRCH) ? "ESRCH" : "other");
  printf("done\n");
  return 0;
}
