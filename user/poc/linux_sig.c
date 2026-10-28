/* Signals and timers on Deloxy (static glibc). */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <time.h>
#include <sys/time.h>
#include <sys/wait.h>
static volatile int usr1, alrm, tick, chld, usr2, last_signo, in_info;
static void h1(int s, siginfo_t *si, void *uc) { usr1++; last_signo = s; in_info = si->si_signo; }
static void ha(int s) { alrm++; }
static void ht(int s) { tick++; }
static void hc(int s) { chld++; }
static void h2(int s) { usr2++; }
int main(void) {
  struct sigaction sa; memset(&sa, 0, sizeof sa);
  sa.sa_sigaction = h1; sa.sa_flags = SA_SIGINFO; sigaction(SIGUSR1, &sa, 0);
  raise(SIGUSR1); printf("handler: usr1=%d signo=%d info=%d\n", usr1, last_signo, in_info);
  sigset_t m, old; sigemptyset(&m); sigaddset(&m, SIGUSR1); sigprocmask(SIG_BLOCK, &m, &old);
  kill(getpid(), SIGUSR1); int before = usr1; sigset_t pend; sigpending(&pend);
  printf("mask: blocked_pending=%d delivered_while_blocked=%d", sigismember(&pend, SIGUSR1), usr1 - before);
  sigprocmask(SIG_SETMASK, &old, 0); printf(" after_unblock=%d\n", usr1 - before);
  struct sigaction sb; memset(&sb, 0, sizeof sb); sb.sa_handler = ha; sigaction(SIGALRM, &sb, 0);
  alarm(1); int pr = pause(); printf("alarm: pause=%d errno=%s alrm=%d\n", pr, errno == EINTR ? "EINTR" : "other", alrm);
  struct sigaction sT; memset(&sT, 0, sizeof sT); sT.sa_handler = ht; sigaction(SIGALRM, &sT, 0);
  struct itimerval it = { { 0, 20000 }, { 0, 20000 } }; setitimer(ITIMER_REAL, &it, 0);
  struct timespec ts = { 0, 300 * 1000 * 1000 }; while (nanosleep(&ts, &ts) < 0 && errno == EINTR) ;
  struct itimerval off = { { 0, 0 }, { 0, 0 } }; setitimer(ITIMER_REAL, &off, 0); printf("itimer: ticks>=5 %d\n", tick >= 5);
  struct sigaction sc; memset(&sc, 0, sizeof sc); sc.sa_handler = hc; sc.sa_flags = SA_RESTART; sigaction(SIGCHLD, &sc, 0);
  struct sigaction sr; memset(&sr, 0, sizeof sr); sr.sa_handler = ht; sr.sa_flags = SA_RESTART; sigaction(SIGALRM, &sr, 0);
  int pf[2]; pipe(pf); int t0 = tick; pid_t c = fork();
  if (c == 0) { usleep(400000); write(pf[1], "late", 4); _exit(0); }
  struct itimerval it2 = { { 0, 50000 }, { 0, 50000 } }; setitimer(ITIMER_REAL, &it2, 0);
  char b[8] = {0}; int n = read(pf[0], b, 7); setitimer(ITIMER_REAL, &off, 0); int st; waitpid(c, &st, 0);
  printf("restart: read=%d '%s' interrupted_ticks=%d chld=%d\n", n, b, (tick - t0) >= 2, chld >= 1);
  struct sigaction s2; memset(&s2, 0, sizeof s2); s2.sa_handler = h2; sigaction(SIGUSR2, &s2, 0);
  sigset_t bm, wm; sigemptyset(&bm); sigaddset(&bm, SIGUSR2); sigprocmask(SIG_BLOCK, &bm, &wm);
  pid_t me = getpid(); c = fork(); if (c == 0) { usleep(150000); kill(me, SIGUSR2); _exit(0); }
  int sr2 = sigsuspend(&wm); waitpid(c, &st, 0); printf("sigsuspend: ret=%d errno=%s usr2=%d\n", sr2, errno == EINTR ? "EINTR" : "other", usr2);
  sigprocmask(SIG_SETMASK, &wm, 0);
  signal(SIGPIPE, SIG_IGN); int pp[2]; pipe(pp); close(pp[0]); int w = write(pp[1], "x", 1); printf("sigpipe-ignored: write=%d errno=%s\n", w, errno == EPIPE ? "EPIPE" : "other"); close(pp[1]);
  signal(SIGPIPE, SIG_DFL); pipe(pp); c = fork(); if (c == 0) { close(pp[0]); write(pp[1], "x", 1); _exit(0); }
  close(pp[0]); close(pp[1]); waitpid(c, &st, 0); printf("sigpipe-default: signaled=%d sig=%d\n", WIFSIGNALED(st), WIFSIGNALED(st) ? WTERMSIG(st) : 0);
  c = fork(); if (c == 0) { raise(SIGABRT); _exit(0); } waitpid(c, &st, 0); printf("abort: signaled=%d sig=%d\n", WIFSIGNALED(st), WIFSIGNALED(st) ? WTERMSIG(st) : 0);
  c = fork(); if (c == 0) { for (;;) ; } usleep(30000); kill(c, SIGTERM); waitpid(c, &st, 0); printf("term-busy-loop: sig=%d\n", WIFSIGNALED(st) ? WTERMSIG(st) : 0);
  sigset_t ws; sigemptyset(&ws); sigaddset(&ws, SIGUSR1); sigprocmask(SIG_BLOCK, &ws, 0); kill(getpid(), SIGUSR1); siginfo_t si; struct timespec to = { 1, 0 };
  int got = sigtimedwait(&ws, &si, &to); printf("sigtimedwait: got=%d\n", got == SIGUSR1);
  timer_t tid; struct sigevent ev; memset(&ev, 0, sizeof ev); ev.sigev_notify = SIGEV_SIGNAL; ev.sigev_signo = SIGALRM;
  struct sigaction sp; memset(&sp, 0, sizeof sp); sp.sa_handler = ha; sigaction(SIGALRM, &sp, 0); int a0 = alrm;
  timer_create(CLOCK_REALTIME, &ev, &tid); struct itimerspec its = { { 0, 0 }, { 0, 100 * 1000 * 1000 } }; timer_settime(tid, 0, &its, 0);
  ts.tv_sec = 1; ts.tv_nsec = 0; while (nanosleep(&ts, &ts) < 0 && errno == EINTR && alrm == a0) ; timer_delete(tid);
  printf("posix-timer: fired=%d\n", alrm > a0);
  printf("done\n"); return 0;
}
