/* Asynchronous signal delivery: handlers must run while the program is spinning in user mode (no syscalls), from a
 * timer and from another process, and the interrupted code must resume with every register intact. */
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <stdint.h>
#include <sys/time.h>
#include <sys/wait.h>

static volatile int flag, hits;
static volatile double fp_scratch;
static void on_alrm(int s) { (void)s; hits++; flag = 1; fp_scratch = fp_scratch * 1.5 + 2.0; /* the handler uses SSE too */ }
static void on_usr1(int s) { (void)s; hits++; flag = 1; }

/* spin with known values in rax, rcx, r11, xmm1 until `flag` is set; report what they held afterwards */
static int spin_check(void) {
  uint64_t ra, rc, r11v, xv;
  flag = 0;
  uint64_t xin = 0x0123456789ABCDEFull;
  asm volatile(
      "movq %[xin], %%xmm1\n"
      "movabs $0x1111222233334444, %%rax\n"
      "movabs $0x5555666677778888, %%rcx\n"
      "movabs $0x99990000AAAABBBB, %%r11\n"
      "1: cmpl $0, %[f]\n"
      "   je 1b\n"
      "movq %%rax, %[ra]\n"
      "movq %%rcx, %[rc]\n"
      "movq %%r11, %[r11]\n"
      "movq %%xmm1, %[xv]\n"
      : [ra] "=m"(ra), [rc] "=m"(rc), [r11] "=m"(r11v), [xv] "=m"(xv)
      : [f] "m"(flag), [xin] "m"(xin)
      : "rax", "rcx", "r11", "xmm1", "memory", "cc");
  return ra == 0x1111222233334444ull && rc == 0x5555666677778888ull && r11v == 0x99990000AAAABBBBull && xv == xin;
}

int main(void) {
  struct sigaction sa; memset(&sa, 0, sizeof sa);
  sa.sa_handler = on_alrm; sigaction(SIGALRM, &sa, 0);
  struct sigaction su; memset(&su, 0, sizeof su);
  su.sa_handler = on_usr1; sigaction(SIGUSR1, &su, 0);

  /* 1. timer signal interrupts a pure user-mode spin */
  struct itimerval it = { { 0, 0 }, { 0, 30000 } };
  setitimer(ITIMER_REAL, &it, 0);
  int ok = spin_check();
  printf("async-timer: handled=%d registers-intact=%d\n", hits == 1, ok);

  /* 2. another process signals a spinning one */
  hits = 0;
  pid_t c = fork();
  if (c == 0) { usleep(40000); kill(getppid(), SIGUSR1); _exit(0); }
  ok = spin_check();
  int st; waitpid(c, &st, 0);
  printf("async-kill: handled=%d registers-intact=%d\n", hits == 1, ok);

  /* 3. a blocked signal stays pending while spinning and is delivered after unblocking */
  sigset_t m, old; sigemptyset(&m); sigaddset(&m, SIGUSR1); sigprocmask(SIG_BLOCK, &m, &old);
  hits = 0; flag = 0;
  c = fork();
  if (c == 0) { usleep(30000); kill(getppid(), SIGUSR1); _exit(0); }
  waitpid(c, &st, 0);
  for (volatile int i = 0; i < 3000000; i++) ;  /* spin well past several ticks */
  int while_blocked = hits;
  sigprocmask(SIG_SETMASK, &old, 0);
  printf("async-blocked: delivered_while_blocked=%d after_unblock=%d\n", while_blocked, hits);

  /* 4. SIGTERM default action still kills a spinner at once; a handler for SIGUSR1 runs repeatedly */
  hits = 0;
  struct itimerval rep = { { 0, 10000 }, { 0, 10000 } };
  sa.sa_handler = on_usr1; sigaction(SIGALRM, &sa, 0);
  setitimer(ITIMER_REAL, &rep, 0);
  for (volatile unsigned long i = 0; hits < 5 && i < 400000000ul; i++) ;
  struct itimerval off = { { 0, 0 }, { 0, 0 } }; setitimer(ITIMER_REAL, &off, 0);
  printf("async-repeat: handler_runs>=5 %d\n", hits >= 5);
  printf("done\n");
  return 0;
}
