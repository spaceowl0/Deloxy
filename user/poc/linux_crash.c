/* CPU faults as signals: SIGSEGV (unmapped / protection), SIGFPE, SIGILL delivered to handlers with si_code and
 * si_addr, recovery with siglongjmp, handler return restarting the instruction, sigaltstack for stack overflow,
 * and the default action (killed by the signal) seen through waitpid. */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <setjmp.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/wait.h>

static int bad = 0;
#define CHECK(c, n) do { if (c) printf("ok   %s\n", n); else { printf("FAIL %s\n", n); bad++; } } while (0)

static sigjmp_buf jb;
static volatile int got_sig, got_code, in_handler_blocked, on_altstack;
static volatile void *got_addr;
static char *volatile altlo, *volatile althi;

static void handler(int sig, siginfo_t *si, void *uc) {
  (void)uc;
  got_sig = sig; got_code = si->si_code; got_addr = si->si_addr;
  sigset_t cur; sigprocmask(SIG_BLOCK, NULL, &cur);
  in_handler_blocked = sigismember(&cur, sig);
  char probe; on_altstack = (&probe >= altlo && &probe < althi);
  siglongjmp(jb, 1);
}
static void install(int sig, int flags) {
  struct sigaction sa; memset(&sa, 0, sizeof sa);
  sa.sa_sigaction = handler; sa.sa_flags = SA_SIGINFO | flags; sigemptyset(&sa.sa_mask);
  sigaction(sig, &sa, NULL);
}
static int status_of(void (*fn)(void)) {
  pid_t c = fork();
  if (c == 0) { signal(SIGSEGV, SIG_DFL); signal(SIGFPE, SIG_DFL); signal(SIGILL, SIG_DFL); fn(); _exit(0); }
  int st = 0; waitpid(c, &st, 0); return st;
}
static void null_deref(void) { volatile int *p = NULL; *p = 1; }
static void div_zero(void) { volatile int z = 0; volatile int r = 5 / z; (void)r; }
static void illegal(void) { __builtin_trap(); }
static void ignored_segv(void) { signal(SIGSEGV, SIG_IGN); null_deref(); }
static void blocked_segv(void) { install(SIGSEGV, 0); sigset_t m; sigemptyset(&m); sigaddset(&m, SIGSEGV); sigprocmask(SIG_BLOCK, &m, NULL); null_deref(); }
static void resethand(void) { install(SIGSEGV, SA_RESETHAND); if (sigsetjmp(jb, 1) == 0) null_deref(); null_deref(); }

static void restart_handler(int sig, siginfo_t *si, void *uc) {
  (void)sig; (void)uc;
  got_code = si->si_code; got_addr = si->si_addr;
  mprotect((void *)((unsigned long)si->si_addr & ~4095UL), 4096, PROT_READ | PROT_WRITE);   /* fix the cause, then return: the store runs again */
}
static int recurse(int n) { volatile char pad[512]; pad[0] = (char)n; return pad[0] + recurse(n + 1); }

int main(void) {
  setvbuf(stdout, NULL, _IONBF, 0);
  /* SIGSEGV on an unmapped address */
  install(SIGSEGV, 0);
  if (sigsetjmp(jb, 1) == 0) { volatile int *p = (volatile int *)0x1234; *p = 7; }
  CHECK(got_sig == SIGSEGV && got_code == SEGV_MAPERR && got_addr == (void *)0x1234, "SIGSEGV: unmapped address -> SEGV_MAPERR, si_addr");
  CHECK(in_handler_blocked == 1, "the signal is blocked inside its own handler");
  sigset_t cur; sigprocmask(SIG_BLOCK, NULL, &cur);
  CHECK(!sigismember(&cur, SIGSEGV), "siglongjmp(sigsetjmp(..,1)) restores the mask");
  /* protection violation */
  char *ro = mmap(NULL, 4096, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  got_sig = 0;
  if (sigsetjmp(jb, 1) == 0) { *(volatile char *)(ro + 100) = 1; }
  CHECK(got_sig == SIGSEGV && got_code == SEGV_ACCERR && got_addr == (void *)(ro + 100), "SIGSEGV: write to a read-only page -> SEGV_ACCERR, si_addr");
  /* handler returns after fixing the page: the instruction restarts and succeeds */
  struct sigaction sa; memset(&sa, 0, sizeof sa); sa.sa_sigaction = restart_handler; sa.sa_flags = SA_SIGINFO; sigaction(SIGSEGV, &sa, NULL);
  *(volatile char *)(ro + 200) = 42;
  CHECK(ro[200] == 42 && got_code == SEGV_ACCERR, "handler fixes the page with mprotect and returns: the store is retried");
  install(SIGSEGV, 0);
  /* SIGFPE */
  install(SIGFPE, 0); got_sig = 0;
  if (sigsetjmp(jb, 1) == 0) { volatile int z = 0; volatile int r = 100 / z; (void)r; }
  CHECK(got_sig == SIGFPE && got_code == FPE_INTDIV, "SIGFPE: integer divide by zero -> FPE_INTDIV");
  /* SIGILL */
  install(SIGILL, 0); got_sig = 0;
  if (sigsetjmp(jb, 1) == 0) { __builtin_trap(); }
  CHECK(got_sig == SIGILL && got_code == ILL_ILLOPC, "SIGILL: ud2 -> ILL_ILLOPC");
  /* stack overflow on an alternate stack */
  size_t altsz = 64 * 1024; char *alt = malloc(altsz); altlo = alt; althi = alt + altsz;
  stack_t ss = { .ss_sp = alt, .ss_size = altsz, .ss_flags = 0 };
  CHECK(sigaltstack(&ss, NULL) == 0, "sigaltstack");
  stack_t old; sigaltstack(NULL, &old);
  CHECK(old.ss_sp == alt && old.ss_size == altsz && !(old.ss_flags & SS_DISABLE), "sigaltstack reports what was set");
  install(SIGSEGV, SA_ONSTACK); got_sig = 0; on_altstack = 0;
  if (sigsetjmp(jb, 1) == 0) { recurse(0); }
  CHECK(got_sig == SIGSEGV && on_altstack, "stack overflow: SIGSEGV handled on the alternate stack");
  install(SIGSEGV, 0);
  /* default actions through waitpid */
  int st = status_of(null_deref);  CHECK(WIFSIGNALED(st) && WTERMSIG(st) == SIGSEGV, "default action: NULL write kills with SIGSEGV");
  st = status_of(div_zero);        CHECK(WIFSIGNALED(st) && WTERMSIG(st) == SIGFPE, "default action: divide by zero kills with SIGFPE");
  st = status_of(illegal);         CHECK(WIFSIGNALED(st) && WTERMSIG(st) == SIGILL, "default action: ud2 kills with SIGILL");
  st = status_of(ignored_segv);    CHECK(WIFSIGNALED(st) && WTERMSIG(st) == SIGSEGV, "SIG_IGN cannot survive a real SIGSEGV");
  st = status_of(blocked_segv);    CHECK(WIFSIGNALED(st) && WTERMSIG(st) == SIGSEGV, "a blocked SIGSEGV kills too");
  st = status_of(resethand);       CHECK(WIFSIGNALED(st) && WTERMSIG(st) == SIGSEGV, "SA_RESETHAND: the second fault kills");
  /* the parent was not affected by its children's crashes */
  CHECK(getpid() > 0, "parent still running");
  printf(bad ? "CRASH-TEST FAIL %d\n" : "CRASH-TEST OK\n", bad);
  return bad;
}
