/* Process groups, sessions and job control. */
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/wait.h>

static int drain(int fd) { char b[64]; int n = 0, r; while ((r = read(fd, b, sizeof b)) > 0) n += r; return n; }

int main(int argc, char **argv) {
  if (argc > 1 && !strcmp(argv[1], "spin")) {       /* for the console Ctrl-C test */
    printf("spinning\n"); fflush(stdout);
    for (;;) { asm volatile("" ::: "memory"); }
  }
  setvbuf(stdout, 0, _IOLBF, 0);
  pid_t me = getpid();
  printf("ids: pgrp_is_pid=%d sid_is_pid=%d setsid_leader=%s\n", getpgrp() == me, getsid(0) == me,
         (setsid() == -1 && errno == EPERM) ? "EPERM" : "other");

  /* child in its own group; the parent sees it */
  pid_t c = fork();
  if (c == 0) { setpgid(0, 0); pause(); _exit(0); }
  usleep(50000);
  printf("child-group: own=%d same_as_parent=%d\n", getpgid(c) == c, getpgid(c) == getpgrp());
  kill(c, SIGKILL); waitpid(c, 0, 0);

  /* two children in one group: kill(-pgid) reaches both; waitpid(-pgid) collects them */
  pid_t a = fork(); if (a == 0) { pause(); _exit(0); }
  pid_t b = fork(); if (b == 0) { pause(); _exit(0); }
  int r1 = setpgid(a, 0), r2 = setpgid(b, a);
  usleep(30000);
  printf("group-setup: setpgid=%d,%d pgids_equal=%d\n", r1, r2, getpgid(a) == a && getpgid(b) == a);
  int kr = kill(-a, SIGTERM);
  int st, got = 0, sigs = 0;
  for (int i = 0; i < 2; i++) { pid_t w = waitpid(-a, &st, 0); if (w == a || w == b) got++; if (WIFSIGNALED(st) && WTERMSIG(st) == SIGTERM) sigs++; }
  printf("group-kill: kill=%d reaped=%d by_sigterm=%d echild_after=%s\n", kr, got, sigs, (waitpid(-a, &st, WNOHANG) == -1 && errno == ECHILD) ? "yes" : "no");

  /* waitpid(0): a child of our own group */
  pid_t g = fork(); if (g == 0) _exit(7);
  pid_t w = waitpid(0, &st, 0);
  printf("wait-pgid0: got_child=%d status=%d\n", w == g, WIFEXITED(st) ? WEXITSTATUS(st) : -1);

  /* kill(0) reaches our own group (we ignore it) */
  signal(SIGUSR1, SIG_IGN);
  printf("kill0: ret=%d\n", kill(0, SIGUSR1));

  /* stop / continue: a stopped child stops running, SIGCONT resumes it */
  int pfd[2]; pipe(pfd); fcntl(pfd[0], F_SETFL, O_NONBLOCK);
  pid_t s = fork();
  if (s == 0) { close(pfd[0]); for (;;) { write(pfd[1], "x", 1); usleep(15000); } }
  close(pfd[1]);
  usleep(120000);
  int before = drain(pfd[0]);
  kill(s, SIGSTOP);
  pid_t ws = waitpid(s, &st, WUNTRACED);
  int stopped = ws == s && WIFSTOPPED(st) && WSTOPSIG(st) == SIGSTOP;
  drain(pfd[0]); usleep(150000);
  int while_stopped = drain(pfd[0]);
  kill(s, SIGCONT);
  pid_t wc = waitpid(s, &st, WCONTINUED);
  int continued = wc == s && WIFCONTINUED(st);
  usleep(150000);
  int after = drain(pfd[0]);
  printf("stop-cont: running_before=%d stopped=%d silent_while_stopped=%d continued=%d running_after=%d\n", before > 2, stopped, while_stopped == 0, continued, after > 2);
  kill(s, SIGKILL); waitpid(s, 0, 0);

  /* SIGTSTP default action stops too; a stopped *user-mode spinner* is stopped by the timer tick; SIGKILL ends it */
  pid_t sp = fork(); if (sp == 0) { for (;;) { asm volatile("" ::: "memory"); } }
  usleep(60000);
  kill(sp, SIGTSTP);
  ws = waitpid(sp, &st, WUNTRACED);
  printf("tstp-spinner: stopped=%d sig=%d\n", ws == sp && WIFSTOPPED(st), WIFSTOPPED(st) ? WSTOPSIG(st) : -1);
  kill(sp, SIGCONT); usleep(30000); kill(sp, SIGKILL);
  ws = waitpid(sp, &st, 0);
  printf("spinner-killed: %d\n", ws == sp && WIFSIGNALED(st) && WTERMSIG(st) == SIGKILL);
  printf("done\n");
  return 0;
}
