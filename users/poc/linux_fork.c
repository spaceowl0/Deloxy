/* Process model: fork, wait4, pipes between processes, execve, posix_spawn via system()/popen(), kill. Static glibc. */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <sys/wait.h>
int main(void) {
  int x = 5; pid_t c = fork();
  if (c == 0) { x = 99; _exit(7); }
  int st = 0; pid_t w = waitpid(c, &st, 0);
  printf("fork: child=%d reaped=%d exit=%d parent_x=%d\n", c > 0, w == c, WIFEXITED(st) ? WEXITSTATUS(st) : -1, x);
  int pf[2]; pipe(pf); c = fork();
  if (c == 0) { close(pf[0]); write(pf[1], "from-child", 10); _exit(0); }
  close(pf[1]); char b[32] = {0}; int n = read(pf[0], b, sizeof b - 1); waitpid(c, &st, 0);
  printf("pipe: got %d '%s'\n", n, b);
  c = fork();
  if (c == 0) { char *av[] = { "dyn_hello.elf", "a", "b", NULL }; char *ev[] = { "FOO=bar", NULL }; execve("/bin/dyn_hello.elf", av, ev); _exit(111); }
  waitpid(c, &st, 0); printf("exec: status=%d\n", WIFEXITED(st) ? WEXITSTATUS(st) : -1);
  c = fork(); if (c == 0) { execl("/bin/no_such_program", "x", (char *)0); _exit(42); }
  waitpid(c, &st, 0); printf("exec-missing: child exit=%d\n", WEXITSTATUS(st));
  int rc = system("echo from-system"); printf("system: rc=%d\n", WEXITSTATUS(rc));
  FILE *pp = popen("echo from-popen", "r"); char pb[64] = {0}; if (pp) { fgets(pb, sizeof pb, pp); pclose(pp); } pb[strcspn(pb, "\n")] = 0; printf("popen: '%s'\n", pb);
  pid_t kids[5]; for (int i = 0; i < 5; i++) { kids[i] = fork(); if (kids[i] == 0) _exit(10 + i); }
  int sum = 0; for (int i = 0; i < 5; i++) { waitpid(kids[i], &st, 0); sum += WEXITSTATUS(st); } printf("many: sum=%d\n", sum);
  c = fork(); if (c == 0) { for (;;) usleep(1000); }
  usleep(20000); int wn = waitpid(c, &st, WNOHANG); kill(c, SIGKILL); waitpid(c, &st, 0);
  printf("kill: wnohang=%d signaled=%d sig=%d\n", wn, WIFSIGNALED(st) ? 1 : 0, WIFSIGNALED(st) ? WTERMSIG(st) : 0);
  int none = waitpid(-1, &st, 0); printf("echild: %d %s\n", none, errno == ECHILD ? "ECHILD" : "other");
  return 0;
}
