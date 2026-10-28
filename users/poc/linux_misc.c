/* Linux compat v2: eventfd + epoll, blocking pipes with a writer thread, readv, pwrite, F_DUPFD, statfs. */
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdint.h>
#include <pthread.h>
#include <sys/eventfd.h>
#include <sys/epoll.h>
#include <sys/uio.h>
#include <sys/statfs.h>
static int pfd[2];
static void *writer(void *a) { usleep(300000); write(pfd[1], "late-data", 9); return 0; }
int main(void) {
  int e = eventfd(0, EFD_NONBLOCK); uint64_t v = 3; write(e, &v, 8); write(e, &v, 8);
  int ep = epoll_create1(0); struct epoll_event ev = { .events = EPOLLIN, .data.u32 = 7 }, out[2]; epoll_ctl(ep, EPOLL_CTL_ADD, e, &ev);
  int n = epoll_wait(ep, out, 2, 1000); uint64_t r = 0; read(e, &r, 8);
  printf("eventfd: epoll=%d data=%u sum=%llu\n", n, n > 0 ? out[0].data.u32 : 0, (unsigned long long)r);
  int rr = read(e, &r, 8); printf("eventfd: empty read -> %s\n", rr < 0 && errno == EAGAIN ? "EAGAIN" : "WRONG");
  pipe(pfd); pthread_t t; pthread_create(&t, 0, writer, 0);
  char buf[32] = {0}; int k = read(pfd[0], buf, sizeof buf - 1);
  printf("pipe: blocking read got %d '%s'\n", k, buf); pthread_join(t, 0);
  int nb[2]; pipe2(nb, O_NONBLOCK); k = read(nb[0], buf, 4); printf("pipe: nonblocking empty -> %s\n", k < 0 && errno == EAGAIN ? "EAGAIN" : "WRONG");
  close(nb[1]); k = read(nb[0], buf, 4); printf("pipe: closed writer -> EOF=%d\n", k == 0);
  int q[2]; pipe(q); write(q[1], "abcdefgh", 8); char a1[3] = {0}, a2[6] = {0}; struct iovec iov[2] = { { a1, 2 }, { a2, 5 } };
  k = readv(q[0], iov, 2); printf("readv: %d '%s' '%s'\n", k, a1, a2);
  int d = fcntl(q[0], F_DUPFD, 20); printf("F_DUPFD: %s\n", d >= 20 ? "ok" : "WRONG");
  struct statfs sf; printf("statfs: %s\n", statfs("/", &sf) == 0 && sf.f_bsize > 0 ? "ok" : "WRONG");
  printf("done\n"); return 0;
}
