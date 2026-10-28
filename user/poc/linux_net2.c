/* Network v2 test (static glibc): stock getaddrinfo (through the kernel resolver), UDP, non-blocking connect + epoll,
   select, and a TCP server (bind/listen/accept) -- no special Deloxy APIs. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <netdb.h>
#include <poll.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/epoll.h>
static void ip_of(const char *h, char *out, size_t n) {
  struct addrinfo hints, *res = 0; memset(&hints, 0, sizeof hints); hints.ai_family = AF_INET; hints.ai_socktype = SOCK_STREAM;
  int r = getaddrinfo(h, "8777", &hints, &res);
  if (r || !res) { snprintf(out, n, "FAIL(%d)", r); return; }
  inet_ntop(AF_INET, &((struct sockaddr_in *)res->ai_addr)->sin_addr, out, n);
  freeaddrinfo(res);
}
int main(int argc, char **argv) {
  char ip[64];
  ip_of("mock.deloxy.test", ip, sizeof ip);
  printf("dns: mock.deloxy.test -> %s\n", ip);
  ip_of("nonexistent.deloxy.invalid", ip, sizeof ip);
  printf("dns: nonexistent -> %s\n", ip[0]=='F' ? "FAIL" : ip);
  /* UDP echo */
  int u = socket(AF_INET, SOCK_DGRAM, 0);
  struct sockaddr_in a; memset(&a, 0, sizeof a); a.sin_family = AF_INET; a.sin_port = htons(9999); inet_pton(AF_INET, "10.0.2.2", &a.sin_addr);
  sendto(u, "hello-udp", 9, 0, (struct sockaddr *)&a, sizeof a);
  struct pollfd pf = { u, POLLIN, 0 };
  int pr = poll(&pf, 1, 5000);
  char buf[256]; struct sockaddr_in from; socklen_t fl = sizeof from;
  int n = pr > 0 ? recvfrom(u, buf, sizeof buf - 1, 0, (struct sockaddr *)&from, &fl) : -1;
  if (n > 0) { buf[n] = 0; printf("udp: got '%s' from port %d\n", buf, ntohs(from.sin_port)); } else printf("udp: FAILED n=%d errno=%d\n", n, errno);
  close(u);
  /* non-blocking connect + epoll */
  int s = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
  a.sin_port = htons(8777);
  int c = connect(s, (struct sockaddr *)&a, sizeof a);
  printf("nbconnect: ret=%d errno=%s\n", c, c < 0 && errno == EINPROGRESS ? "EINPROGRESS" : "other");
  int ep = epoll_create1(0);
  struct epoll_event ev = { .events = EPOLLOUT, .data.fd = s }, out[4];
  epoll_ctl(ep, EPOLL_CTL_ADD, s, &ev);
  int w = epoll_wait(ep, out, 4, 8000);
  int err = -1; socklen_t el = sizeof err; getsockopt(s, SOL_SOCKET, SO_ERROR, &err, &el);
  printf("epoll: connect ready=%d so_error=%d\n", w, err);
  const char *rq = "GET /nothing HTTP/1.0\r\nHost: x\r\n\r\n"; send(s, rq, strlen(rq), 0);
  ev.events = EPOLLIN; epoll_ctl(ep, EPOLL_CTL_MOD, s, &ev);
  w = epoll_wait(ep, out, 4, 8000);
  n = recv(s, buf, sizeof buf - 1, 0);
  if (n > 0) { buf[n] = 0; int k = strcspn(buf, "\r\n"); buf[k] = 0; printf("epoll: read ready=%d status='%s'\n", w, buf); } else printf("epoll: read FAILED\n");
  /* select on the same socket */
  fd_set rs; FD_ZERO(&rs); FD_SET(s, &rs); struct timeval tv = { 1, 0 };
  int sr = select(s + 1, &rs, 0, 0, &tv);
  printf("select: n=%d (EOF or data pending)\n", sr);
  close(s); close(ep);
  /* TCP server */
  int l = socket(AF_INET, SOCK_STREAM, 0); int one = 1; setsockopt(l, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
  struct sockaddr_in b; memset(&b, 0, sizeof b); b.sin_family = AF_INET; b.sin_port = htons(7070); b.sin_addr.s_addr = INADDR_ANY;
  if (bind(l, (struct sockaddr *)&b, sizeof b) < 0) { printf("bind failed errno=%d\n", errno); return 2; }
  if (listen(l, 4) < 0) { printf("listen failed errno=%d\n", errno); return 3; }
  printf("listening on 7070\n"); fflush(stdout);
  struct pollfd lp = { l, POLLIN, 0 };
  if (poll(&lp, 1, 40000) <= 0) { printf("accept: timeout\n"); return 4; }
  struct sockaddr_in pa; socklen_t pl = sizeof pa;
  int cs = accept(l, (struct sockaddr *)&pa, &pl);
  if (cs < 0) { printf("accept failed errno=%d\n", errno); return 5; }
  n = recv(cs, buf, sizeof buf - 1, 0);
  if (n > 0) { buf[n] = 0; char rep[300]; snprintf(rep, sizeof rep, "pong:%s", buf); send(cs, rep, strlen(rep), 0); printf("server: got '%s' from %s\n", buf, inet_ntoa(pa.sin_addr)); }
  shutdown(cs, SHUT_WR); close(cs); close(l);
  printf("done\n");
  return 0;
}
