/* Winsock v2 test (MinGW): gethostbyname, getaddrinfo, UDP sendto/recvfrom, select, WSAPoll, listen/accept. */
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include <string.h>
int main(void) {
  WSADATA w; WSAStartup(MAKEWORD(2,2), &w);
  struct hostent *h = gethostbyname("mock.deloxy.test");
  if (h) printf("win dns: gethostbyname -> %s\n", inet_ntoa(*(struct in_addr *)h->h_addr_list[0])); else printf("win dns: gethostbyname FAILED %d\n", WSAGetLastError());
  struct addrinfo hints, *res = 0; memset(&hints, 0, sizeof hints); hints.ai_family = AF_INET; hints.ai_socktype = SOCK_STREAM;
  int r = getaddrinfo("mock.deloxy.test", "8777", &hints, &res);
  if (!r && res) printf("win dns: getaddrinfo -> %s port %d\n", inet_ntoa(((struct sockaddr_in *)res->ai_addr)->sin_addr), ntohs(((struct sockaddr_in *)res->ai_addr)->sin_port)); else printf("win dns: getaddrinfo FAILED %d\n", r);
  SOCKET u = socket(AF_INET, SOCK_DGRAM, 0);
  struct sockaddr_in a; memset(&a, 0, sizeof a); a.sin_family = AF_INET; a.sin_port = htons(9999); a.sin_addr.s_addr = inet_addr("10.0.2.2");
  sendto(u, "hello-win", 9, 0, (struct sockaddr *)&a, sizeof a);
  fd_set rs; FD_ZERO(&rs); FD_SET(u, &rs); struct timeval tv = { 5, 0 };
  int n = select(0, &rs, 0, 0, &tv);
  char buf[256]; int fl = sizeof a; struct sockaddr_in from;
  if (n > 0 && FD_ISSET(u, &rs)) { int k = recvfrom(u, buf, sizeof buf - 1, 0, (struct sockaddr *)&from, &fl); buf[k > 0 ? k : 0] = 0; printf("win udp: got '%s' from port %d\n", buf, ntohs(from.sin_port)); } else printf("win udp: FAILED select=%d\n", n);
  closesocket(u);
  SOCKET l = socket(AF_INET, SOCK_STREAM, 0);
  struct sockaddr_in b; memset(&b, 0, sizeof b); b.sin_family = AF_INET; b.sin_port = htons(7071); b.sin_addr.s_addr = INADDR_ANY;
  if (bind(l, (struct sockaddr *)&b, sizeof b) != 0) { printf("win bind failed %d\n", WSAGetLastError()); return 2; }
  if (listen(l, 4) != 0) { printf("win listen failed %d\n", WSAGetLastError()); return 3; }
  printf("win listening on 7071\n"); fflush(stdout);
  WSAPOLLFD pf = { l, POLLRDNORM, 0 };
  if (WSAPoll(&pf, 1, 40000) <= 0) { printf("win accept: timeout\n"); return 4; }
  SOCKET c = accept(l, 0, 0);
  int k = recv(c, buf, sizeof buf - 1, 0);
  if (k > 0) { buf[k] = 0; char rep[300]; sprintf(rep, "winpong:%s", buf); send(c, rep, (int)strlen(rep), 0); printf("win server: got '%s'\n", buf); }
  closesocket(c); closesocket(l);
  printf("win done\n");
  return 0;
}
