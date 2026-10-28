#include <stdio.h>
#include <dlfcn.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/socket.h>
int main(void) {
  void *h = dlopen("libm.so.6", RTLD_NOW); double (*c)(double) = h ? dlsym(h, "cos") : 0;
  printf("dl: dlopen=%s cos(0)=%.1f\n", h ? "ok" : dlerror(), c ? c(0.0) : -1);
  void *bad = dlopen("libdoesnotexist.so", RTLD_NOW); printf("dl: missing lib -> %s\n", bad ? "FOUND?!" : "NULL");
  struct addrinfo hints = {0}, *r; hints.ai_family = AF_INET; hints.ai_socktype = SOCK_STREAM;
  int rc = getaddrinfo("mock.deloxy.test", "80", &hints, &r);
  if (rc == 0) { char b[32]; inet_ntop(AF_INET, &((struct sockaddr_in *)r->ai_addr)->sin_addr, b, sizeof b); printf("dl: getaddrinfo -> %s\n", b); } else printf("dl: getaddrinfo failed: %s\n", gai_strerror(rc));
  return 0;
}
