/* Entropy test: getrandom() and /dev/urandom must look random (bit balance, byte chi-square, no repeats). */
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/random.h>
#define N 65536
static unsigned char a[N], b[N];
static void stats(const char *tag, unsigned char *d) {
  long ones = 0, hist[256] = {0}; for (int i = 0; i < N; i++) { hist[d[i]]++; for (int k = 0; k < 8; k++) ones += (d[i] >> k) & 1; }
  double e = N / 256.0, chi = 0; for (int i = 0; i < 256; i++) chi += (hist[i] - e) * (hist[i] - e) / e;
  int rep = 0; for (int i = 0; i + 16 < N; i += 16) for (int j = i + 16; j < N && j < i + 4096; j += 16) if (!memcmp(d + i, d + j, 8)) rep++;
  printf("%s: ones=%.4f chi2=%.0f repeats=%d %s\n", tag, ones / (N * 8.0), chi, rep, (ones > N * 4 - N / 2 && ones < N * 4 + N / 2 && chi > 180 && chi < 340 && !rep) ? "OK" : "BAD");
}
int main(void) {
  ssize_t g = getrandom(a, N, 0); int fd = open("/dev/urandom", O_RDONLY); ssize_t u = read(fd, b, N);
  printf("sizes: %zd %zd\n", g, u);
  stats("getrandom", a); stats("urandom", b);
  printf("differ: %s\n", memcmp(a, b, 64) ? "yes" : "NO");
  printf("sample:"); for (int i = 0; i < 8; i++) printf("%02x", a[i]); printf("\n");
  return 0;
}
