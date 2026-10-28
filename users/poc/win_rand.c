#include <windows.h>
#include <bcrypt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
BOOLEAN WINAPI SystemFunction036(PVOID, ULONG);
int main(void) {
  unsigned char a[4096], b[4096]; memset(a, 0, sizeof a); memset(b, 0, sizeof b);
  NTSTATUS s = BCryptGenRandom(NULL, a, sizeof a, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
  BOOLEAN r = SystemFunction036(b, sizeof b);
  unsigned int v = 0; errno_t e = rand_s(&v);
  long ones = 0; for (int i = 0; i < 4096; i++) for (int k = 0; k < 8; k++) ones += (a[i] >> k) & 1;
  printf("bcrypt=%ld rtlgenrandom=%d rand_s=%d balance=%s differ=%s\n", (long)s, r, (int)e, (ones > 16384 - 700 && ones < 16384 + 700) ? "ok" : "BAD", memcmp(a, b, 64) ? "yes" : "NO");
  return 0;
}
