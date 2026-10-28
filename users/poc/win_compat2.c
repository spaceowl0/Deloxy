/* Windows compatibility v2: heap reuse, GetProcAddress, FLS, SList, wide strings, time, misc runtime APIs. */
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <wchar.h>
typedef ULONGLONG (WINAPI *tick_fn)(void);
int main(void) {
  /* heap: 200k alloc/free cycles of 4 KiB would need ~800 MiB without reuse */
  size_t total = 0;
  for (int i = 0; i < 200000; i++) { char *p = malloc(4000 + (i % 7)); if (!p) { printf("heap: FAILED at %d\n", i); return 1; } p[0] = 1; p[3999] = 2; total += 4000; free(p); }
  printf("heap: %zu bytes churned OK\n", total);
  char *g = malloc(10); strcpy(g, "grow"); for (int n = 20; n < 100000; n *= 3) g = realloc(g, n);
  printf("realloc: %s\n", g);
  char *z = calloc(100, 1); int nz = 0; for (int i = 0; i < 100; i++) nz |= z[i]; free(z); z = calloc(100, 1); for (int i = 0; i < 100; i++) nz |= z[i];
  printf("calloc: zeroed=%d\n", nz == 0);
  /* GetProcAddress */
  HMODULE k = GetModuleHandleA("kernel32.dll");
  tick_fn t = (tick_fn)GetProcAddress(k, "GetTickCount64");
  printf("getprocaddress: %s\n", t && t() > 0 ? "ok" : "FAILED");
  printf("getprocaddress missing: %s\n", GetProcAddress(k, "NoSuchApi123") == NULL ? "null" : "FAILED");
  /* FLS + pointer encoding */
  DWORD f = FlsAlloc(NULL); FlsSetValue(f, (PVOID)0x1234); printf("fls: %p\n", FlsGetValue(f));
  PVOID e = EncodePointer((PVOID)0x5678); printf("encode: %p\n", DecodePointer(e));
  SLIST_HEADER *h = _aligned_malloc(sizeof *h, 16); InitializeSListHead(h);
  SLIST_ENTRY *a = _aligned_malloc(16, 16), *b = _aligned_malloc(16, 16);
  InterlockedPushEntrySList(h, a); InterlockedPushEntrySList(h, b);
  printf("slist: pop order %s\n", InterlockedPopEntrySList(h) == b && InterlockedPopEntrySList(h) == a && InterlockedPopEntrySList(h) == NULL ? "ok" : "FAILED");
  /* wide */
  LPWSTR cl = GetCommandLineW(); printf("cmdlineW: %d\n", cl && cl[0] ? 1 : 0);
  wchar_t w1[32] = L"Hello", w2[32]; wcscpy(w2, w1); wcscat(w2, L", wide"); 
  printf("wcs: cmp=%d len=%d chr=%d\n", wcscmp(w1, w2) != 0, (int)wcslen(w2), wcschr(w2, L',') == w2 + 5);
  DWORD wr; WriteConsoleW(GetStdHandle(STD_OUTPUT_HANDLE), L"wide-out \x00e9\n", 11, &wr, NULL);
  /* misc */
  SYSTEM_INFO si; GetSystemInfo(&si); printf("sysinfo: page=%lu cpus=%lu\n", si.dwPageSize, si.dwNumberOfProcessors);
  HLOCAL l = LocalAlloc(LPTR, 64); printf("localalloc: %s\n", l && ((char *)l)[63] == 0 ? "ok" : "FAILED"); LocalFree(l);
  char buf[64]; _itoa(-12345, buf, 10); char b2[64]; _itoa(255, b2, 16); printf("itoa: %s %s\n", buf, b2);
  char s[] = "a,b;;c"; char *tok = strtok(s, ",;"); printf("strtok:"); while (tok) { printf(" %s", tok); tok = strtok(NULL, ",;"); } printf("\n");
  time_t tt = 86400 * 365 + 3661; struct tm *tm = gmtime(&tt); char ts[64]; strftime(ts, sizeof ts, "%Y-%m-%d %H:%M:%S", tm);
  printf("time: %s\n", ts);
  struct tm m2 = *tm; printf("mktime: %lld\n", (long long)mktime(&m2));
  printf("feature: sse2=%d\n", IsProcessorFeaturePresent(10));
  printf("done\n");
  return 0;
}
