/* Uses mathdll.dll through the import table (static link), then LoadLibrary/GetProcAddress/FreeLibrary at run time. */
#include <windows.h>
#include <stdio.h>
extern int math_add(int, int);
extern int math_base_plus(int);
extern int math_calls(void);
extern int math_counter;
extern void math_sleep(DWORD);
static int bad = 0;
#define CHECK(c, n) do { if (c) printf("ok   %s\n", n); else { printf("FAIL %s (err %lu)\n", n, GetLastError()); bad++; } } while (0)
int main(void) {
  setvbuf(stdout, NULL, _IONBF, 0);
  CHECK(math_add(20, 22) == 42, "static import: math_add");
  CHECK(math_base_plus(5) == 1006, "static import through a dependency chain (mathdll -> basedll)");
  CHECK(math_counter == 41, "imported data variable");
  math_sleep(1);
  CHECK(1, "forwarded export math_sleep -> KERNEL32.Sleep");
  CHECK(math_calls() == 2, "DLL keeps its own state");
  HMODULE hm = GetModuleHandleA("mathdll.dll");
  CHECK(hm != NULL, "GetModuleHandle of a statically linked DLL");
  CHECK(GetModuleHandleA("mathdll") == hm && GetModuleHandleA("MATHDLL.DLL") == hm, "module names: case and extension insensitive");
  FARPROC p = GetProcAddress(hm, "math_add");
  CHECK(p && ((int (*)(int, int))p)(1, 2) == 3, "GetProcAddress on a static DLL");
  FARPROC o = GetProcAddress(hm, (LPCSTR)(ULONG_PTR)7);
  CHECK(o && ((int (*)(void))o)() == 777, "GetProcAddress by ordinal");
  CHECK(GetProcAddress(hm, "no_such_export") == NULL && GetLastError() == 127, "missing export -> ERROR_PROC_NOT_FOUND");
  char path[260]; DWORD n = GetModuleFileNameA(hm, path, sizeof path);
  CHECK(n > 0 && strstr(path, "mathdll.dll"), "GetModuleFileName of a DLL");

  /* dynamic loading */
  CHECK(GetModuleHandleA("dyndll.dll") == NULL && GetLastError() == 126, "dyndll not loaded yet -> ERROR_MOD_NOT_FOUND");
  HMODULE d = LoadLibraryA("dyndll.dll");
  CHECK(d != NULL, "LoadLibrary (DllMain ran before it returned)");
  int (*sq)(int) = (int (*)(int))GetProcAddress(d, "dyn_square");
  int (*bump)(void) = (int (*)(void))GetProcAddress(d, "dyn_bump");
  int (*pv)(void) = (int (*)(void))GetProcAddress(d, "dyn_ptr_value");
  CHECK(sq && sq(12) == 144, "call a function of a loaded DLL");
  CHECK(pv && pv() == 9, "relocated DLL: pointer in .data fixed up");
  CHECK(bump && bump() == 6 && bump() == 7, "DLL data is writable and persistent");
  CHECK(LoadLibraryA("dyndll.dll") == d, "second LoadLibrary returns the same module");
  CHECK(FreeLibrary(d) && GetModuleHandleA("dyndll.dll") == d, "FreeLibrary with refs left keeps it loaded");
  CHECK(FreeLibrary(d) && GetModuleHandleA("dyndll.dll") == NULL, "last FreeLibrary unloads (DllMain DETACH ran)");
  HMODULE d2 = LoadLibraryA("dyndll.dll");
  int (*bump2)(void) = d2 ? (int (*)(void))GetProcAddress(d2, "dyn_bump") : NULL;
  CHECK(d2 != NULL && bump2 && bump2() == 6, "reload after free starts with fresh data");
  CHECK(LoadLibraryA("nonexistent.dll") == NULL && GetLastError() == 126, "missing DLL -> ERROR_MOD_NOT_FOUND");
  CHECK(LoadLibraryA("baddll.dll") == NULL, "DllMain returning FALSE fails the load");
  CHECK(LoadLibraryA("kernel32.dll") != NULL && GetProcAddress(GetModuleHandleA("kernel32.dll"), "Sleep") != NULL, "system DLLs still resolve");
  CHECK(FreeLibrary((HMODULE)0x1234) == 0 && GetLastError() == 6, "FreeLibrary of garbage -> ERROR_INVALID_HANDLE");
  printf(bad ? "DLL-TEST FAIL %d\n" : "DLL-TEST OK\n", bad);
  return bad;
}
