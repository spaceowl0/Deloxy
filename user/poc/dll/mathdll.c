/* Imports basedll.dll (dependency chain), exports functions, a data variable, a forwarder and ordinal-only exports. */
#include <windows.h>
extern int base_value(void);
static void say(const char *s) { DWORD w; WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), s, lstrlenA(s), &w, NULL); }
static int calls;
__declspec(dllexport) int math_counter = 41;               /* exported data */
__declspec(dllexport) int math_add(int a, int b) { calls++; return a + b; }
__declspec(dllexport) int math_base_plus(int x) { calls++; return base_value() + x; }
__declspec(dllexport) int math_calls(void) { return calls; }
__declspec(dllexport) int math_ordinal_only(void) { return 777; }
BOOL WINAPI DllMain(HINSTANCE h, DWORD reason, LPVOID res) {
  (void)h; (void)res;
  if (reason == DLL_PROCESS_ATTACH) say("[mathdll] attach (base_value() = 1001 expected: ");
  if (reason == DLL_PROCESS_ATTACH) { char b[8] = "0000)\n"; int v = base_value(); b[0] = '0' + v / 1000 % 10; b[1] = '0' + v / 100 % 10; b[2] = '0' + v / 10 % 10; b[3] = '0' + v % 10; say(b); }
  return TRUE;
}
