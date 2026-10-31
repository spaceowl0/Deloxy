/* Leaf DLL: no imports from other DLLs. Prints from DllMain so the init order is visible. */
#include <windows.h>
static void say(const char *s) { DWORD w; WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), s, lstrlenA(s), &w, NULL); }
static int attached;
__declspec(dllexport) int base_value(void) { return 1000 + attached; }
BOOL WINAPI DllMain(HINSTANCE h, DWORD reason, LPVOID res) {
  (void)h; (void)res;
  if (reason == DLL_PROCESS_ATTACH) { attached = 1; say("[basedll] attach\n"); }
  if (reason == DLL_PROCESS_DETACH) say("[basedll] detach\n");
  return TRUE;
}
