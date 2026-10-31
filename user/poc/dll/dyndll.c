/* Loaded with LoadLibrary at run time; linked at the same base as the exe so it must be relocated. */
#include <windows.h>
static void say(const char *s) { DWORD w; WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), s, lstrlenA(s), &w, NULL); }
static int state = 5;               /* initialised data: must be fresh after a reload */
static int global_ptr_target = 9;
static int *volatile global_ptr = &global_ptr_target;   /* needs a base relocation */
__declspec(dllexport) int dyn_square(int x) { return x * x; }
__declspec(dllexport) int dyn_bump(void) { return ++state; }
__declspec(dllexport) int dyn_ptr_value(void) { return *global_ptr; }
BOOL WINAPI DllMain(HINSTANCE h, DWORD reason, LPVOID res) {
  (void)h; (void)res;
  if (reason == DLL_PROCESS_ATTACH) say("[dyndll] attach\n");
  if (reason == DLL_PROCESS_DETACH) say("[dyndll] detach\n");
  return TRUE;
}
