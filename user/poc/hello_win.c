/* hello_win: freestanding Windows x64 console program using only kernel32 (no CRT).
   Exit code 0 = all checks passed, 3 = stdout write failed. Built with mingw-w64. */
#include <windows.h>

static const char hello[] = "Hello from Windows PE\r\n";
static int data_var = 41;
static char bss_buf[4096];

static void out(HANDLE h, const char *s) {
    DWORD n = 0, w;
    while (s[n]) n++;
    WriteFile(h, s, n, &w, NULL);
}

void mainCRTStartup(void) {
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD w = 0;
    if (!WriteFile(h, hello, sizeof(hello) - 1, &w, NULL) || w != sizeof(hello) - 1) ExitProcess(3);

    if (data_var != 41) ExitProcess(11);
    data_var++;
    for (int i = 0; i < 4096; i++) if (bss_buf[i]) ExitProcess(12);

    char *p = (char *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 300);
    if (!p) ExitProcess(13);
    for (int i = 0; i < 300; i++) { if (p[i]) ExitProcess(14); p[i] = (char)i; }
    char *q = (char *)HeapReAlloc(GetProcessHeap(), 0, p, 600);
    if (!q || q[299] != (char)299) ExitProcess(15);

    char *v = (char *)VirtualAlloc(NULL, 8192, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!v) ExitProcess(16);
    v[8191] = 1;
    if (!VirtualFree(v, 0, MEM_RELEASE)) ExitProcess(17);

    DWORD t = TlsAlloc();
    if (t == TLS_OUT_OF_INDEXES || !TlsSetValue(t, (LPVOID)0x1234) || TlsGetValue(t) != (LPVOID)0x1234) ExitProcess(18);

    LARGE_INTEGER a, b, f;
    QueryPerformanceFrequency(&f);
    QueryPerformanceCounter(&a);
    Sleep(20);
    QueryPerformanceCounter(&b);
    if (f.QuadPart != 10000000 || b.QuadPart <= a.QuadPart) ExitProcess(19);

    SetLastError(1234);
    if (GetLastError() != 1234) ExitProcess(20);

    const char *cmd = GetCommandLineA();
    out(h, "cmdline: ");
    out(h, cmd);
    out(h, "\r\n");
    if (GetModuleHandleA(NULL) == NULL) ExitProcess(21);
    ExitProcess(0);
}
