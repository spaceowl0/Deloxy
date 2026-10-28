/* hello_linux: freestanding static Linux x86-64 program (no libc). Exercises the loader's
   System V stack (argc/argv/auxv) and the syscall layer: write, uname, brk, mmap/munmap,
   clock_gettime, exit_group. Exit code 0 = everything checked out, 3 = stdout write failed. */
typedef unsigned long u64;
typedef long i64;

static inline i64 sc(i64 n, i64 a, i64 b, i64 c, i64 d, i64 e, i64 f) {
    i64 r;
    register i64 r10 __asm__("r10") = d;
    register i64 r8 __asm__("r8") = e;
    register i64 r9 __asm__("r9") = f;
    __asm__ volatile("syscall" : "=a"(r) : "a"(n), "D"(a), "S"(b), "d"(c), "r"(r10), "r"(r8), "r"(r9) : "rcx", "r11", "memory");
    return r;
}

static int data_var = 41;
static char bss_buf[8192];
static const char hello[] = "Hello from Linux ELF\n";

static u64 slen(const char *s) { u64 n = 0; while (s[n]) n++; return n; }
static void out(const char *s) { sc(1, 1, (i64)s, slen(s), 0, 0, 0); }
static void outnum(u64 v) {
    char b[24]; int i = 23; b[i] = 0;
    if (!v) b[--i] = '0';
    while (v) { b[--i] = '0' + v % 10; v /= 10; }
    out(&b[i]);
}
__attribute__((noreturn)) static void die(int code) { for (;;) sc(231, code, 0, 0, 0, 0, 0); }

void c_main(u64 *sp) {
    i64 argc = (i64)sp[0];
    char **argv = (char **)&sp[1];
    char **envp = argv + argc + 1;
    char **e = envp; while (*e) e++;
    u64 *auxv = (u64 *)(e + 1);

    if (sc(1, 1, (i64)hello, sizeof(hello) - 1, 0, 0, 0) != (i64)sizeof(hello) - 1) die(3);

    out("argc="); outnum((u64)argc); out(" argv0="); out(argc ? argv[0] : "(none)"); out("\n");

    u64 pagesz = 0, random = 0, entry = 0;
    for (u64 *a = auxv; a[0]; a += 2) {
        if (a[0] == 6) pagesz = a[1];
        if (a[0] == 25) random = a[1];
        if (a[0] == 9) entry = a[1];
    }
    if (pagesz != 4096 || !random || !entry) { out("auxv bad\n"); die(10); }
    if (data_var != 41) die(11);
    data_var++;
    if (data_var != 42) die(12);
    for (int i = 0; i < 8192; i++) if (bss_buf[i]) die(13);
    bss_buf[8191] = 7;

    char uts[65 * 6];
    if (sc(63, (i64)uts, 0, 0, 0, 0, 0) != 0) die(14);
    out("uname: "); out(uts); out(" "); out(uts + 65 * 4); out("\n");

    i64 b0 = sc(12, 0, 0, 0, 0, 0, 0);
    i64 b1 = sc(12, b0 + 8192, 0, 0, 0, 0, 0);
    if (b1 != b0 + 8192) die(15);
    char *h = (char *)b0;
    for (int i = 0; i < 8192; i++) h[i] = (char)i;
    if (h[8191] != (char)8191) die(16);

    char *m = (char *)sc(9, 0, 4096, 3, 0x22, -1, 0);   /* PROT_READ|WRITE, MAP_PRIVATE|ANONYMOUS */
    if ((i64)m < 0 && (i64)m > -4096) die(17);
    m[0] = 'x'; m[4095] = 'y';
    if (sc(11, (i64)m, 4096, 0, 0, 0, 0) != 0) die(18);

    u64 ts[2];
    if (sc(228, 1, (i64)ts, 0, 0, 0, 0) != 0) die(19);
    out("pid="); outnum((u64)sc(39, 0, 0, 0, 0, 0, 0)); out(" ok\n");
    die(0);
}

__attribute__((naked, noreturn)) void _start(void) {
    __asm__ volatile("mov %rsp, %rdi\n\tcall c_main\n\tud2\n");
}
