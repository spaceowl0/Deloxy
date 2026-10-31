/* Windows exception dispatch: vectored handlers, CONTEXT editing, RaiseException, unhandled-exception filter. */
#include <windows.h>
#include <stdio.h>
#include <string.h>

static volatile int hits, order_n;
static char order[16];
static int dummy, av_info;
static volatile double fpjunk;

static LONG WINAPI skip_ud2(PEXCEPTION_POINTERS ep) {
  if (ep->ExceptionRecord->ExceptionCode != EXCEPTION_ILLEGAL_INSTRUCTION) return EXCEPTION_CONTINUE_SEARCH;
  hits++;
  fpjunk = fpjunk * 3.0 + 1.0;          /* handlers may use SSE; the interrupted code's XMM state must survive */
  ep->ContextRecord->Rip += 2;
  return EXCEPTION_CONTINUE_EXECUTION;
}
static LONG WINAPI fix_av(PEXCEPTION_POINTERS ep) {
  PEXCEPTION_RECORD r = ep->ExceptionRecord;
  if (r->ExceptionCode != EXCEPTION_ACCESS_VIOLATION) return EXCEPTION_CONTINUE_SEARCH;
  hits++;
  av_info = (int)(r->ExceptionInformation[0] * 100 + (r->ExceptionInformation[1] == 0) * 10 + r->NumberParameters);
  ep->ContextRecord->Rax = (ULONG64)(ULONG_PTR)&dummy + 0;   /* point the store at valid memory and retry */
  return EXCEPTION_CONTINUE_EXECUTION;
}
static LONG WINAPI fix_div(PEXCEPTION_POINTERS ep) {
  if (ep->ExceptionRecord->ExceptionCode != EXCEPTION_INT_DIVIDE_BY_ZERO) return EXCEPTION_CONTINUE_SEARCH;
  hits++;
  ep->ContextRecord->Rcx = 1;
  return EXCEPTION_CONTINUE_EXECUTION;
}
static ULONG_PTR got_info[2]; static DWORD got_code, got_n;
static LONG WINAPI soft(PEXCEPTION_POINTERS ep) {
  if ((ep->ExceptionRecord->ExceptionCode & 0xF0000000) != 0xE0000000) return EXCEPTION_CONTINUE_SEARCH;
  hits++;
  got_code = ep->ExceptionRecord->ExceptionCode; got_n = ep->ExceptionRecord->NumberParameters;
  got_info[0] = ep->ExceptionRecord->ExceptionInformation[0]; got_info[1] = ep->ExceptionRecord->ExceptionInformation[1];
  return EXCEPTION_CONTINUE_EXECUTION;
}
static LONG WINAPI first_h(PEXCEPTION_POINTERS ep)  { (void)ep; order[order_n++] = 'F'; return EXCEPTION_CONTINUE_SEARCH; }
static LONG WINAPI second_h(PEXCEPTION_POINTERS ep) { (void)ep; order[order_n++] = 'S'; return EXCEPTION_CONTINUE_SEARCH; }
static LONG WINAPI last_h(PEXCEPTION_POINTERS ep)   { (void)ep; order[order_n++] = 'L'; return EXCEPTION_CONTINUE_EXECUTION; }
static LONG WINAPI uef_continue(PEXCEPTION_POINTERS ep) { hits++; ep->ContextRecord->Rip += 2; return EXCEPTION_CONTINUE_EXECUTION; }
static LONG WINAPI uef_die(PEXCEPTION_POINTERS ep) { (void)ep; printf("filter: dying\n"); fflush(stdout); return EXCEPTION_EXECUTE_HANDLER; }

int main(int argc, char **argv) {
  if (argc > 1 && !strcmp(argv[1], "die")) {          /* unhandled-exception filter ends the process with the exception code */
    SetUnhandledExceptionFilter(uef_die);
    volatile int *z = 0; *z = 1;
    printf("not reached\n");
    return 0;
  }
  PVOID h = AddVectoredExceptionHandler(1, skip_ud2);
  /* registers rcx/r11/rbx and xmm survive a handled fault */
  unsigned long long rc, r11v, rb; double xo = 0;
  fpjunk = 1.0;
  asm volatile(
      "movabs $0x1122334455667788, %%rcx\n"
      "movabs $0x99AABBCCDDEEFF00, %%r11\n"
      "movabs $0x0F0E0D0C0B0A0908, %%rbx\n"
      "movsd %[x], %%xmm3\n"
      "ud2\n"
      "movq %%rcx, %[rc]\n movq %%r11, %[r11]\n movq %%rbx, %[rb]\n movsd %%xmm3, %[xo]\n"
      : [rc] "=m"(rc), [r11] "=m"(r11v), [rb] "=m"(rb), [xo] "=m"(xo)
      : [x] "m"(*(volatile double *)&(double){6.25}) : "rcx", "r11", "rbx", "xmm3", "memory");
  printf("ud2: hits=%d regs=%d sse=%d\n", hits, rc == 0x1122334455667788ull && r11v == 0x99AABBCCDDEEFF00ull && rb == 0x0F0E0D0C0B0A0908ull, xo == 6.25 && fpjunk == 4.0);
  RemoveVectoredExceptionHandler(h);

  hits = 0; h = AddVectoredExceptionHandler(1, fix_av);
  asm volatile("movl $7, (%%rax)" :: "a"((void *)0) : "memory");
  printf("av: hits=%d write-info=%d retried-store=%d\n", hits, av_info == 112, dummy == 7);
  RemoveVectoredExceptionHandler(h);

  hits = 0; h = AddVectoredExceptionHandler(1, fix_div);
  int q;
  asm volatile("idivl %%ecx" : "=a"(q) : "a"(10), "d"(0), "c"(0) : "cc");
  printf("div0: hits=%d quotient=%d\n", hits, q);
  RemoveVectoredExceptionHandler(h);

  hits = 0; h = AddVectoredExceptionHandler(1, soft);
  ULONG_PTR args[2] = { 0xAAAA, 0xBBBB };
  RaiseException(0xE0000001, 0, 2, args);
  printf("raise: hits=%d code=%lx n=%lu info=%lx,%lx after-return-ok=1\n", hits, got_code, got_n, (unsigned long)got_info[0], (unsigned long)got_info[1]);
  RemoveVectoredExceptionHandler(h);

  /* First=1 handlers run before First=0 ones; the chain stops at the first CONTINUE_EXECUTION (so 'S' never runs) */
  order_n = 0; memset(order, 0, sizeof order);
  PVOID a = AddVectoredExceptionHandler(0, last_h);
  PVOID b = AddVectoredExceptionHandler(0, second_h);
  PVOID c = AddVectoredExceptionHandler(1, first_h);
  RaiseException(0xE0000002, 0, 0, NULL);
  printf("order: %s\n", order);
  RemoveVectoredExceptionHandler(a); RemoveVectoredExceptionHandler(b); RemoveVectoredExceptionHandler(c);

  hits = 0;
  SetUnhandledExceptionFilter(uef_continue);
  asm volatile("ud2");
  printf("filter-continue: hits=%d\n", hits);
  printf("done\n");
  return 0;
}
