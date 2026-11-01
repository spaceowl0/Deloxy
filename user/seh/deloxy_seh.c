/* deloxy_seh.dll - user-mode SEH runtime for Deloxy's Windows compatibility layer (the part of ntdll that walks
 * `.pdata`): RtlLookupFunctionEntry, RtlVirtualUnwind, RtlUnwindEx, RtlUnwind, __C_specific_handler and the frame
 * dispatcher the kernel calls after the vectored handlers have declined an exception.
 * The kernel only supplies primitives (module/.pdata query, RtlCaptureContext, RtlRestoreContext) as kernel32 shims.
 * Not implemented: epilogue detection (a fault *inside* an epilogue unwinds as if still in the body), UWOP_EPILOG
 * (unwind info v2), dynamic function tables, UNW_FLAG nested/collided handling beyond "continue". */
#include <windows.h>

typedef struct { ULONG64 base, pdata, plen, size; } ModInfo;
static int (*p_info)(ULONG64, ModInfo *);
static int (*p_register)(void *);
static void (*p_capture)(PCONTEXT);
static void (*p_restore)(PCONTEXT, PEXCEPTION_RECORD);

/* freestanding: the compiler may emit calls to these for big struct copies */
void *memcpy(void *d, const void *s, size_t n) { void *r = d; __asm__ volatile("rep movsb" : "+D"(d), "+S"(s), "+c"(n) :: "memory"); return r; }
void *memset(void *d, int c, size_t n) { void *r = d; __asm__ volatile("rep stosb" : "+D"(d), "+c"(n) : "a"(c) : "memory"); return r; }

#define STATUS_UNWIND_CODE 0xC0000027u
/* the kernel's exception-return stub (thunk page + 0x3D00, == win_exc::EXC_RET_VA): handlers are called with it as return address */
#define EXC_RET_VA 0x7FFE00003D00ull

typedef struct { BYTE offset; BYTE op : 4; BYTE info : 4; } UCode;
typedef struct { BYTE ver : 3; BYTE flags : 5; BYTE prolog; BYTE count; BYTE frame_reg : 4; BYTE frame_off : 4; UCode codes[1]; } UInfo;

PRUNTIME_FUNCTION rt_lookup(DWORD64 pc, PDWORD64 imagebase, PUNWIND_HISTORY_TABLE hist) {
  (void)hist;
  ModInfo mi;
  if (!p_info || !p_info(pc, &mi)) { if (imagebase) *imagebase = 0; return 0; }
  if (imagebase) *imagebase = mi.base;
  if (!mi.pdata || !mi.plen) return 0;
  RUNTIME_FUNCTION *t = (RUNTIME_FUNCTION *)mi.pdata;
  long lo = 0, hi = (long)(mi.plen / sizeof(RUNTIME_FUNCTION)) - 1;
  DWORD rva = (DWORD)(pc - mi.base);
  while (lo <= hi) {
    long mid = (lo + hi) / 2;
    if (rva < t[mid].BeginAddress) hi = mid - 1;
    else if (rva >= t[mid].EndAddress) lo = mid + 1;
    else return &t[mid];
  }
  return 0;
}

PEXCEPTION_ROUTINE rt_virtual_unwind(DWORD htype, DWORD64 base, DWORD64 pc, PRUNTIME_FUNCTION fe, PCONTEXT ctx,
                                     PVOID *hdata, PDWORD64 establisher, PKNONVOLATILE_CONTEXT_POINTERS ptrs) {
  (void)ptrs;
  DWORD64 *reg = &ctx->Rax;                                   /* Rax,Rcx,Rdx,Rbx,Rsp,Rbp,Rsi,Rdi,R8..R15 */
  UInfo *info = (UInfo *)(base + (fe->UnwindData & ~3u));
  DWORD64 offset = pc - (base + fe->BeginAddress);
  DWORD64 frame = ctx->Rsp;
  int fpreg_done = 0;
  int chained = 0;
  for (;;) {
    int in_prolog = !chained && offset < info->prolog;
    unsigned i = 0, n = info->count;
    if (!chained && info->frame_reg) {
      /* the frame register is authoritative once SET_FPREG has executed; the other codes are relative to it */
      DWORD64 fpoff = 0;
      for (unsigned k = 0; k < n; ) {
        UCode *c = &info->codes[k];
        if (c->op == 3) fpoff = c->offset;
        k += (c->op == 1) ? (c->info == 0 ? 2 : 3) : (c->op == 4 || c->op == 8) ? 2 : (c->op == 5 || c->op == 9) ? 3 : 1;
      }
      if (!in_prolog || fpoff <= offset) {
        ctx->Rsp = reg[info->frame_reg] - (DWORD64)info->frame_off * 16;
        frame = ctx->Rsp;
        fpreg_done = 1;
      }
    }
    while (i < n) {
      UCode *c = &info->codes[i];
      unsigned slots = 1;
      DWORD64 *sp = (DWORD64 *)ctx->Rsp;
      int skip = in_prolog && c->offset > offset;              /* not executed yet */
      switch (c->op) {
        case 0: if (!skip) { reg[c->info] = *sp; ctx->Rsp += 8; } break;                              /* PUSH_NONVOL */
        case 1:                                                                                       /* ALLOC_LARGE */
          if (c->info == 0) { slots = 2; if (!skip) ctx->Rsp += (DWORD64)*(WORD *)&info->codes[i + 1] * 8; }
          else { slots = 3; if (!skip) ctx->Rsp += *(DWORD *)&info->codes[i + 1]; }
          break;
        case 2: if (!skip) ctx->Rsp += (DWORD64)c->info * 8 + 8; break;                               /* ALLOC_SMALL */
        case 3: break;                                                                                /* SET_FPREG: applied above */
        case 4: slots = 2; if (!skip) reg[c->info] = *(DWORD64 *)(ctx->Rsp + (DWORD64)*(WORD *)&info->codes[i + 1] * 8); break;  /* SAVE_NONVOL */
        case 5: slots = 3; if (!skip) reg[c->info] = *(DWORD64 *)(ctx->Rsp + *(DWORD *)&info->codes[i + 1]); break;               /* SAVE_NONVOL_FAR */
        case 8: slots = 2; if (!skip) (&ctx->Xmm0)[c->info] = *(M128A *)(ctx->Rsp + (DWORD64)*(WORD *)&info->codes[i + 1] * 16); break; /* SAVE_XMM128 */
        case 9: slots = 3; if (!skip) (&ctx->Xmm0)[c->info] = *(M128A *)(ctx->Rsp + *(DWORD *)&info->codes[i + 1]); break;         /* SAVE_XMM128_FAR */
        case 10:                                                                                      /* PUSH_MACHFRAME */
          if (!skip) { if (c->info) ctx->Rsp += 8; ctx->Rip = sp[c->info ? 1 : 0]; ctx->Rsp = sp[c->info ? 4 : 3]; goto machframe; }
          break;
        case 6: case 7: slots = 1; break;                                                             /* v2 epilog markers: ignored */
        default: break;
      }
      i += slots;
    }
    if (!(info->flags & UNW_FLAG_CHAININFO)) break;
    /* the parent's RUNTIME_FUNCTION follows the (even-padded) codes; all of its codes apply */
    RUNTIME_FUNCTION *par = (RUNTIME_FUNCTION *)&info->codes[(info->count + 1) & ~1u];
    info = (UInfo *)(base + (par->UnwindData & ~3u));
    chained = 1;
  }
  (void)fpreg_done;                                           /* establisher: frame register based, else RSP of the body */
  ctx->Rip = *(DWORD64 *)ctx->Rsp;                            /* the return address */
  ctx->Rsp += 8;
  if (ctx->Rip == EXC_RET_VA) {
    /* unwound out of the exception dispatcher (the kernel called us): like ntdll's KiUserExceptionDispatcher this is a
       machine frame - continue in the context the exception was raised in. Layout (kernel): handler return slot, 32 bytes
       shadow, pad, then { magic, next, exit, kind } (32), EXCEPTION_POINTERS { record, context }. */
    PCONTEXT saved = *(PCONTEXT *)(ctx->Rsp + 48 + 32 + 8);
    *ctx = *saved;
  }
machframe:
  *establisher = frame;
  if (hdata) *hdata = 0;
  if (info->flags & htype & (UNW_FLAG_EHANDLER | UNW_FLAG_UHANDLER)) {
    DWORD *h = (DWORD *)&info->codes[(info->count + 1) & ~1u];
    if (hdata) *hdata = h + 1;
    return (PEXCEPTION_ROUTINE)(base + *h);
  }
  return 0;
}

/* one frame of an unwind: fills `next` with the caller's context; returns the language handler (or 0) */
static PEXCEPTION_ROUTINE step(DWORD htype, DWORD64 pc, PCONTEXT cur, PCONTEXT next, PRUNTIME_FUNCTION *fe_out, DWORD64 *base,
                               PVOID *hdata, DWORD64 *frame) {
  *next = *cur;
  PRUNTIME_FUNCTION fe = rt_lookup(pc, base, 0);
  *fe_out = fe;
  *hdata = 0;
  if (!fe) {                                                  /* leaf function: the return address is at [rsp] */
    *frame = cur->Rsp;
    next->Rip = *(DWORD64 *)cur->Rsp;
    next->Rsp = cur->Rsp + 8;
    return 0;
  }
  return rt_virtual_unwind(htype, *base, pc, fe, next, hdata, frame, 0);
}


typedef EXCEPTION_DISPOSITION (*Handler)(PEXCEPTION_RECORD, ULONG64, PCONTEXT, PDISPATCHER_CONTEXT);

/* called by the kernel (after the vectored handlers) with EXCEPTION_POINTERS*: walk the stack calling language handlers */
LONG rt_dispatch_frames(PEXCEPTION_POINTERS ep) {
  PEXCEPTION_RECORD rec = ep->ExceptionRecord;
  CONTEXT cur = *ep->ContextRecord, next;
  for (int depth = 0; depth < 512; depth++) {
    PRUNTIME_FUNCTION fe; DWORD64 base = 0, frame = 0; PVOID hd;
    DWORD64 pc = cur.Rip;
    PEXCEPTION_ROUTINE h = step(UNW_FLAG_EHANDLER, pc, &cur, &next, &fe, &base, &hd, &frame);
    if (next.Rip == 0 || frame == 0) break;
    if (h) {
      DISPATCHER_CONTEXT d;
      memset(&d, 0, sizeof d);
      d.ControlPc = pc; d.ImageBase = base; d.FunctionEntry = fe; d.EstablisherFrame = frame;
      d.ContextRecord = &cur; d.LanguageHandler = h; d.HandlerData = hd;
      EXCEPTION_DISPOSITION r = ((Handler)h)(rec, frame, &cur, &d);
      if (r == ExceptionContinueExecution) {
        *ep->ContextRecord = cur;                              /* the handler may have edited the context */
        return -1;
      }
    }
    cur = next;
  }
  return 0;                                                   /* EXCEPTION_CONTINUE_SEARCH */
}

void rt_unwind_ex(PVOID end_frame, PVOID target_ip, PEXCEPTION_RECORD rec, PVOID retval, PCONTEXT orig, PUNWIND_HISTORY_TABLE hist) {
  EXCEPTION_RECORD local;
  CONTEXT next;
  PCONTEXT context = orig;
  p_capture(context);                                         /* rip/rsp: just after this call, inside this function */
  if (!rec) {
    memset(&local, 0, sizeof local);
    local.ExceptionCode = STATUS_UNWIND_CODE;
    local.ExceptionAddress = (PVOID)context->Rip;
    rec = &local;
  }
  rec->ExceptionFlags |= EXCEPTION_UNWINDING;
  if (!end_frame) rec->ExceptionFlags |= EXCEPTION_EXIT_UNWIND;
  {
    /* unwind this function's own frame: `context` becomes the caller's state */
    PRUNTIME_FUNCTION fe; DWORD64 base = 0, frame = 0; PVOID hd;
    step(0, context->Rip, context, &next, &fe, &base, &hd, &frame);
    *context = next;
  }
  for (int depth = 0; depth < 1024; depth++) {
    PRUNTIME_FUNCTION fe; DWORD64 base = 0, frame = 0; PVOID hd;
    DWORD64 pc = context->Rip;
    PEXCEPTION_ROUTINE h = step(UNW_FLAG_UHANDLER, pc, context, &next, &fe, &base, &hd, &frame);
    if (next.Rip == 0 && frame == 0) break;
    if (frame == (DWORD64)end_frame) rec->ExceptionFlags |= EXCEPTION_TARGET_UNWIND;
    if (h) {
      DISPATCHER_CONTEXT d;
      memset(&d, 0, sizeof d);
      d.ControlPc = pc; d.ImageBase = base; d.FunctionEntry = fe; d.EstablisherFrame = frame; d.TargetIp = (ULONG64)target_ip;
      d.ContextRecord = context; d.LanguageHandler = h; d.HandlerData = hd; d.HistoryTable = hist;
      ((Handler)h)(rec, frame, context, &d);                  /* ExceptionContinueSearch (or collided: treated the same) */
    }
    if (frame == (DWORD64)end_frame) break;
    *context = next;
  }
  context->Rax = (DWORD64)retval;
  context->Rip = (DWORD64)target_ip;
  p_restore(context, rec);
}

void rt_unwind(PVOID end_frame, PVOID target_ip, PEXCEPTION_RECORD rec, PVOID retval) {
  CONTEXT c;
  rt_unwind_ex(end_frame, target_ip, rec, retval, &c, 0);
}

/* C scope tables (__try/__except/__finally compiled by MSVC/clang):  HandlerData = { DWORD Count; { Begin, End, Handler, Jump }[Count] } */
typedef struct { DWORD begin, end, handler, jump; } Scope;
EXCEPTION_DISPOSITION rt_c_specific_handler(PEXCEPTION_RECORD rec, ULONG64 frame, PCONTEXT ctx, PDISPATCHER_CONTEXT d) {
  DWORD *tab = (DWORD *)d->HandlerData;
  if (!tab) return ExceptionContinueSearch;
  DWORD count = tab[0];
  Scope *sc = (Scope *)(tab + 1);
  DWORD64 pc = d->ControlPc - d->ImageBase;
  if (rec->ExceptionFlags & (EXCEPTION_UNWINDING | EXCEPTION_EXIT_UNWIND)) {
    for (DWORD i = d->ScopeIndex; i < count; i++) {
      if (pc < sc[i].begin || pc >= sc[i].end) continue;
      if (sc[i].jump == 0) {                                  /* __finally: termination handler */
        d->ScopeIndex = i + 1;
        ((void (*)(BOOLEAN, ULONG64))(d->ImageBase + sc[i].handler))(1, frame);
      } else if ((rec->ExceptionFlags & EXCEPTION_TARGET_UNWIND) && d->TargetIp == d->ImageBase + sc[i].jump) {
        return ExceptionContinueSearch;                       /* the __except block we are unwinding to */
      }
    }
    return ExceptionContinueSearch;
  }
  EXCEPTION_POINTERS ep = { rec, ctx };
  for (DWORD i = 0; i < count; i++) {
    if (pc < sc[i].begin || pc >= sc[i].end || sc[i].jump == 0) continue;
    LONG r = sc[i].handler == 1 ? 1 : ((LONG (*)(PEXCEPTION_POINTERS, ULONG64))(d->ImageBase + sc[i].handler))(&ep, frame);
    if (r < 0) return ExceptionContinueExecution;
    if (r > 0) { rt_unwind_ex((PVOID)frame, (PVOID)(d->ImageBase + sc[i].jump), rec, 0, d->ContextRecord, d->HistoryTable); }
  }
  return ExceptionContinueSearch;
}

BOOL WINAPI DllMain(HINSTANCE h, DWORD reason, LPVOID res) {
  (void)h; (void)res;
  if (reason == DLL_PROCESS_ATTACH) {
    HMODULE k = GetModuleHandleA("kernel32.dll");
    p_info = (void *)GetProcAddress(k, "__DeloxyModuleInfo");
    p_register = (void *)GetProcAddress(k, "__DeloxyRegisterSeh");
    p_capture = (void *)GetProcAddress(k, "RtlCaptureContext");
    p_restore = (void *)GetProcAddress(k, "RtlRestoreContext");
    if (!p_info || !p_register || !p_capture || !p_restore) return FALSE;
    p_register((void *)rt_dispatch_frames);
  }
  return TRUE;
}
