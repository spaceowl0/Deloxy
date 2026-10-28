#include <windows.h>
#include <process.h>
#include <stdio.h>
static CRITICAL_SECTION cs;
static volatile LONG counter;
static long shared;
static __thread int tls_var = 5;
static DWORD tls_idx;
static DWORD WINAPI worker(LPVOID p){
  long id=(long)(INT_PTR)p;
  TlsSetValue(tls_idx,(LPVOID)(INT_PTR)(id*7));
  tls_var = (int)id*10;
  for(int i=0;i<5000;i++){ EnterCriticalSection(&cs); shared++; LeaveCriticalSection(&cs); InterlockedIncrement(&counter); }
  Sleep(5);
  return (DWORD)(id*100 + tls_var + (long)(INT_PTR)TlsGetValue(tls_idx));
}
static unsigned __stdcall ex_worker(void*p){ return 77; }
static HANDLE evt, sem;
static DWORD WINAPI signaler(LPVOID p){ Sleep(20); SetEvent(evt); ReleaseSemaphore(sem,2,NULL); return 0; }
int main(void){
  InitializeCriticalSection(&cs); tls_idx=TlsAlloc();
  HANDLE h[3]; DWORD tid;
  for(int i=0;i<3;i++) h[i]=CreateThread(NULL,0,worker,(LPVOID)(INT_PTR)(i+1),0,&tid);
  WaitForMultipleObjects(3,h,TRUE,INFINITE);
  DWORD sum=0,code; for(int i=0;i<3;i++){ GetExitCodeThread(h[i],&code); sum+=code; CloseHandle(h[i]); }
  printf("shared=%ld counter=%ld sum=%lu main tls=%d\n",shared,(long)counter,(unsigned long)sum,tls_var);
  evt=CreateEventA(NULL,TRUE,FALSE,NULL); sem=CreateSemaphoreA(NULL,0,10,NULL);
  HANDLE s=CreateThread(NULL,0,signaler,NULL,0,NULL);
  DWORD r=WaitForSingleObject(evt,2000); printf("event wait=%lu\n",(unsigned long)r);
  r=WaitForSingleObject(sem,2000); printf("semaphore wait=%lu\n",(unsigned long)r);
  r=WaitForSingleObject(sem,100); printf("semaphore again=%lu\n",(unsigned long)r);
  r=WaitForSingleObject(sem,100); printf("semaphore empty=%lu\n",(unsigned long)r);
  WaitForSingleObject(s,INFINITE);
  HANDLE m=CreateMutexA(NULL,FALSE,NULL); WaitForSingleObject(m,0); ReleaseMutex(m);
  uintptr_t t=_beginthreadex(NULL,0,ex_worker,NULL,0,NULL); WaitForSingleObject((HANDLE)t,INFINITE);
  GetExitCodeThread((HANDLE)t,&code); printf("beginthreadex code=%lu\n",(unsigned long)code);
  return 0; }
