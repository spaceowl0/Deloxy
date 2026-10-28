#include <windows.h>
#include <stdio.h>
static SRWLOCK srw = SRWLOCK_INIT;
static CONDITION_VARIABLE cv = CONDITION_VARIABLE_INIT;
static CRITICAL_SECTION cs;
static int queue[32], qn; static long hits;
static DWORD WINAPI producer(LPVOID p){
  for(int i=1;i<=20;i++){
    AcquireSRWLockExclusive(&srw); hits++; ReleaseSRWLockExclusive(&srw);
    EnterCriticalSection(&cs); queue[qn++]=i; WakeConditionVariable(&cv); LeaveCriticalSection(&cs);
    Sleep(1);
  }
  return 0; }
static DWORD WINAPI reader(LPVOID p){ AcquireSRWLockShared(&srw); Sleep(5); long v=hits; ReleaseSRWLockShared(&srw); return v>=0; }
int main(void){
  InitializeCriticalSection(&cs);
  HANDLE t=CreateThread(NULL,0,producer,NULL,0,NULL);
  long sum=0;
  for(int got=0;got<20;got++){
    EnterCriticalSection(&cs);
    while(qn==0) SleepConditionVariableCS(&cv,&cs,INFINITE);
    sum+=queue[--qn];
    LeaveCriticalSection(&cs);
  }
  WaitForSingleObject(t,INFINITE);
  AcquireSRWLockExclusive(&srw); hits++; ReleaseSRWLockExclusive(&srw);
  HANDLE r[2]; r[0]=CreateThread(NULL,0,reader,NULL,0,NULL); r[1]=CreateThread(NULL,0,reader,NULL,0,NULL);
  WaitForMultipleObjects(2,r,TRUE,5000);
  EnterCriticalSection(&cs);
  BOOL ok=SleepConditionVariableCS(&cv,&cs,50);
  DWORD err=GetLastError();
  LeaveCriticalSection(&cs);
  printf("consumer sum=%ld hits=%ld timeout ok=%d err=%lu\n",sum,hits,(int)ok,(unsigned long)err);
  return 0; }
