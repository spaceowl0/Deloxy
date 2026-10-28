#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static int cmp(const void*a,const void*b){return *(const int*)a-*(const int*)b;}
static void bye(void){ puts("atexit ran"); }
int main(void){
  atexit(bye);
  int v[7]={9,4,7,1,8,2,5}; qsort(v,7,sizeof(int),cmp);
  for(int i=0;i<7;i++) printf("%d ",v[i]); puts("");
  char name[32]={0}; int age=0;
  printf("name age? "); fflush(stdout);
  int got=scanf("%31s %d",name,&age);
  printf("scanned %d: %s (%d)\n",got,name,age);
  HANDLE h=CreateFileA("win-out.txt",GENERIC_WRITE,0,NULL,CREATE_ALWAYS,FILE_ATTRIBUTE_NORMAL,NULL);
  DWORD w=0; WriteFile(h,"abc123",6,&w,NULL); CloseHandle(h);
  h=CreateFileA("win-out.txt",GENERIC_READ,0,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);
  char b[16]={0}; DWORD r=0; ReadFile(h,b,15,&r,NULL);
  printf("read back %lu: %s size=%lu\n",(unsigned long)r,b,(unsigned long)GetFileSize(h,NULL)); CloseHandle(h);
  WIN32_FIND_DATAA fd; HANDLE f=FindFirstFileA("*.txt",&fd); int cnt=0;
  if(f!=INVALID_HANDLE_VALUE){ do cnt++; while(FindNextFileA(f,&fd)); FindClose(f); }
  printf("txt files>=2: %d\n",cnt>=2);
  printf("strtol=%ld\n",strtol("0x1f",NULL,0));
  return 5;
}
