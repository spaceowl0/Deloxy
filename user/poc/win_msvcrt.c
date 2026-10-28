#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(int argc,char**argv){
  printf("msvcrt hello: argc=%d\n",argc);
  char*p=malloc(64); strcpy(p,"heap works"); puts(p); free(p);
  printf("fmt: %d %s %x %5.2f %c\n",42,"str",255,3.14159,'Z');
  FILE*f=fopen("README.txt","r");
  if(f){char b[48]={0}; fread(b,1,30,f); printf("read: %.18s\n",b); fclose(f);} else printf("fopen failed\n");
  return 7;
}
