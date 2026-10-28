#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
static int cmp(const void*a,const void*b){return *(const int*)a-*(const int*)b;}
int main(int argc,char**argv){
  printf("glibc hello: argc=%d\n",argc);
  int v[6]={5,3,9,1,7,2}; qsort(v,6,sizeof(int),cmp);
  for(int i=0;i<6;i++) printf("%d ",v[i]); printf("\n");
  char*m=malloc(100000); memset(m,'x',99999); m[99999]=0; printf("malloc len=%zu\n",strlen(m)); free(m);
  FILE*f=fopen("README.txt","r");
  if(f){ char b[64]={0}; size_t n=fread(b,1,40,f); printf("read %zu bytes: %.20s\n",n,b); fseek(f,0,SEEK_END); printf("size=%ld\n",ftell(f)); fclose(f);} else printf("fopen README.txt failed\n");
  FILE*o=fopen("lin-out.txt","w");
  if(o){ fprintf(o,"written by a Linux program\n"); fclose(o); printf("wrote lin-out.txt\n"); } else printf("fopen write failed\n");
  struct timespec ts; clock_gettime(CLOCK_MONOTONIC,&ts); printf("clock ok=%d\n",ts.tv_sec>=0);
  return 3;
}
