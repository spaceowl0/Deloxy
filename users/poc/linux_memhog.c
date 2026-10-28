#include <stdio.h>
#include <sys/mman.h>
int main(void){
  size_t mb=0; void *p;
  while((p=mmap(0,1<<20,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0))!=MAP_FAILED){ ((char*)p)[0]=1; mb++; if(mb>4096) break; }
  printf("memory limit reached after %zu MiB\n",mb);
  p=mmap(0,4096,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
  printf("small mmap after limit: %s\n", p==MAP_FAILED?"failed":"ok");
  return 0; }
