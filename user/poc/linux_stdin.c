#include <stdio.h>
#include <string.h>
#include <dirent.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
int main(void){
  char name[64];
  printf("name? "); fflush(stdout);
  if(!fgets(name,sizeof name,stdin)){ puts("no input"); return 1; }
  name[strcspn(name,"\r\n")]=0;
  printf("hello, %s!\n",name);
  DIR*d=opendir("/"); int n=0,found=0; struct dirent*e;
  if(d){ while((e=readdir(d))){ n++; if(!strcmp(e->d_name,"README.txt")) found=1; } closedir(d); }
  printf("dir: entries>=3=%d readme=%d\n", n>=3, found);
  int fd=open("README.txt",O_RDONLY); off_t len=lseek(fd,0,SEEK_END);
  char*m=mmap(0,len,PROT_READ,MAP_PRIVATE,fd,0);
  if(m==MAP_FAILED) puts("mmap failed"); else printf("mmap: %.7s len=%ld\n",m,(long)len);
  close(fd);
  FILE*f=fopen("tmp-del.txt","w"); fputs("x",f); fclose(f);
  printf("unlink=%d\n",unlink("tmp-del.txt"));
  return 0;
}
