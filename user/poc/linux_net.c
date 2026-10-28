#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
int main(int argc,char**argv){
  int s=socket(AF_INET,SOCK_STREAM,0);
  struct sockaddr_in a; memset(&a,0,sizeof a); a.sin_family=AF_INET; a.sin_port=htons(argc>1?atoi(argv[1]):8777); inet_pton(AF_INET,"10.0.2.2",&a.sin_addr);
  if(connect(s,(struct sockaddr*)&a,sizeof a)<0){ printf("connect failed: errno=%d\n",errno); return 2; }
  const char*req="GET /nothing HTTP/1.0\r\nHost: x\r\n\r\n"; send(s,req,strlen(req),0);
  char buf[512]; int n,total=0; char first[64]={0};
  while((n=read(s,buf,sizeof buf))>0){ if(!total){ int k=strcspn(buf,"\r\n"); if(k>63)k=63; memcpy(first,buf,k);} total+=n; }
  printf("status: %s (%d bytes)\n",first,total); close(s); return 0; }
