#include <winsock2.h>
#include <stdio.h>
#include <string.h>
int main(void){
  WSADATA w; if(WSAStartup(MAKEWORD(2,2),&w)){ puts("wsastartup failed"); return 1; }
  SOCKET s=socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);
  struct sockaddr_in a; memset(&a,0,sizeof a); a.sin_family=AF_INET; a.sin_port=htons(8777); a.sin_addr.s_addr=inet_addr("10.0.2.2");
  if(connect(s,(struct sockaddr*)&a,sizeof a)==SOCKET_ERROR){ printf("connect failed: wsa=%d\n",WSAGetLastError()); return 2; }
  const char*req="GET /nothing HTTP/1.0\r\nHost: x\r\n\r\n"; send(s,req,(int)strlen(req),0);
  char buf[512]; int n,total=0; char first[64]={0};
  while((n=recv(s,buf,sizeof buf,0))>0){ if(!total){ int k=(int)strcspn(buf,"\r\n"); if(k>63)k=63; memcpy(first,buf,k);} total+=n; }
  printf("winsock status: %s (%d bytes)\n",first,total); closesocket(s); WSACleanup(); return 0; }
