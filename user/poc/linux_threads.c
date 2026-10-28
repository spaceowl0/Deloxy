#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <poll.h>
static pthread_mutex_t mu = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t cv = PTHREAD_COND_INITIALIZER;
static long counter; static int ready;
static __thread int tls_val;
static int pfd[2];
static void *worker(void *arg){ long id=(long)arg; tls_val=(int)id*10;
  for(int i=0;i<10000;i++){ pthread_mutex_lock(&mu); counter++; pthread_mutex_unlock(&mu); }
  return (void*)(id*100+tls_val); }
static void *waiter(void *a){ pthread_mutex_lock(&mu); while(!ready) pthread_cond_wait(&cv,&mu); pthread_mutex_unlock(&mu); return (void*)7; }
static void *writer(void *a){ const char*m="through the pipe"; usleep(10000); write(pfd[1],m,strlen(m)); close(pfd[1]); return 0; }
int main(void){
  pthread_t t[4]; long sum=0; void *r;
  for(long i=0;i<4;i++) pthread_create(&t[i],0,worker,(void*)(i+1));
  for(int i=0;i<4;i++){ pthread_join(t[i],&r); sum+=(long)r; }
  printf("counter=%ld sum=%ld\n",counter,sum);
  pthread_t w; pthread_create(&w,0,waiter,0); usleep(20000);
  pthread_mutex_lock(&mu); ready=1; pthread_cond_broadcast(&cv); pthread_mutex_unlock(&mu);
  pthread_join(w,&r); printf("condvar ok=%ld main tls=%d\n",(long)r,tls_val);
  pipe(pfd); pthread_create(&w,0,writer,0);
  char buf[64]={0}; struct pollfd p={pfd[0],POLLIN,0}; int pr=poll(&p,1,2000);
  int n=read(pfd[0],buf,63); pthread_join(w,0);
  printf("pipe: poll=%d %d bytes: %s\n",pr,n,buf);
  return 0; }
