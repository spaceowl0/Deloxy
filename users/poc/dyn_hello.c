#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <unistd.h>
int main(int argc, char **argv) {
  char *p = malloc(100); strcpy(p, "dynamic linking works"); 
  printf("dyn: %s (pid>0=%d) sqrt2=%.6f argc=%d\n", p, getpid() > 0, sqrt(2.0), argc);
  free(p); return 0;
}
