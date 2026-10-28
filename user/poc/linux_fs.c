/* Filesystem test: working directory, /tmp, hierarchical read-only tree, symlinks, *at() calls, error codes. */
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <dirent.h>
#include <sys/stat.h>
static int count_entries(const char *d, const char *want) {
  DIR *dp = opendir(d); if (!dp) return -1; int n = 0, found = 0; struct dirent *e;
  while ((e = readdir(dp))) { if (strcmp(e->d_name, ".") && strcmp(e->d_name, "..")) n++; if (want && !strcmp(e->d_name, want)) found = 1; }
  closedir(dp); return want ? found : n;
}
int main(void) {
  char cwd[256]; getcwd(cwd, sizeof cwd); printf("cwd0: %s\n", cwd);
  char b[128] = {0}; int fd = open("/usr/share/test/hello.txt", O_RDONLY); int n = fd >= 0 ? read(fd, b, sizeof b - 1) : -1; if (fd >= 0) close(fd);
  printf("rootfs: read %d '%.21s'\n", n, b);
  struct stat st; printf("stat: dir=%d file=%d size=%ld\n", stat("/usr/share", &st) == 0 && S_ISDIR(st.st_mode), stat("/usr/share/test/hello.txt", &st) == 0 && S_ISREG(st.st_mode), (long)st.st_size);
  fd = open("/usr/share/test/link", O_RDONLY); n = fd >= 0 ? read(fd, b, 5) : -1; b[n > 0 ? n : 0] = 0; printf("symlink-file: '%s'\n", b); if (fd >= 0) close(fd);
  fd = open("/usr/share/test/sublink/deep.txt", O_RDONLY); n = fd >= 0 ? read(fd, b, 9) : -1; b[n > 0 ? n : 0] = 0; printf("symlink-dir: '%s'\n", b); if (fd >= 0) close(fd);
  char lt[64] = {0}; ssize_t ln = readlink("/usr/share/test/link", lt, sizeof lt - 1); printf("readlink: %zd '%s'\n", ln, lt);
  fd = open("/lib/testlib/data.bin", O_RDONLY); n = fd >= 0 ? read(fd, b, 7) : -1; b[n > 0 ? n : 0] = 0; printf("usrmerge: '%s'\n", b); if (fd >= 0) close(fd);
  printf("readdir: /usr/share/test has %d entries, hello.txt=%d, sub is dir=%d\n", count_entries("/usr/share/test", 0), count_entries("/usr/share/test", "hello.txt"), stat("/usr/share/test/sub", &st) == 0 && S_ISDIR(st.st_mode));
  printf("root-listing: usr=%d tmp=%d\n", count_entries("/", "usr"), count_entries("/", "tmp"));
  printf("write-rootfs: %s\n", open("/usr/share/test/new.txt", O_WRONLY | O_CREAT, 0644) < 0 ? (errno == EROFS ? "EROFS" : "other") : "WRONG");
  printf("mkdir: %d", mkdir("/tmp/d1", 0755)); printf(" again=%s", mkdir("/tmp/d1", 0755) < 0 && errno == EEXIST ? "EEXIST" : "WRONG");
  printf(" nested-noparent=%s\n", mkdir("/tmp/nope/x", 0755) < 0 && errno == ENOENT ? "ENOENT" : "WRONG");
  printf("chdir: %d", chdir("/tmp/d1")); getcwd(cwd, sizeof cwd); printf(" cwd=%s", cwd); printf(" bad=%s\n", chdir("/usr/share/test/hello.txt") < 0 && errno == ENOTDIR ? "ENOTDIR" : "WRONG");
  fd = open("rel.txt", O_WRONLY | O_CREAT | O_TRUNC, 0644); write(fd, "tmp data", 8); close(fd);
  fd = open("/tmp/d1/rel.txt", O_RDONLY); n = fd >= 0 ? read(fd, b, 20) : -1; b[n > 0 ? n : 0] = 0; printf("tmpfile: relative write -> absolute read %d '%s'\n", n, b); if (fd >= 0) close(fd);
  printf("tmp-readdir: %d entry, rel.txt=%d\n", count_entries(".", 0), count_entries(".", "rel.txt"));
  DIR *dp = opendir("/tmp"); int dfd = dirfd(dp); fd = openat(dfd, "d1/rel.txt", O_RDONLY); n = fd >= 0 ? read(fd, b, 3) : -1; b[n > 0 ? n : 0] = 0; printf("openat: '%s'", b); if (fd >= 0) close(fd);
  printf(" fstatat=%d\n", fstatat(dfd, "d1", &st, 0) == 0 && S_ISDIR(st.st_mode)); closedir(dp);
  int rn = rename("rel.txt", "moved.txt"); int og = access("rel.txt", F_OK) < 0; int nk = access("moved.txt", F_OK) == 0;
  printf("rename: %d old-gone=%d new-ok=%d", rn, og, nk);
  int rd = rmdir("/tmp/d1"); printf(" rmdir-nonempty=%s\n", rd < 0 && errno == ENOTEMPTY ? "ENOTEMPTY" : "WRONG");
  int ul = unlink("moved.txt"); chdir("/"); int rm = rmdir("/tmp/d1"); int gone = access("/tmp/d1", F_OK) < 0;
  printf("unlink: %d rmdir: %d gone=%d\n", ul, rm, gone);
  chdir("/usr/share"); fd = open("test/hello.txt", O_RDONLY); n = fd >= 0 ? read(fd, b, 5) : -1; b[n > 0 ? n : 0] = 0; printf("relative-rootfs: '%s'", b); if (fd >= 0) close(fd);
  fd = open("../share/test/sub/../hello.txt", O_RDONLY); printf(" dotdot=%s\n", fd >= 0 ? "ok" : "FAIL"); if (fd >= 0) close(fd);
  chdir("/"); printf("missing: %s\n", open("/usr/nothing/here", O_RDONLY) < 0 && errno == ENOENT ? "ENOENT" : "WRONG");
  char big[1000]; memset(big, 'x', sizeof big); fd = open("/tmp/big", O_WRONLY | O_CREAT, 0644); for (int i = 0; i < 100; i++) write(fd, big, sizeof big); close(fd);
  stat("/tmp/big", &st); printf("big: size=%ld\n", (long)st.st_size); unlink("/tmp/big");
  printf("done\n"); return 0;
}
