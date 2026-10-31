/* Persistent hierarchical filesystem test (run twice across a reboot):
 *   linux_pfs.elf w   build a tree under /home and /store, exercise every operation and its errno
 *   linux_pfs.elf r   after a reboot: everything is still there with the same content, modes and links */
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <dirent.h>
#include <sys/stat.h>

static int bad = 0;
#define CHECK(cond, name) do { if (cond) printf("ok   %s\n", name); else { printf("FAIL %s (errno %d)\n", name, errno); bad++; } } while (0)

static int count_entries(const char *d, const char *want) {
  DIR *dp = opendir(d); if (!dp) return -1; int n = 0, found = 0; struct dirent *e;
  while ((e = readdir(dp))) { if (strcmp(e->d_name, ".") && strcmp(e->d_name, "..")) n++; if (want && !strcmp(e->d_name, want)) found = 1; }
  closedir(dp); return want ? found : n;
}
static int dtype_of(const char *d, const char *name) {
  DIR *dp = opendir(d); if (!dp) return -1; struct dirent *e; int t = -1;
  while ((e = readdir(dp))) if (!strcmp(e->d_name, name)) t = e->d_type;
  closedir(dp); return t;
}
static int put(const char *path, const void *data, size_t n) {
  int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644); if (fd < 0) return -1;
  ssize_t w = write(fd, data, n); int c = close(fd); return (w == (ssize_t)n && c == 0) ? 0 : -1;
}
static ssize_t get(const char *path, char *buf, size_t max) {
  int fd = open(path, O_RDONLY); if (fd < 0) return -1;
  ssize_t n = read(fd, buf, max); close(fd); return n;
}
static unsigned pattern(unsigned i) { return (i * 2654435761u) >> 24; }

static void phase_write(void) {
  char b[256]; struct stat st;
  CHECK(mkdir("/home", 0755) == 0, "mkdir /home");
  CHECK(mkdir("/home", 0755) < 0 && errno == EEXIST, "mkdir existing -> EEXIST");
  CHECK(mkdir("/home/user", 0755) == 0 && mkdir("/home/user/docs", 0755) == 0, "mkdir nested");
  CHECK(mkdir("/home/nope/x", 0755) < 0 && errno == ENOENT, "mkdir missing parent -> ENOENT");
  CHECK(put("/home/user/docs/notes.txt", "persistent hello", 16) == 0, "create file in nested dir");
  CHECK(put("/home/user/space name é.txt", "unicode", 7) == 0, "file name with spaces and UTF-8");
  CHECK(put("/home/user/docs/notes.txt/x", "1", 1) < 0 && errno == ENOTDIR, "file used as directory -> ENOTDIR");
  CHECK(open("/home/user/docs", O_WRONLY) < 0 && errno == EISDIR, "open directory for writing -> EISDIR");
  /* append and in-place rewrite of an existing file */
  int fd = open("/home/user/docs/notes.txt", O_WRONLY | O_APPEND); write(fd, " + more", 7); close(fd);
  ssize_t n = get("/home/user/docs/notes.txt", b, sizeof b - 1); b[n > 0 ? n : 0] = 0;
  CHECK(n == 23 && !strcmp(b, "persistent hello + more"), "O_APPEND extends the file");
  fd = open("/home/user/docs/notes.txt", O_RDWR); lseek(fd, 11, SEEK_SET); write(fd, "WORLD", 5); close(fd);
  n = get("/home/user/docs/notes.txt", b, sizeof b - 1); b[n > 0 ? n : 0] = 0;
  CHECK(!strcmp(b, "persistent WORLD + more"), "overwrite in the middle (pwrite semantics)");
  CHECK(truncate("/home/user/docs/notes.txt", 10) == 0 && stat("/home/user/docs/notes.txt", &st) == 0 && st.st_size == 10, "truncate()");
  /* metadata */
  CHECK(stat("/home/user/docs", &st) == 0 && S_ISDIR(st.st_mode), "stat directory");
  CHECK(stat("/home/user/docs/notes.txt", &st) == 0 && S_ISREG(st.st_mode) && (st.st_mode & 0777) == 0644 && st.st_mtime > 1000000000, "stat file: type, mode 0644, mtime");
  CHECK(chmod("/home/user/docs/notes.txt", 0755) == 0 && stat("/home/user/docs/notes.txt", &st) == 0 && (st.st_mode & 0777) == 0755, "chmod 0755 is reported by stat");
  /* symlinks */
  CHECK(symlink("docs/notes.txt", "/home/user/rel-link") == 0, "symlink (relative target)");
  CHECK(symlink("/home/user/docs", "/home/user/abs-link") == 0, "symlink (absolute target)");
  CHECK(symlink("/home/user/loop-b", "/home/user/loop-a") == 0 && symlink("/home/user/loop-a", "/home/user/loop-b") == 0, "create a symlink loop");
  CHECK(open("/home/user/loop-a", O_RDONLY) < 0 && errno == ELOOP, "open through a loop -> ELOOP");
  ssize_t ln = readlink("/home/user/rel-link", b, sizeof b - 1); b[ln > 0 ? ln : 0] = 0;
  CHECK(ln == 14 && !strcmp(b, "docs/notes.txt"), "readlink");
  CHECK(lstat("/home/user/rel-link", &st) == 0 && S_ISLNK(st.st_mode) && st.st_size == 14, "lstat reports a symlink with the target length");
  CHECK(stat("/home/user/rel-link", &st) == 0 && S_ISREG(st.st_mode) && st.st_size == 10, "stat follows the link");
  n = get("/home/user/abs-link/notes.txt", b, sizeof b - 1); b[n > 0 ? n : 0] = 0;
  CHECK(n == 10 && !strncmp(b, "persistent", 10), "read through a directory symlink");
  CHECK(dtype_of("/home/user", "docs") == DT_DIR && dtype_of("/home/user", "space name é.txt") == DT_REG, "readdir d_type: directory and regular file");
  CHECK(link("/home/user/docs/notes.txt", "/home/user/hard") < 0, "hard links are refused");
  /* rename */
  CHECK(rename("/home/user/space name é.txt", "/home/user/docs/moved.txt") == 0 && access("/home/user/space name é.txt", F_OK) < 0, "rename across directories");
  CHECK(put("/home/user/victim", "old", 3) == 0 && rename("/home/user/docs/moved.txt", "/home/user/victim") == 0, "rename replaces a file");
  n = get("/home/user/victim", b, sizeof b - 1); b[n > 0 ? n : 0] = 0;
  CHECK(!strcmp(b, "unicode"), "replaced file has the new content");
  CHECK(rename("/home/user/docs", "/home/user/docs/sub") < 0, "rename a directory into itself fails");
  CHECK(rmdir("/home/user/docs") < 0 && errno == ENOTEMPTY, "rmdir non-empty -> ENOTEMPTY");
  CHECK(mkdir("/home/user/tmpdir", 0755) == 0 && rmdir("/home/user/tmpdir") == 0 && access("/home/user/tmpdir", F_OK) < 0, "mkdir + rmdir");
  CHECK(unlink("/home/user/victim") == 0 && unlink("/home/user/victim") < 0 && errno == ENOENT, "unlink, then ENOENT");
  CHECK(count_entries("/home/user", "docs") == 1 && count_entries("/home", "user") == 1, "readdir finds entries");
  /* big file: 1 MiB with a pattern, written in odd-sized chunks */
  fd = open("/store/big.bin", O_WRONLY | O_CREAT | O_TRUNC, 0644);
  unsigned char chunk[1000]; unsigned off = 0; int wok = fd >= 0;
  while (wok && off < (1u << 20)) { unsigned m = sizeof chunk; if (off + m > (1u << 20)) m = (1u << 20) - off; for (unsigned i = 0; i < m; i++) chunk[i] = pattern(off + i); wok = write(fd, chunk, m) == (ssize_t)m; off += m; }
  CHECK(wok && close(fd) == 0, "write 1 MiB");
  CHECK(stat("/store/big.bin", &st) == 0 && st.st_size == (1 << 20), "1 MiB size");
  /* /store mirrors /home (same tree) and kernel-owned names are protected */
  CHECK(get("/store/home/user/docs/notes.txt", b, 10) == 10, "/store/home/... is the same tree as /home/...");
  CHECK(put("/store/upd.evil", "x", 1) < 0 && errno == EACCES, "kernel-owned upd.* cannot be created");
  CHECK(mkdir("/store/perms.x", 0755) < 0 && errno == EACCES, "kernel-owned perms.* cannot be created as a directory");
  CHECK(chdir("/home/user/docs") == 0 && put("rel.txt", "relative", 8) == 0 && get("/home/user/docs/rel.txt", b, 8) == 8, "relative paths against a persistent cwd");
  getcwd(b, sizeof b); CHECK(!strcmp(b, "/home/user/docs"), "getcwd in the persistent tree");
  chdir("/");
  printf(bad ? "PFS-W FAIL %d\n" : "PFS-W OK\n", bad);
}

static void phase_read(void) {
  char b[256]; struct stat st;
  ssize_t n = get("/home/user/docs/notes.txt", b, sizeof b - 1); b[n > 0 ? n : 0] = 0;
  CHECK(n == 10 && !strncmp(b, "persistent", 10), "file content survived the reboot");
  CHECK(stat("/home/user/docs/notes.txt", &st) == 0 && (st.st_mode & 0777) == 0755, "mode 0755 survived");
  CHECK(readlink("/home/user/rel-link", b, sizeof b) == 14, "relative symlink survived");
  n = get("/home/user/abs-link/notes.txt", b, 10); CHECK(n == 10, "directory symlink still resolves");
  CHECK(access("/home/user/victim", F_OK) < 0 && access("/home/user/tmpdir", F_OK) < 0, "deleted names stayed deleted");
  n = get("/home/user/docs/rel.txt", b, sizeof b - 1); b[n > 0 ? n : 0] = 0; CHECK(!strcmp(b, "relative"), "file written via relative path");
  CHECK(stat("/store/big.bin", &st) == 0 && st.st_size == (1 << 20), "1 MiB file size");
  int fd = open("/store/big.bin", O_RDONLY); unsigned char chunk[4096]; unsigned off = 0; int good = fd >= 0;
  while (good && off < (1u << 20)) { ssize_t r = read(fd, chunk, sizeof chunk); if (r <= 0) { good = 0; break; } for (ssize_t i = 0; i < r; i++) if (chunk[i] != pattern(off + i)) good = 0; off += r; }
  if (fd >= 0) close(fd);
  CHECK(good && off == (1u << 20), "1 MiB pattern intact after reboot");
  CHECK(count_entries("/home/user", 0) == 5, "directory has exactly the expected entries");
  /* cleanup path: remove everything, directories last */
  CHECK(unlink("/home/user/docs/rel.txt") == 0 && unlink("/home/user/docs/notes.txt") == 0 && rmdir("/home/user/docs") == 0, "delete a populated directory bottom-up");
  CHECK(unlink("/home/user/rel-link") == 0 && unlink("/home/user/abs-link") == 0 && unlink("/home/user/loop-a") == 0 && unlink("/home/user/loop-b") == 0 && rmdir("/home/user") == 0 && rmdir("/home") == 0 && unlink("/store/big.bin") == 0, "remove the rest");
  printf(bad ? "PFS-R FAIL %d\n" : "PFS-R OK\n", bad);
}

int main(int argc, char **argv) {
  if (argc > 1 && argv[1][0] == 'r') phase_read(); else phase_write();
  return bad ? 1 : 0;
}
