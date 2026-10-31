/* Win32 view of the persistent tree: C:\home\... is the same store as /home/... for Linux programs and the shell. */
#include <windows.h>
#include <stdio.h>
static int bad = 0;
#define CHECK(c, n) do { if (c) printf("ok   %s\n", n); else { printf("FAIL %s (err %lu)\n", n, GetLastError()); bad++; } } while (0)
static int put(const char *p, const char *t) { HANDLE h = CreateFileA(p, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL); if (h == INVALID_HANDLE_VALUE) return 0; DWORD w; BOOL ok = WriteFile(h, t, lstrlenA(t), &w, NULL); CloseHandle(h); return ok && w == (DWORD)lstrlenA(t); }
int main(void) {
  setvbuf(stdout, NULL, _IONBF, 0);
  CHECK(CreateDirectoryA("C:\\srv", NULL) || GetLastError() == ERROR_ALREADY_EXISTS, "CreateDirectory C:\\srv");
  CHECK(CreateDirectoryA("C:\\srv\\winw", NULL), "CreateDirectory nested");
  CHECK(!CreateDirectoryA("C:\\srv\\winw", NULL) && GetLastError() == ERROR_ALREADY_EXISTS, "CreateDirectory again -> ERROR_ALREADY_EXISTS");
  CHECK(!CreateDirectoryA("C:\\srv\\nope\\x", NULL) && GetLastError() == ERROR_PATH_NOT_FOUND, "CreateDirectory missing parent -> ERROR_PATH_NOT_FOUND");
  CHECK(put("C:\\srv\\winw\\a.txt", "windows wrote this"), "CreateFile + WriteFile in a persistent folder");
  CHECK(put("C:\\srv\\winw\\b.txt", "second"), "second file");
  CHECK((GetFileAttributesA("C:\\srv\\winw") & FILE_ATTRIBUTE_DIRECTORY) != 0, "GetFileAttributes: directory");
  CHECK(GetFileAttributesA("C:\\srv\\winw\\a.txt") != INVALID_FILE_ATTRIBUTES && !(GetFileAttributesA("C:\\srv\\winw\\a.txt") & FILE_ATTRIBUTE_DIRECTORY), "GetFileAttributes: file");
  WIN32_FIND_DATAA fd; int n = 0; HANDLE f = FindFirstFileA("C:\\srv\\winw\\*", &fd);
  if (f != INVALID_HANDLE_VALUE) { do { if (strcmp(fd.cFileName, ".") && strcmp(fd.cFileName, "..")) n++; } while (FindNextFileA(f, &fd)); FindClose(f); }
  CHECK(n == 2, "FindFirstFile lists the folder");
  CHECK(MoveFileA("C:\\srv\\winw\\b.txt", "C:\\srv\\winw\\c.txt") && GetFileAttributesA("C:\\srv\\winw\\b.txt") == INVALID_FILE_ATTRIBUTES, "MoveFile within the persistent tree");
  CHECK(!RemoveDirectoryA("C:\\srv\\winw") && GetLastError() == ERROR_DIR_NOT_EMPTY, "RemoveDirectory non-empty -> ERROR_DIR_NOT_EMPTY");
  CHECK(DeleteFileA("C:\\srv\\winw\\b.txt") == 0, "DeleteFile of the moved-away name fails");
  CHECK(DeleteFileA("C:\\srv\\winw\\c.txt"), "DeleteFile");
  printf(bad ? "WIN-PFS FAIL %d\n" : "WIN-PFS OK\n", bad);
  return bad;   /* leaves C:\home\winw\a.txt behind: the second boot checks it */
}
