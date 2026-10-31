#!/usr/bin/env python3
"""Files app folder browsing: boots the ISO with a store disk that already contains
/home/note.txt, /home/docs/deep.txt and top.txt, then navigates, creates and deletes folders with the mouse/keyboard.
usage: tools/files-test.py <iso> <disk.img> <outdir>   (prepare the disk with runone.py: format, mkdir /home, mkdir /home/docs, save ...)"""
import os, re, socket, subprocess, sys, time

ISO, DISK, OUT = sys.argv[1], sys.argv[2], sys.argv[3]
os.makedirs(OUT, exist_ok=True)
SERIAL, SOCK = os.path.join(OUT, "serial.log"), os.path.join(OUT, "mon.sock")
for f in (SERIAL, SOCK):
    if os.path.exists(f):
        os.remove(f)
qemu = subprocess.Popen(["qemu-system-x86_64", "-M", "q35", "-m", "256M", "-cdrom", ISO, "-serial", "file:" + SERIAL,
                         "-display", "none", "-monitor", "unix:%s,server,nowait" % SOCK, "-no-reboot",
                         "-drive", "file=%s,if=none,id=d0,format=raw" % DISK, "-device", "virtio-blk-pci,drive=d0"])
results = []

def check(name, ok, detail=""):
    results.append(ok)
    print(("PASS " if ok else "FAIL ") + name + ((" (" + detail + ")") if detail else ""))

def serial():
    try:
        return re.sub(r"\x1b\[[0-9;]*m", "", open(SERIAL, errors="replace").read())
    except FileNotFoundError:
        return ""

def wait_for(text, timeout=40):
    t0 = time.time()
    while time.time() - t0 < timeout:
        if text in serial():
            return True
        time.sleep(0.1)
    return False

for _ in range(100):
    if os.path.exists(SOCK):
        break
    time.sleep(0.1)
mon = socket.socket(socket.AF_UNIX)
mon.connect(SOCK)
mon.settimeout(2)
time.sleep(0.3)
try:
    mon.recv(4096)
except Exception:
    pass

def cmd(c, wait=0.15):
    mon.sendall((c + "\n").encode())
    time.sleep(wait)
    try:
        mon.recv(65536)
    except Exception:
        pass

def move(dx, dy):
    while dx or dy:
        sx = max(-100, min(100, dx)); sy = max(-100, min(100, dy))
        cmd("mouse_move %d %d" % (sx, sy), 0.06)
        dx -= sx; dy -= sy

state = {"x": 640, "y": 400}
def click_at(x, y, settle=0.45):
    move(x - state["x"], y - state["y"]); state["x"], state["y"] = x, y
    time.sleep(0.15)
    cmd("mouse_button 1", 0.2); cmd("mouse_button 0", settle)

# Files window content origin on screen = window position + (1 border, 28 title bar); set once the window exists
OX, OY = 0, 0
def row(i): return (OX + 111, OY + 58 + 22 * i + 11)
def OPEN(): return (OX + 40, OY + 18)
def DELETE(): return (OX + 112, OY + 18)
def NEWDIR(): return (OX + 284, OY + 18)
def last(pat):
    m = re.findall(pat, serial())
    return m[-1] if m else None
def select(i, expect):
    click_at(*row(i), 0.35)
    got = last(r"files: select '([^']*)'")
    return got == expect

try:
    check("desktop started", wait_for("[deloxy-de] desktop ready"))
    time.sleep(1.0)
    check("store mounted", "store" in serial().lower())
    click_at(50, 780)          # start button
    click_at(60, 483)          # Files entry
    time.sleep(0.5)
    m = re.search(r"window \d+ 'Files' at \((\d+),(\d+)\)", serial())
    check("Files window opened", m is not None)
    if m:
        OX, OY = int(m.group(1)) + 1, int(m.group(2)) + 28

    # top level: the folder comes first
    check("top level lists the folder first", select(0, "home"))
    click_at(*OPEN(), 0.6)
    check("Open enters a folder", "files: cd '/home'" in serial())
    check("folder shows '..' first", select(0, ".."))
    check("folder lists its sub-folder", select(1, "docs"))
    check("folder lists its file", select(2, "note.txt"))
    click_at(*OPEN(), 0.7)
    check("file inside a folder opens in the viewer", re.search(r"window \d+ 'Viewer - note.txt'", serial()) is not None)
    cmd("sendkey alt-f4", 0.6)
    check("viewer closes", "'Viewer - note.txt' closed" in serial())

    # into docs, then double-click the file's folder entry flow
    check("select docs", select(1, "docs"))
    click_at(*OPEN(), 0.6)
    check("enter /home/docs", "files: cd '/home/docs'" in serial())
    check("deep file listed", select(1, "deep.txt"))

    # create a folder, it must appear and be persisted
    click_at(*NEWDIR(), 0.8)
    check("New folder creates one", "files: mkdir '/home/docs/folder'" in serial())
    check("new folder is listed (folders before files)", select(1, "folder"))

    # delete it again
    click_at(*DELETE(), 0.8)
    check("Delete removes an empty folder", "files: deleted 'folder'" in serial())

    # '..' goes up, Backspace goes up again
    check("select '..'", select(0, ".."))
    click_at(*OPEN(), 0.6)
    check("'..' row goes to the parent", serial().count("files: cd '/home'") >= 2)
    cmd("sendkey backspace", 0.6)
    check("Backspace goes up to the top level", "files: cd '/'" in serial())

    # non-empty folder cannot be deleted
    check("top level again, folder first", select(0, "home"))
    click_at(*OPEN(), 0.5)
    check("back in /home", serial().count("files: cd '/home'") >= 3)
    check("select docs again", select(1, "docs"))
    click_at(*DELETE(), 0.7)
    check("a non-empty folder is NOT deleted", "files: deleted 'docs'" not in serial())

    # system files stay read-only at the top level
    cmd("sendkey backspace", 0.6)
    click_at(*row(1), 0.35)
    click_at(*DELETE(), 0.6)
    check("system files cannot be deleted", "files: deleted" not in serial().split("files: deleted 'folder'")[-1])
    log = serial()
    check("no kernel panic/fault", "PANIC" not in log and "EXCEPTION" not in log)
finally:
    qemu.kill()
print("\n%d/%d checks passed" % (sum(results), len(results)))
sys.exit(0 if all(results) else 1)
