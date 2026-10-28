#!/usr/bin/env python3
"""End-to-end UI test: boots the ISO in QEMU, injects keyboard/mouse through the QEMU monitor,
takes screendumps and checks pixels + kernel log lines.
usage: tools/ui-test.py <iso> <outdir>   (needs qemu-system-x86_64; Pillow optional for PNG output)"""
import os, re, socket, subprocess, sys, time

ISO, OUT = sys.argv[1], sys.argv[2]
os.makedirs(OUT, exist_ok=True)
SERIAL, SOCK = os.path.join(OUT, "serial.log"), os.path.join(OUT, "mon.sock")
for f in (SERIAL, SOCK):
    if os.path.exists(f):
        os.remove(f)

qemu = subprocess.Popen(["qemu-system-x86_64", "-M", "q35", "-m", "256M", "-cdrom", ISO, "-serial", "file:" + SERIAL,
                         "-display", "none", "-monitor", "unix:%s,server,nowait" % SOCK, "-no-reboot"])
results = []

def check(name, ok, detail=""):
    results.append(ok)
    print(("PASS " if ok else "FAIL ") + name + (("  (" + detail + ")") if detail else ""))

def serial():
    try:
        return re.sub(r"\x1b\[[0-9;]*m", "", open(SERIAL, errors="replace").read())
    except FileNotFoundError:
        return ""

def wait_for(text, timeout=30):
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

def shot(name):
    path = os.path.join(OUT, name + ".ppm")
    cmd("screendump " + path, 0.5)
    return read_ppm(path)

def read_ppm(path):
    d = open(path, "rb").read()
    m = re.match(rb"P6\s+(\d+)\s+(\d+)\s+255\s", d)
    w, h = int(m.group(1)), int(m.group(2))
    return w, h, d[m.end():]

def px(img, x, y):
    w, h, data = img
    i = (y * w + x) * 3
    return tuple(data[i:i + 3])

def save_png(img, name):
    try:
        from PIL import Image
        w, h, data = img
        Image.frombytes("RGB", (w, h), data).save(os.path.join(OUT, name + ".png"))
    except ImportError:
        pass

def near(a, b, tol=6):
    return all(abs(x - y) <= tol for x, y in zip(a, b))

def move(dx, dy):
    # relative motion in chunks the PS/2 protocol can carry
    while dx or dy:
        sx = max(-100, min(100, dx)); sy = max(-100, min(100, dy))
        cmd("mouse_move %d %d" % (sx, sy), 0.06)
        dx -= sx; dy -= sy

try:
    check("kernel reached LAPIC timer", wait_for("LAPIC timer"))
    time.sleep(0.6)
    boot = shot("boot_console")
    w, h = boot[0], boot[1]
    green = sum(1 for y in range(0, 200) for x in range(0, 400) if near(px(boot, x, y), (0x55, 0xFF, 0x7F), 10))
    bright = sum(1 for y in range(0, 200) for x in range(0, 400) if sum(px(boot, x, y)) > 400)
    check("boot log visible on screen", green > 50 and bright > 200, "%dx%d green=%d bright=%d" % (w, h, green, bright))
    save_png(boot, "boot_console")

    check("desktop started", wait_for("[deloxy-de] desktop ready"))
    time.sleep(1.0)
    d1 = shot("desktop1")
    time.sleep(0.7)
    d2 = shot("desktop2")
    save_png(d2, "desktop")
    cx, cy = w // 2, h // 2
    tb_y = h - 40
    check("taskbar drawn (dark panel)", near(px(d2, 5, h - 4), (17, 21, 29)), str(px(d2, 5, h - 4)))
    t = px(d2, 300, 74)
    check("idle title bar is neutral grey", abs(t[0] - t[2]) < 30 and 40 < t[0] < 130, str(t))
    check("cursor drawn at centre", near(px(d2, cx + 1, cy + 2), (255, 255, 255)) and near(px(d2, cx, cy), (0, 0, 0)))
    anim = [(x, y) for y in range(100, 270, 7) for x in range(150, 450, 7)]
    diff = sum(1 for p in anim if px(d1, *p) != px(d2, *p))
    check("animation running (window content changes)", diff > 5, "%d/%d sample pixels changed" % (diff, len(anim)))
    sh_ = px(d2, 300, 60 + 28 + 200 + 5)  # just below the anim window: drop shadow darkens the wallpaper
    wp = px(d2, 300, 60 + 28 + 200 + 30)
    check("window drop shadow is drawn", sum(sh_) < sum(wp) - 6, "%s vs %s" % (sh_, wp))
    icon = sum(1 for yy in range(20, 70) for xx in range(30, 80) if px(d2, xx, yy) != px(d2, 200, 300))
    check("desktop icons drawn", icon > 800, "%d px differ from wallpaper" % icon)
    clk = sum(1 for yy in range(tb_y + 4, h - 4) for xx in range(w - 90, w - 8) if sum(px(d2, xx, yy)) > 450)
    check("taskbar clock text drawn", clk > 40, "%d bright px" % clk)
    time.sleep(3.2)
    log = serial()
    check("diag reads SYS_STAT", re.search(r"\[user pid \d+\] diag: up=\d+s free=\d+ heap=\d+K", log) is not None)

    # keyboard: focused window is the terminal
    for k in ("h", "i"):
        cmd("sendkey " + k, 0.25)
    time.sleep(0.3)
    log = serial()
    check("keyboard events reach compositor", "[deloxy-de] key 'h'" in log and "[deloxy-de] key 'i'" in log)
    cmd("sendkey ret", 0.4)
    for k in ("e", "c", "h", "o", "spc", "o", "k", "ret"):
        cmd("sendkey " + k, 0.25)
    time.sleep(1.0)
    log = serial()
    check("terminal: typed 'hi' reached the shell", "unknown command 'hi'" in log)
    check("terminal: 'echo ok' executed by deloxy-sh", re.search(r"\r?\nok\r?\n", log) is not None)
    d4 = shot("terminal")
    m = re.search(r"'terminal' at \((\d+),(\d+)\)", log)
    tx0, ty0 = (int(m.group(1)), int(m.group(2))) if m else (w - 660, h - 464)
    green = sum(1 for yy in range(ty0 + 28, ty0 + 28 + 384, 2) for xx in range(tx0 + 1, tx0 + 641, 2) if near(px(d4, xx, yy), (200, 230, 200), 20))
    check("terminal window shows shell text on screen", green > 150, "%d bright text pixels" % green)

    def click_at(x, y, settle=0.45):
        move(x - state["x"], y - state["y"]); state["x"], state["y"] = x, y
        time.sleep(0.15)
        cmd("mouse_button 1", 0.2); cmd("mouse_button 0", settle)
    state = {"x": cx, "y": cy}

    # drag 'anim' (window 1 at (140,60), title bar y 61..88): grab at (300,75), move (+120,+90) -> (260,150)
    move(300 - cx, 75 - cy); state["x"], state["y"] = 300, 75
    time.sleep(0.3)
    cmd("mouse_button 1", 0.3)
    move(120, 90); state["x"], state["y"] = 420, 165
    cmd("mouse_button 0", 0.4)
    time.sleep(0.4)
    log = serial()
    check("click hit title bar of 'anim'", re.search(r"click \(300,75\) -> title bar of window 1 'anim'", log) is not None)
    m = re.search(r"window 1 moved to \((-?\d+),(-?\d+)\)", log)
    check("window dragged", m is not None and (int(m.group(1)), int(m.group(2))) == (260, 150), m.group(0) if m else "no move log")
    check("focus followed click", "[deloxy-de] focus -> window 1 'anim'" in log)
    d3 = shot("after_drag")
    save_png(d3, "after_drag")
    t = px(d3, 260 + 100, 150 + 14)
    check("moved title bar is focused (accent blue)", t[2] > t[0] + 40, str(t))
    check("old position is wallpaper again", not near(px(d3, 150, 100), (28, 32, 40), 12) and px(d3, 150, 100)[2] < 90, str(px(d3, 150, 100)))

    # ---- start menu -> Settings
    click_at(50, h - 20)
    log = serial()
    check("start button opens the menu", "-> start button" in log)
    dm = shot("menu"); save_png(dm, "menu")
    check("menu panel drawn", near(px(dm, 30, tb_y - 20), (26, 31, 41), 8), str(px(dm, 30, tb_y - 20)))
    click_at(60, 633)
    time.sleep(0.6)
    log = serial()
    check("menu item launches Settings", "menu -> Settings" in log and re.search(r"window 5 'Settings' at \(180,50\)", log) is not None)

    def settings(name, x, y, expect):
        click_at(181 + x, 78 + y)
        l = serial()
        check("settings: " + name, expect in l, expect)

    settings("accent orange", 249, 91, "theme: theme=dark accent=orange")
    ds = shot("settings_orange"); save_png(ds, "settings_orange")
    t = px(ds, 181 + 100, 52)
    check("settings window title uses the new accent", t[0] > t[2] + 50, str(t))
    settings("wallpaper dusk", 272, 165, "wallpaper=dusk")
    dd = shot("dusk"); save_png(dd, "dusk")
    t = px(dd, 1100, 10)
    check("dusk wallpaper painted", t[2] > t[1] + 20 and t[0] < 90, str(t))
    settings("light theme", 276, 50, "theme=light")
    dl = shot("light"); save_png(dl, "light")
    check("light taskbar", near(px(dl, 5, h - 4), (238, 241, 246), 4), str(px(dl, 5, h - 4)))
    settings("taskbar on top", 276, 220, "taskbar=top")
    dt = shot("top"); save_png(dt, "top")
    check("taskbar moved to the top", near(px(dt, 5, 4), (238, 241, 246), 4) and not near(px(dt, 5, h - 4), (238, 241, 246), 4), "%s / %s" % (px(dt, 5, 4), px(dt, 5, h - 4)))
    settings("square corners", 170, 256, "corners=square")
    settings("reset to defaults", 386, 473, "theme=dark accent=blue wallpaper=midnight taskbar=bottom corners=round clock=24")
    dr = shot("reset")
    check("defaults restored (dark taskbar at the bottom)", near(px(dr, 5, h - 4), (17, 21, 29)), str(px(dr, 5, h - 4)))

    # ---- v3 customization: dock, glass, flat titles, shadows
    RESET = "wallpaper=midnight taskbar=bottom corners=round clock=24 panel=bar glass=off titles=gradient shadows=soft"
    settings("wallpaper dusk again", 272, 165, "wallpaper=dusk")
    settings("panel dock", 276, 328, "panel=dock")
    dk = shot("dock"); save_png(dk, "dock")
    check("dock floats above the screen edge", not near(px(dk, 5, h - 4), (17, 21, 29), 20) and near(px(dk, 1000, h - 28), (17, 21, 29), 6), "%s / %s" % (px(dk, 5, h - 4), px(dk, 1000, h - 28)))
    settings("glass panel", 276, 364, "glass=on")
    dg = shot("glass"); save_png(dg, "glass")
    t = px(dg, 1000, h - 28)
    check("glass panel blends with the wallpaper behind it", t[0] > 40 and t != (17, 21, 29), str(t))
    settings("flat titles", 276, 400, "titles=flat")
    df = shot("flat")
    a, b = px(df, 181 + 100, 50 + 5), px(df, 181 + 100, 50 + 24)
    check("flat title bar is one colour", a == b, "%s vs %s" % (a, b))
    settings("shadows off", 170, 436, "shadows=off")
    check("shadows option applied", "shadows=off" in serial())
    click_at(181 + 386, 78 + 473)
    check("second reset restores v3 defaults", serial().count(RESET) >= 2)

    # ---- close Settings, then minimize / restore / desktop icon
    click_at(604, 64)
    time.sleep(0.4)
    check("Settings close box closes the window", "window 5 'Settings' closed" in serial())
    click_at(538, 164)
    log = serial()
    check("minimize box hides the window", "window 1 'anim' minimized" in log)
    dmn = shot("minimized")
    check("minimized window is gone from the screen", px(dmn, 400, 200)[2] < 90 and not near(px(dmn, 400, 200), (28, 32, 40), 10), str(px(dmn, 400, 200)))
    click_at(180, h - 20)
    log = serial()
    check("taskbar button restores it", log.count("[deloxy-de] focus -> window 1 'anim'") >= 2)
    click_at(56, 320)
    log = serial()
    check("desktop icon launches / focuses Monitor", "desktop icon Monitor" in log and "launch 'diag'" in log)

    # ---- Files app
    click_at(50, h - 20)
    click_at(60, 483)
    time.sleep(0.5)
    log = serial()
    check("menu launches Files", "menu -> Files" in log and re.search(r"window 6 'Files' at \(188,78\)", log) is not None)
    names = {}
    for i in range(10):
        click_at(300, 175 + 22 * i, 0.3)
        m = re.findall(r"files: select '([^']+)'", serial())
        names[i] = m[-1] if m else None
    check("Files lists the initramfs", "sample-wall.ppm" in names.values() and "README.txt" in names.values() and "hello_win.exe" in names.values(), str(names))
    dfi = shot("files"); save_png(dfi, "files")
    def files_open(name):
        row = [i for i, n in names.items() if n == name][0]
        click_at(300, 175 + 22 * row, 0.3)
        click_at(229, 124, 0.6)
    files_open("README.txt")
    log = serial()
    check("Files opens a text file in the viewer", "files: open 'README.txt'" in log and re.search(r"window \d+ 'Viewer - README.txt'", log) is not None)
    dv = shot("viewer"); save_png(dv, "viewer")
    cmd("sendkey alt-f4", 0.6)
    log = serial()
    check("alt-f4 closes the focused window", "alt-f4 -> window" in log and "'Viewer - README.txt' closed" in log)
    files_open("sample-wall.ppm")
    log = serial()
    check("Files sets a PPM as the wallpaper", "wallpaper loaded from sample-wall.ppm (128x80)" in log)
    dw = shot("custom_wall"); save_png(dw, "custom_wall")
    t = px(dw, 1100, 20)
    check("custom wallpaper is painted", t[2] > 110 and t[2] > t[1] + 40, str(t))
    files_open("hello_win.exe")
    check("Files runs a program", "files: started 'hello_win.exe'" in serial())

    # ---- Task Manager: end a process, toast, then the right-click context menu
    click_at(56, 230)
    time.sleep(0.5)
    log = serial()
    check("desktop icon launches the Task Manager", "desktop icon Tasks" in log and re.search(r"window \d+ 'Task Manager' at", log) is not None)
    tnames = {}
    for i in range(8):
        click_at(300, 203 + 22 * i, 0.3)
        m = re.findall(r"tasks: select '([^']+)' \(pid (\d+)\)", serial())
        tnames[i] = m[-1][0] if m else None
    check("Task Manager lists processes (shell, desktop apps, programs)", "deloxy-sh" in tnames.values() and "anim" in tnames.values(), str(tnames))
    dt = shot("tasks"); save_png(dt, "tasks")
    row = [i for i, n in tnames.items() if n == "anim"][0]
    click_at(300, 203 + 22 * row, 0.3)
    click_at(287, 152, 0.8)
    log = serial()
    check("End process terminates the selected program", "tasks: ended 'anim'" in log and "window 1 'anim' closed" in log)
    check("a toast notification is raised", "notify: Ended anim" in log)
    dtoast = shot("toast"); save_png(dtoast, "toast")
    check("toast is drawn top-right with the accent bar", near(px(dtoast, 967, 30), (52, 101, 196), 24), str(px(dtoast, 967, 30)))
    # protected process
    shrow = [i for i, n in tnames.items() if n == "deloxy-sh"][0]
    click_at(300, 203 + 22 * shrow, 0.3)
    click_at(287, 152, 0.5)
    check("the shell cannot be ended from the Task Manager", "tasks: ended 'deloxy-sh'" not in serial())
    state["x"], state["y"] = state["x"], state["y"]
    move(120 - state["x"], 600 - state["y"]); state["x"], state["y"] = 120, 600
    time.sleep(0.3)
    cmd("mouse_button 2", 0.3); cmd("mouse_button 0", 0.4)
    check("right click opens the desktop context menu", "right click (120,600) -> context menu" in serial())
    dctx = shot("ctx"); save_png(dctx, "ctx")
    check("context menu is drawn", near(px(dctx, 300, 640), (26, 31, 41), 10), str(px(dctx, 300, 640)))
    click_at(200, 741, 0.8)
    log = serial()
    check("context menu item changes the wallpaper", "ctx -> Next wallpaper" in log and "wallpaper=aurora" in log)

    # ---- Permissions manager (rules created from the shell, managed in the GUI)
    KEYS = {" ": "spc", ".": "dot", ":": "shift-semicolon", "-": "minus", "_": "shift-minus"}
    def type_line(txt, wait=0.7):
        for ch in txt:
            cmd("sendkey " + KEYS.get(ch, ch), 0.08)
        cmd("sendkey ret", wait)
    cmd("sendkey ctrl-alt-t", 0.8)
    type_line("perms allow hello_linux.elf rw")
    type_line("perms net win_net.exe 10.0.2.2:8777 deny")
    log = serial()
    check("shell records permission decisions", "hello_linux.elf: file access set to rw" in log and "win_net.exe: connections denied to 10.0.2.2:8777" in log)
    click_at(50, h - 20)
    click_at(60, 663)
    time.sleep(0.6)
    log = serial()
    m = re.search(r"window \d+ 'Permissions' at \((-?\d+),(-?\d+)\)", log)
    check("menu launches the Permissions manager", "menu -> Permissions" in log and m is not None)
    pox, poy = (int(m.group(1)) + 1, int(m.group(2)) + 28) if m else (0, 0)
    pnames = {}
    for i in range(2):
        click_at(pox + 300, poy + 58 + 22 * i + 11, 0.3)
        mm = re.findall(r"perms: select '([^']+)' \((files|net)\)", serial())
        pnames[i] = mm[-1] if mm else None
    check("Permissions lists both rules (files and network)", ("hello_linux.elf", "files") in pnames.values() and ("win_net.exe", "net") in pnames.values(), str(pnames))
    dp = shot("perms"); save_png(dp, "perms")
    nrow = [i for i, n in pnames.items() if n == ("win_net.exe", "net")][0]
    click_at(pox + 300, poy + 58 + 22 * nrow + 11, 0.3)
    click_at(pox + 116, poy + 18, 0.6)
    log = serial()
    check("Allow flips a network rule", "perms: set 'win_net.exe' net 10.0.2.2:8777 allow" in log)
    click_at(pox + 252, poy + 18, 0.6)
    check("Full turns the rule into full access (any host, no limits)", "perms: full access for 'win_net.exe'" in serial())
    dpf = shot("perms_full"); save_png(dpf, "perms_full")
    nrow2 = None
    for i in range(2):
        click_at(pox + 300, poy + 58 + 22 * i + 11, 0.3)
        mm = re.findall(r"perms: select '([^']+)' \((files|net)\)", serial())
        if mm and mm[-1] == ("win_net.exe", "net"):
            nrow2 = i
            break
    check("the full-access rule is listed as a network rule", nrow2 is not None)
    click_at(pox + 325, poy + 18, 0.6)
    check("Limits cycles the preset (unlimited -> 1 h / 1 GiB)", "perms: limits for 'win_net.exe' 3600s 1048576 KiB" in serial())
    frow = [i for i, n in pnames.items() if n == ("hello_linux.elf", "files")][0]
    click_at(pox + 300, poy + 58 + 22 * frow + 11, 0.3)
    click_at(pox + 43, poy + 18, 0.6)
    check("Revoke removes a file rule", "perms: revoked 'hello_linux.elf'" in serial())
    cmd("sendkey ctrl-alt-t", 0.8)
    n0 = len(serial())
    type_line("perms")
    tail = serial()[n0:]
    check("the shell sees the changes (network rule now full access with limits, file rule gone)", "net ANY HOST limit: 3600 s, 1048576 KiB ALLOWED" in tail and "hello_linux.elf" not in tail, tail[-300:])

    # ---- calendar popup
    click_at(w - 44, h - 20)
    check("clock click opens the calendar", "-> clock (calendar)" in serial())
    dc = shot("calendar"); save_png(dc, "calendar")
    acc = sum(1 for yy in range(508, 750, 2) for xx in range(1044, 1276, 2) if near(px(dc, xx, yy), (52, 101, 196), 14))
    check("calendar highlights today", acc > 20 and near(px(dc, 1058, 530), (26, 31, 41), 10), "%d accent px, bg %s" % (acc, px(dc, 1058, 530)))
    cmd("sendkey esc", 0.5)
    dc2 = shot("calendar_closed")
    check("escape closes the calendar", not near(px(dc2, 1058, 530), (26, 31, 41), 6), str(px(dc2, 1058, 530)))

    # ---- keyboard shortcuts
    cmd("sendkey alt-tab", 0.6)
    check("alt-tab cycles windows", "alt-tab -> window" in serial())
    cmd("sendkey meta_l", 0.6)
    check("super opens the start menu", "super -> start menu" in serial())
    cmd("sendkey esc", 0.5)
    cmd("sendkey ctrl-alt-t", 0.6)
    check("ctrl-alt-t opens the terminal", "shortcut ctrl-alt-t -> terminal" in serial())
    log = serial()
    check("no kernel panic/fault", "PANIC" not in log and "EXCEPTION" not in log)
finally:
    qemu.kill()
print("\n%d/%d checks passed" % (sum(results), len(results)))
sys.exit(0 if all(results) else 1)
