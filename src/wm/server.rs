//! deloxy-de - the Deloxy desktop environment: compositor + window management + taskbar.
//! Owns the framebuffer, composites client surfaces with
//! damage tracking, draws window decorations + taskbar + cursor, and routes input.
//!
//! Alpha: runs as a kernel thread; clients are ring-3 processes that talk to it only
//! through `deloxy-wm-protocol` channels and shared pixel buffers, so it can move to
//! user space without client changes. Window management policy (move/focus/raise) is
//! built in; a separate WM client is post-alpha.
//! Client programs of the desktop live in `user/de` (package `deloxy-de-apps`).

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;

use crate::cap::{CapObject, Rights};
use crate::drivers::fb::{self, FbInfo};
use crate::drivers::input::{self, InputEvent, EV_KEY, EV_MOUSE_ABS, EV_MOUSE_BUTTON, EV_MOUSE_MOVE};
use crate::gfx::draw::{mix, rgb, Rect, Surface};
use crate::ipc::memobj::MemObject;
use crate::ipc::ring::Spsc;
use crate::mm::layout::PAGE_SIZE;
use crate::mm::vmm;
use crate::task::{self, blobs, InitSpec, Process};
use crate::wm::proto::*;
use crate::wm::theme::{self, Palette, Theme};

type WmRing = Spsc<WmMsg, 32>;


const ARROW: [&str; 16] = [
    "X               ",
    "XX              ",
    "X.X             ",
    "X..X            ",
    "X...X           ",
    "X....X          ",
    "X.....X         ",
    "X......X        ",
    "X.......X       ",
    "X........X      ",
    "X.....XXXXX     ",
    "X..X..X         ",
    "X.X X..X        ",
    "XX  X..X        ",
    "X    X..X       ",
    "     XXX        ",
];


const TERM_COLS: usize = 80;
const TERM_ROWS: usize = 24;
const COL_TERM_BG: u32 = rgb(12, 14, 18);
const COL_TERM_FG: u32 = rgb(200, 230, 200);

/// Character grid of the terminal window.
struct Term {
    grid: Vec<u8>, // TERM_ROWS * TERM_COLS
    row: usize,
    col: usize,
    pos: u64, // absolute TTY output position consumed so far
    dirty: bool,
}

impl Term {
    fn new() -> Term {
        Term { grid: vec![b' '; TERM_COLS * TERM_ROWS], row: 0, col: 0, pos: 0, dirty: true }
    }
    fn newline(&mut self) {
        self.col = 0;
        if self.row + 1 < TERM_ROWS {
            self.row += 1;
        } else {
            self.grid.copy_within(TERM_COLS.., 0);
            let n = self.grid.len();
            self.grid[n - TERM_COLS..].fill(b' ');
        }
    }
    fn feed(&mut self, bytes: &[u8]) {
        for &b in bytes {
            match b {
                b'\n' => self.newline(),
                b'\r' => self.col = 0,
                0x08 => self.col = self.col.saturating_sub(1),
                0x20..=0x7E => {
                    if self.col >= TERM_COLS {
                        self.newline();
                    }
                    self.grid[self.row * TERM_COLS + self.col] = b;
                    self.col += 1;
                }
                _ => {}
            }
        }
        self.dirty = true;
    }
}


const TITLE_H: i32 = 28;
const BORDER: i32 = 1;
const TASKBAR_H: i32 = 40;
const BTN_W: i32 = 22;
const BTN_H: i32 = 19;
const TASK_BTN_W: i32 = 148;
const TASK_BTN_STEP: i32 = 154;
const TASK_BTN_X0: i32 = 112;
const MENU_W: i32 = 232;
const ICON_CELL_W: i32 = 84;
const ICON_CELL_H: i32 = 88;

const MONTHS: [&str; 12] = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Kind {
    Client,
    Terminal,
    Settings,
    Files,
    Viewer,
    Tasks,
    Perms,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Hover {
    None,
    Start,
    Task(u32),
    Menu(usize),
    Icon(usize),
    Ctx(usize),
}

/// Launchable things (start menu and desktop icons).
#[derive(Clone, Copy, PartialEq, Eq)]
enum Launch {
    Terminal,
    Files,
    Tasks,
    Monitor,
    Anim,
    Bars,
    Settings,
    Perms,
    Restart,
    Shutdown,
}

const MENU: [(Option<Launch>, &str); 11] = [
    (Some(Launch::Terminal), "Terminal"),
    (Some(Launch::Files), "Files"),
    (Some(Launch::Tasks), "Task Manager"),
    (Some(Launch::Monitor), "Activity Monitor"),
    (Some(Launch::Anim), "Animation Demo"),
    (Some(Launch::Bars), "Colour Bars"),
    (Some(Launch::Settings), "Settings"),
    (Some(Launch::Perms), "Permissions"),
    (None, ""),
    (Some(Launch::Restart), "Restart"),
    (Some(Launch::Shutdown), "Shut down"),
];
const ICONS: [(Launch, &str); 5] = [(Launch::Terminal, "Terminal"), (Launch::Files, "Files"), (Launch::Tasks, "Tasks"), (Launch::Monitor, "Monitor"), (Launch::Settings, "Settings")];

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Act {
    Dark(bool),
    Accent(usize),
    Wall(u8),
    Top(bool),
    Round(bool),
    Clock12(bool),
    Dock(bool),
    Glass(bool),
    Flat(bool),
    Shadow(u8),
    Reset,
}

#[derive(Clone, Copy)]
enum Look {
    Toggle(&'static str),
    Swatch(u32),
    Thumb(u8),
}

struct Item {
    rect: Rect,
    act: Act,
    look: Look,
    selected: bool,
}

const CTX_ITEMS: [&str; 5] = ["Open Terminal", "Open Files", "Task Manager", "Settings", "Next wallpaper"];
const TASKS_W: i32 = 500;
const TASKS_H: i32 = 340;
const TASK_ROWS: usize = 11;

const SET_W: i32 = 440;
const SET_H: i32 = 500;

/// Layout of the Settings window content; used for both drawing and hit-testing.
fn settings_layout(t: &Theme) -> Vec<Item> {
    let mut v = Vec::new();
    let tog = |v: &mut Vec<Item>, x: i32, y: i32, label: &'static str, act: Act, sel: bool| {
        v.push(Item { rect: Rect::new(x, y, 100, 28), act, look: Look::Toggle(label), selected: sel });
    };
    tog(&mut v, 120, 36, "Dark", Act::Dark(true), t.dark);
    tog(&mut v, 226, 36, "Light", Act::Dark(false), !t.dark);
    for (i, (_, c)) in theme::ACCENTS.iter().enumerate() {
        v.push(Item { rect: Rect::new(120 + i as i32 * 38, 76, 30, 30), act: Act::Accent(i), look: Look::Swatch(*c), selected: t.accent == *c });
    }
    for i in 0..4u8 {
        v.push(Item { rect: Rect::new(16 + i as i32 * 104, 138, 96, 54), act: Act::Wall(i), look: Look::Thumb(i), selected: t.wallpaper == i && t.wall_file_str().is_empty() });
    }
    tog(&mut v, 120, 206, "Bottom", Act::Top(false), !t.taskbar_top);
    tog(&mut v, 226, 206, "Top", Act::Top(true), t.taskbar_top);
    tog(&mut v, 120, 242, "Square", Act::Round(false), !t.round);
    tog(&mut v, 226, 242, "Rounded", Act::Round(true), t.round);
    tog(&mut v, 120, 278, "24-hour", Act::Clock12(false), !t.clock12);
    tog(&mut v, 226, 278, "12-hour", Act::Clock12(true), t.clock12);
    tog(&mut v, 120, 314, "Bar", Act::Dock(false), !t.dock);
    tog(&mut v, 226, 314, "Dock", Act::Dock(true), t.dock);
    tog(&mut v, 120, 350, "Solid", Act::Glass(false), !t.glass);
    tog(&mut v, 226, 350, "Glass", Act::Glass(true), t.glass);
    tog(&mut v, 120, 386, "Gradient", Act::Flat(false), !t.flat_titles);
    tog(&mut v, 226, 386, "Flat", Act::Flat(true), t.flat_titles);
    tog(&mut v, 120, 422, "Off", Act::Shadow(0), t.shadow == 0);
    tog(&mut v, 226, 422, "Soft", Act::Shadow(1), t.shadow == 1);
    tog(&mut v, 332, 422, "Strong", Act::Shadow(2), t.shadow == 2);
    v.push(Item { rect: Rect::new(SET_W - 96, SET_H - 40, 84, 26), act: Act::Reset, look: Look::Toggle("Reset"), selected: false });
    v
}

struct Window {
    id: u32,
    key: &'static str,
    kind: Kind,
    title: String,
    proc: Arc<Process>,
    x: i32,
    y: i32,
    w: i32,
    h: i32,
    buf: *mut u32, // kernel view of the client's shared pixel buffer
    _bufmem: Arc<MemObject>,
    _chanmem: Arc<MemObject>,
    rx: &'static WmRing, // client -> compositor
    tx: &'static WmRing, // compositor -> client
    focused: bool,
    minimized: bool,
    closing: bool,
    /// Built-in terminal (shows the kernel TTY, feeds keystrokes to it); has no client process.
    term: Option<Term>,
}

#[derive(Clone)]
struct FEntry {
    name: String,
    size: u64,
    store: bool,
}

struct FilesState {
    entries: Vec<FEntry>,
    sel: Option<usize>,
    scroll: usize,
    last_click: (usize, u64),
    status: String,
    gen: u64,
}

#[derive(Clone)]
struct TRow {
    pid: u64,
    name: String,
    thr: u32,
    mem_kib: u32,
    abi: &'static str,
}

struct TasksState {
    rows: Vec<TRow>,
    sel: Option<u64>, // selected pid
    status: String,
}

#[derive(Clone)]
struct PRow {
    name: String,
    net: Option<crate::perm::NetRule>,
    read: bool,
    write: bool,
}

struct PermsState {
    rows: Vec<PRow>,
    sel: Option<usize>,
    status: String,
}

const PERMS_W: i32 = 560;
const PERMS_H: i32 = 340;
const PERM_ROWS: usize = 11;

struct ViewerState {
    title: String,
    lines: Vec<String>,
    scroll: usize,
}

const FILES_W: i32 = 480;
const FILES_H: i32 = 340;
const FILE_ROWS: usize = 11;
const VIEW_W: i32 = 520;
const VIEW_H: i32 = 340;
const VIEW_ROWS: usize = 19;

fn files_open_btn() -> Rect {
    Rect::new(8, 6, 64, 24)
}
fn files_del_btn() -> Rect {
    Rect::new(80, 6, 64, 24)
}
fn files_refresh_btn() -> Rect {
    Rect::new(152, 6, 76, 24)
}
fn files_up_btn() -> Rect {
    Rect::new(452, 58, 20, 20)
}
fn files_down_btn() -> Rect {
    Rect::new(452, 58 + FILE_ROWS as i32 * 22 - 20, 20, 20)
}
fn files_row_rect(i: usize) -> Rect {
    Rect::new(8, 58 + i as i32 * 22, 440, 22)
}

impl Window {
    fn outer(&self) -> Rect {
        Rect::new(self.x, self.y, self.w + 2 * BORDER, self.h + TITLE_H + BORDER)
    }
    fn content(&self) -> Rect {
        Rect::new(self.x + BORDER, self.y + TITLE_H, self.w, self.h)
    }
    fn title_bar(&self) -> Rect {
        Rect::new(self.x + BORDER, self.y + BORDER, self.w, TITLE_H - BORDER)
    }
    fn close_box(&self) -> Rect {
        Rect::new(self.x + BORDER + self.w - BTN_W - 6, self.y + 5, BTN_W, BTN_H)
    }
    fn min_box(&self) -> Rect {
        let c = self.close_box();
        Rect::new(c.x - BTN_W - 4, c.y, BTN_W, BTN_H)
    }
    fn send(&self, m: WmMsg) {
        let _ = self.tx.try_push(m); // lossy: a slow client just misses events
    }
}

struct Server {
    fb: FbInfo,
    sw: i32,
    sh: i32,
    back: Vec<u32>,
    wall: Vec<u32>,
    wall_kind: u8,
    theme: Theme,
    pal: Palette,
    windows: Vec<Window>, // bottom -> top
    next_id: u32,
    cx: i32,
    cy: i32,
    buttons: u8,
    drag: Option<(u32, i32, i32)>, // window id, grab offset
    damage: Rect,
    last_clock_sec: u64,
    menu_open: bool,
    hover: Hover,
    cascade: i32,
    store_gen: u64,
    persist_note: &'static str,
    wall_file: [u8; 32],
    wall_note: &'static str,
    cal_open: bool,
    files: FilesState,
    viewer: ViewerState,
    tasks: TasksState,
    perms: PermsState,
    toasts: Vec<(String, u64)>,
    ctx: Option<(i32, i32)>,
}

fn draw_glyph_scaled(s: &mut Surface, x: i32, y: i32, ch: u8, scale: i32, color: u32) {
    use crate::gfx::font::{FONT8X16, GLYPH_W};
    if !(32..=126).contains(&ch) {
        return;
    }
    for (row, bits) in FONT8X16[(ch - 32) as usize].iter().enumerate() {
        for col in 0..GLYPH_W as i32 {
            if bits & (0x80 >> col) != 0 {
                s.fill_rect(Rect::new(x + col * scale, y + row as i32 * scale, scale, scale), color);
            }
        }
    }
}

impl Server {
    fn new(fb: FbInfo) -> Server {
        let (sw, sh) = (fb.width as i32, fb.height as i32);
        let theme = Theme::default();
        let mut s = Server {
            fb,
            sw,
            sh,
            back: vec![0u32; (sw * sh) as usize],
            wall: Vec::new(),
            wall_kind: 255,
            theme,
            pal: theme.palette(),
            windows: Vec::new(),
            next_id: 1,
            cx: sw / 2,
            cy: sh / 2,
            buttons: 0,
            drag: None,
            damage: Rect::new(0, 0, sw, sh),
            last_clock_sec: u64::MAX,
            menu_open: false,
            hover: Hover::None,
            cascade: 0,
            store_gen: 0,
            persist_note: "",
            wall_file: [0; 32],
            wall_note: "",
            cal_open: false,
            files: FilesState { entries: Vec::new(), sel: None, scroll: 0, last_click: (usize::MAX, 0), status: String::new(), gen: 0 },
            viewer: ViewerState { title: String::new(), lines: Vec::new(), scroll: 0 },
            tasks: TasksState { rows: Vec::new(), sel: None, status: String::new() },
            perms: PermsState { rows: Vec::new(), sel: None, status: String::new() },
            toasts: Vec::new(),
            ctx: None,
        };
        s.rebuild_wallpaper();
        s
    }

    fn screen(&self) -> Rect {
        Rect::new(0, 0, self.sw, self.sh)
    }

    fn add_damage(&mut self, r: Rect) {
        let r = r.intersect(&self.screen());
        self.damage = self.damage.union(&r);
    }

    fn cursor_rect(&self) -> Rect {
        Rect::new(self.cx, self.cy, 16, 16)
    }

    fn panel_margin(&self) -> i32 {
        if self.theme.dock { 8 } else { 0 }
    }

    /// The visible panel (full-width bar, or a floating dock inset by the margin).
    fn taskbar_rect(&self) -> Rect {
        let m = self.panel_margin();
        Rect::new(m, if self.theme.taskbar_top { m } else { self.sh - TASKBAR_H - m }, self.sw - 2 * m, TASKBAR_H)
    }

    /// Vertical extent usable by windows (between the panel and the opposite screen edge).
    fn work_y(&self) -> (i32, i32) {
        let r = TASKBAR_H + 2 * self.panel_margin();
        if self.theme.taskbar_top { (r, self.sh) } else { (0, self.sh - r) }
    }

    fn start_rect(&self) -> Rect {
        let tb = self.taskbar_rect();
        Rect::new(tb.x + 6, tb.y + 5, 96, TASKBAR_H - 10)
    }

    fn task_btn_rect(&self, idx: usize) -> Rect {
        let tb = self.taskbar_rect();
        Rect::new(tb.x + TASK_BTN_X0 + idx as i32 * TASK_BTN_STEP, tb.y + 5, TASK_BTN_W, TASKBAR_H - 10)
    }

    fn task_order(&self) -> Vec<u32> {
        let mut ids: Vec<u32> = self.windows.iter().map(|w| w.id).collect();
        ids.sort_unstable();
        ids
    }

    fn clock_rect(&self) -> Rect {
        let tb = self.taskbar_rect();
        Rect::new(tb.right() - 84, tb.y + 2, 80, TASKBAR_H - 4)
    }

    fn tray_rect(&self) -> Rect {
        let tb = self.taskbar_rect();
        Rect::new(tb.right() - 84 - 60, tb.y + 2, 56, TASKBAR_H - 4)
    }

    fn menu_rows(&self) -> (Rect, Vec<(Rect, usize)>) {
        let mut h = 12;
        for (l, _) in MENU.iter() {
            h += if l.is_some() { 30 } else { 10 };
        }
        let tb = self.taskbar_rect();
        let y = if self.theme.taskbar_top { tb.bottom() + 6 } else { tb.y - h - 6 };
        let m = Rect::new(tb.x + 6, y, MENU_W, h);
        let mut rows = Vec::new();
        let mut cy = m.y + 6;
        for (i, (l, _)) in MENU.iter().enumerate() {
            let rh = if l.is_some() { 30 } else { 10 };
            if l.is_some() {
                rows.push((Rect::new(m.x + 6, cy, m.w - 12, rh), i));
            }
            cy += rh;
        }
        (m, rows)
    }

    fn icon_cell(&self, i: usize) -> Rect {
        let y0 = self.work_y().0;
        Rect::new(14, y0 + 16 + i as i32 * ICON_CELL_H, ICON_CELL_W, ICON_CELL_H - 4)
    }

    // ------------------------------------------------------------- theme ----

    /// Read a P6 PPM (maxval 255) from the initramfs or the store.
    fn load_ppm(name: &str) -> Option<(usize, usize, Vec<u8>)> {
        let data: Vec<u8> = if let Some(f) = crate::fs::root().and_then(|d| d.lookup(name)) {
            f.data.to_vec()
        } else {
            crate::store::with(|s| s.read(name)).ok()?.ok()?
        };
        let mut pos = 0usize;
        let mut tok = |data: &[u8]| -> Option<Vec<u8>> {
            loop {
                while pos < data.len() && data[pos].is_ascii_whitespace() {
                    pos += 1;
                }
                if pos < data.len() && data[pos] == b'#' {
                    while pos < data.len() && data[pos] != b'\n' {
                        pos += 1;
                    }
                } else {
                    break;
                }
            }
            let st = pos;
            while pos < data.len() && !data[pos].is_ascii_whitespace() {
                pos += 1;
            }
            if st == pos { None } else { Some(data[st..pos].to_vec()) }
        };
        if tok(&data)? != b"P6" {
            return None;
        }
        let num = |t: Vec<u8>| core::str::from_utf8(&t).ok()?.parse::<usize>().ok();
        let (w, h, mx) = (num(tok(&data)?)?, num(tok(&data)?)?, num(tok(&data)?)?);
        if w == 0 || h == 0 || w > 8192 || h > 8192 || mx != 255 {
            return None;
        }
        pos += 1; // single whitespace after maxval
        let need = w * h * 3;
        if data.len() < pos + need {
            return None;
        }
        Some((w, h, data[pos..pos + need].to_vec()))
    }

    fn rebuild_wallpaper(&mut self) {
        let (sw, sh, k, wf) = (self.sw, self.sh, self.theme.wallpaper, self.theme.wall_file);
        if self.wall_kind == k && self.wall_file == wf && !self.wall.is_empty() {
            return;
        }
        self.wall.resize((sw * sh) as usize, 0);
        self.wall_note = "";
        let fname = self.theme.wall_file_str();
        if !fname.is_empty() {
            if let Some((iw, ih, px)) = Self::load_ppm(fname) {
                // "cover": scale to fill the screen, centre-crop (nearest neighbour, fixed point)
                let f = ((sw as i64 * 1024) / iw as i64).max((sh as i64 * 1024) / ih as i64).max(1);
                let (scw, sch) = (iw as i64 * f / 1024, ih as i64 * f / 1024);
                let (cx, cy) = ((scw - sw as i64) / 2, (sch - sh as i64) / 2);
                for y in 0..sh {
                    let sy = (((y as i64 + cy) * 1024 / f) as usize).min(ih - 1);
                    for x in 0..sw {
                        let sx = (((x as i64 + cx) * 1024 / f) as usize).min(iw - 1);
                        let o = (sy * iw + sx) * 3;
                        self.wall[(y * sw + x) as usize] = rgb(px[o], px[o + 1], px[o + 2]);
                    }
                }
                self.wall_kind = k;
                self.wall_file = wf;
                log::info!("[deloxy-de] wallpaper loaded from {} ({}x{})", fname, iw, ih);
                return;
            }
            self.wall_note = "custom wallpaper not found or not a P6 PPM";
            log::warn!("[deloxy-de] wallpaper file '{}' unusable; using the built-in one", fname);
        }
        for y in 0..sh {
            for x in 0..sw {
                self.wall[(y * sw + x) as usize] = theme::wallpaper_px(k, x, y, sw, sh);
            }
        }
        self.wall_kind = k;
        self.wall_file = wf;
    }

    fn settings_dirty(&mut self) {
        let r = self.windows.iter().find(|w| w.kind == Kind::Settings).map(|w| w.content());
        if let Some(r) = r {
            self.add_damage(r);
        }
        for w in self.windows.iter_mut() {
            if w.kind == Kind::Settings {
                w.title = String::from("Settings");
            }
        }
    }

    /// Install a new theme (repaint everything, keep windows inside the work area).
    fn set_theme(&mut self, t: Theme, save: bool) {
        if t == self.theme {
            return;
        }
        self.theme = t;
        self.pal = t.palette();
        self.rebuild_wallpaper();
        let (y0, y1) = self.work_y();
        for w in self.windows.iter_mut() {
            w.y = w.y.clamp(y0, (y1 - TITLE_H).max(y0));
        }
        self.damage = self.screen();
        self.redraw_settings_surfaces();
        log::info!("[deloxy-de] theme: {}", t.to_text().replace('\n', " ").trim_end());
        if save {
            self.save_theme();
        }
    }

    fn save_theme(&mut self) {
        use crate::store;
        self.persist_note = match store::state() {
            store::State::Ready => match store::with(|s| s.write("de.conf", self.theme.to_text().as_bytes())) {
                Ok(Ok(())) => {
                    self.store_gen = store::with(|s| s.stats().generation).unwrap_or(0);
                    "saved to de.conf"
                }
                _ => "saving failed",
            },
            _ => "not saved (no store disk)",
        };
        self.redraw_settings_surfaces();
    }

    /// Load `de.conf` from the store (if present) and apply it.
    fn load_theme(&mut self) {
        use crate::store;
        if store::state() != store::State::Ready {
            return;
        }
        let gen = store::with(|s| s.stats().generation).unwrap_or(0);
        if gen == self.store_gen {
            return;
        }
        self.store_gen = gen;
        if let Ok(Ok(bytes)) = store::with(|s| s.read("de.conf")) {
            let mut t = Theme::default();
            t.apply_text(&String::from_utf8_lossy(&bytes));
            self.set_theme(t, false);
        }
    }

    fn apply_act(&mut self, a: Act) {
        let mut t = self.theme;
        match a {
            Act::Dark(d) => t.dark = d,
            Act::Accent(i) => t.accent = theme::ACCENTS[i.min(7)].1,
            Act::Wall(i) => {
                t.wallpaper = i;
                t.wall_file = [0; 32];
            }
            Act::Top(b) => t.taskbar_top = b,
            Act::Round(b) => t.round = b,
            Act::Clock12(b) => t.clock12 = b,
            Act::Dock(b) => t.dock = b,
            Act::Glass(b) => t.glass = b,
            Act::Flat(b) => t.flat_titles = b,
            Act::Shadow(n) => t.shadow = n,
            Act::Reset => t = Theme::default(),
        }
        self.set_theme(t, true);
    }

    // ----------------------------------------------------------- clients ----

    fn alloc_surface(&mut self, w: i32, h: i32, fill: u32) -> Option<(Arc<MemObject>, Arc<MemObject>, *mut u32, &'static WmRing, &'static WmRing, CapObject)> {
        let (cli_end, _srv_end) = crate::ipc::create_channel()?;
        let chanmem = match &cli_end {
            CapObject::Channel { mem, .. } => mem.clone(),
            _ => return None,
        };
        let pages = (w as u64 * h as u64 * 4 + PAGE_SIZE - 1) / PAGE_SIZE;
        let bufmem = MemObject::new(pages as usize)?;
        let view = vmm::map_kernel_shared(&bufmem)?;
        // SAFETY: the view maps `pages` writable pages starting at `view`.
        unsafe { core::slice::from_raw_parts_mut(view as *mut u32, (w * h) as usize).fill(fill) };
        // SAFETY: the channel memory has two zeroed pages; each holds a ring (all-zero = empty),
        // and `chanmem` (stored in the window) outlives these references.
        let (rx, tx) = unsafe {
            (
                &*(vmm::phys_to_virt(chanmem.frames()[0].start_address()) as *const WmRing),
                &*(vmm::phys_to_virt(chanmem.frames()[1].start_address()) as *const WmRing),
            )
        };
        Some((bufmem, chanmem, view as *mut u32, rx, tx, cli_end))
    }

    fn spawn_app(&mut self, key: &'static str, title: &str, role: u64, x: i32, y: i32, w: i32, h: i32) -> bool {
        let Some((bufmem, chanmem, view, rx, tx, cli_end)) = self.alloc_surface(w, h, rgb(28, 32, 40)) else { return false };
        let rw = Rights::READ | Rights::WRITE | Rights::MAP;
        let proc = match task::spawn_process(
            title,
            blobs::DE,
            Some(InitSpec { role, n: ((w as u64) << 16) | h as u64, side: 0, caps: vec![(cli_end, rw), (CapObject::Memory(bufmem.clone()), rw)] }),
        ) {
            Ok(p) => p,
            Err(_) => return false,
        };
        let id = self.next_id;
        self.next_id += 1;
        let win = Window { id, key, kind: Kind::Client, title: String::from(title), proc, x, y, w, h, buf: view, _bufmem: bufmem, _chanmem: chanmem, rx, tx, focused: false, minimized: false, closing: false, term: None };
        win.send(WmMsg::new(S_CONFIGURE, id, w, h, 0, 0));
        let outer = win.outer();
        self.windows.push(win);
        self.add_damage(outer);
        self.focus(id);
        log::info!("[deloxy-de] window {} '{}' at ({},{}) {}x{}", id, title, x, y, w, h);
        true
    }

    /// Create a compositor-drawn window (the terminal or Settings): it has no client process.
    fn spawn_builtin(&mut self, key: &'static str, kind: Kind, title: &str, x: i32, y: i32, w: i32, h: i32, fill: u32) -> bool {
        let Some((bufmem, chanmem, view, rx, tx, _cli)) = self.alloc_surface(w, h, fill) else { return false };
        let id = self.next_id;
        self.next_id += 1;
        let win = Window {
            id,
            key,
            kind,
            title: String::from(title),
            proc: task::kernel_process(),
            x,
            y,
            w,
            h,
            buf: view,
            _bufmem: bufmem,
            _chanmem: chanmem,
            rx,
            tx,
            focused: false,
            minimized: false,
            closing: false,
            term: if kind == Kind::Terminal { Some(Term::new()) } else { None },
        };
        let outer = win.outer();
        self.windows.push(win);
        self.add_damage(outer);
        self.focus(id);
        if kind == Kind::Settings {
            self.redraw_settings_surfaces();
        }
        log::info!("[deloxy-de] window {} '{}' at ({},{}) {}x{}", id, title, x, y, w, h);
        true
    }

    fn spawn_terminal(&mut self, x: i32, y: i32) -> bool {
        let (w, h) = ((TERM_COLS * crate::gfx::font::GLYPH_W) as i32, (TERM_ROWS * crate::gfx::font::GLYPH_H) as i32);
        self.spawn_builtin("term", Kind::Terminal, "terminal", x, y, w, h, COL_TERM_BG)
    }

    fn redraw_settings_surfaces(&mut self) {
        let (theme, pal, note) = (self.theme, self.pal, if self.wall_note.is_empty() { self.persist_note } else { self.wall_note });
        let mut dmg = Vec::new();
        for win in self.windows.iter() {
            if !matches!(win.kind, Kind::Settings | Kind::Files | Kind::Viewer | Kind::Tasks | Kind::Perms) {
                continue;
            }
            // SAFETY: `buf` is a live kernel view of w*h pixels owned by `_bufmem`.
            let px = unsafe { core::slice::from_raw_parts_mut(win.buf, (win.w * win.h) as usize) };
            let mut s = Surface::new(px, win.w, win.h, win.w);
            match win.kind {
                Kind::Settings => draw_settings(&mut s, &theme, &pal, note),
                Kind::Files => draw_files(&mut s, &theme, &pal, &self.files),
                Kind::Tasks => draw_tasks(&mut s, &theme, &pal, &self.tasks),
                Kind::Perms => draw_perms(&mut s, &theme, &pal, &self.perms),
                _ => draw_viewer(&mut s, &pal, &self.viewer),
            }
            if !win.minimized {
                dmg.push(win.content());
            }
        }
        for r in dmg {
            self.add_damage(r);
        }
    }

    /// Pull new TTY output into the terminal grid and repaint it when something changed.
    fn pump_terminal(&mut self) {
        let mut dmg = None;
        for win in self.windows.iter_mut() {
            let Some(t) = win.term.as_mut() else { continue };
            let mut buf = [0u8; 256];
            loop {
                let (n, np) = crate::tty::read_output(t.pos, &mut buf);
                t.pos = np;
                if n == 0 {
                    break;
                }
                t.feed(&buf[..n]);
            }
            if t.dirty {
                t.dirty = false;
                // SAFETY: `buf` is a live kernel view of w*h pixels owned by `_bufmem`.
                let px = unsafe { core::slice::from_raw_parts_mut(win.buf, (win.w * win.h) as usize) };
                let mut s = Surface::new(px, win.w, win.h, win.w);
                s.fill_rect(Rect::new(0, 0, win.w, win.h), COL_TERM_BG);
                let (gw, gh) = (crate::gfx::font::GLYPH_W as i32, crate::gfx::font::GLYPH_H as i32);
                for r in 0..TERM_ROWS {
                    let line = &t.grid[r * TERM_COLS..(r + 1) * TERM_COLS];
                    if line.iter().any(|&c| c != b' ') {
                        s.draw_text(0, r as i32 * gh, line, COL_TERM_FG, None);
                    }
                }
                let cc = t.col.min(TERM_COLS - 1) as i32;
                s.fill_rect(Rect::new(cc * gw, t.row as i32 * gh + gh - 3, gw, 2), COL_TERM_FG);
                if !win.minimized {
                    dmg = Some(win.content());
                }
            }
        }
        if let Some(r) = dmg {
            self.add_damage(r);
        }
    }

    fn poll_clients(&mut self) {
        let mut dmg: Vec<Rect> = Vec::new();
        for win in self.windows.iter_mut() {
            while let Some((m, _)) = win.rx.try_pop() {
                match m.kind {
                    C_TITLE => {
                        // SAFETY: `pad` is 40 plain bytes.
                        let bytes = unsafe { core::slice::from_raw_parts(m.pad.as_ptr() as *const u8, 40) };
                        let n = bytes.iter().position(|&b| b == 0).unwrap_or(40);
                        win.title = String::from_utf8_lossy(&bytes[..n]).into_owned();
                        dmg.push(win.title_bar());
                    }
                    C_COMMIT => {
                        let (a, b, cw, ch) = if m.c <= 0 || m.d <= 0 { (0, 0, win.w, win.h) } else { (m.a, m.b, m.c, m.d) };
                        let c = win.content();
                        if !win.minimized {
                            dmg.push(Rect::new(c.x + a, c.y + b, cw.min(win.w), ch.min(win.h)).intersect(&c));
                        }
                    }
                    _ => {}
                }
            }
        }
        for r in dmg {
            self.add_damage(r);
        }
    }

    fn reap_dead(&mut self) {
        let mut i = 0;
        while i < self.windows.len() {
            if self.windows[i].proc.has_exited() || self.windows[i].closing {
                let w = self.windows.remove(i);
                log::info!("[deloxy-de] window {} '{}' closed", w.id, w.title);
                let o = w.outer();
                self.add_damage(Rect::new(o.x - 12, o.y - 12, o.w + 24, o.h + 28)); // include the drop shadow
                if self.drag.map_or(false, |d| d.0 == w.id) {
                    self.drag = None;
                }
                if w.focused {
                    self.focus_topmost_visible();
                }
                let tb = self.taskbar_rect();
                self.add_damage(tb);
            } else {
                i += 1;
            }
        }
    }

    // ------------------------------------------------------------- focus ----

    fn focus_topmost_visible(&mut self) {
        if let Some(top) = self.windows.iter().rev().find(|w| !w.minimized).map(|w| w.id) {
            self.focus(top);
        }
    }

    fn focus(&mut self, id: u32) {
        if self.windows.last().map_or(false, |w| w.id == id && w.focused && !w.minimized) {
            return;
        }
        let mut dmg = Vec::new();
        for w in self.windows.iter_mut() {
            if w.focused && w.id != id {
                w.focused = false;
                w.send(WmMsg::new(S_FOCUS, w.id, 0, 0, 0, 0));
                dmg.push(w.outer());
            }
        }
        if let Some(idx) = self.windows.iter().position(|w| w.id == id) {
            let mut w = self.windows.remove(idx);
            w.minimized = false;
            w.focused = true;
            w.send(WmMsg::new(S_FOCUS, w.id, 1, 0, 0, 0));
            dmg.push(w.outer());
            log::info!("[deloxy-de] focus -> window {} '{}'", w.id, w.title);
            self.windows.push(w);
        }
        for r in dmg {
            self.add_damage(r);
        }
        let tb = self.taskbar_rect();
        self.add_damage(tb);
    }

    fn minimize(&mut self, id: u32) {
        let mut r = None;
        if let Some(w) = self.windows.iter_mut().find(|w| w.id == id) {
            w.minimized = true;
            if w.focused {
                w.focused = false;
                w.send(WmMsg::new(S_FOCUS, w.id, 0, 0, 0, 0));
            }
            r = Some(w.outer());
            log::info!("[deloxy-de] window {} '{}' minimized", w.id, w.title);
        }
        if let Some(r) = r {
            self.add_damage(r);
            self.add_damage(r.union(&Rect::new(r.x - 12, r.y - 12, r.w + 24, r.h + 28)));
        }
        self.focus_topmost_visible();
        let tb = self.taskbar_rect();
        self.add_damage(tb);
    }

    // ------------------------------------------------------------ launch ----

    fn launch(&mut self, l: Launch) {
        let (key, name): (&'static str, &str) = match l {
            Launch::Terminal => ("term", "terminal"),
            Launch::Files => ("files", "Files"),
            Launch::Tasks => ("tasks", "Task Manager"),
            Launch::Perms => ("perms", "Permissions"),
            Launch::Monitor => ("diag", "diag"),
            Launch::Anim => ("anim", "anim"),
            Launch::Bars => ("bars", "bars"),
            Launch::Settings => ("settings", "Settings"),
            Launch::Restart => {
                log::info!("[deloxy-de] restart requested from the menu");
                crate::arch::x86_64::power(true)
            }
            Launch::Shutdown => {
                log::info!("[deloxy-de] shutdown requested from the menu");
                crate::arch::x86_64::power(false)
            }
        };
        log::info!("[deloxy-de] launch '{}'", key);
        if let Some(id) = self.windows.iter().find(|w| w.key == key && !w.closing && !w.proc.has_exited()).map(|w| w.id) {
            self.focus(id); // already running: raise / restore it
            return;
        }
        let (y0, y1) = self.work_y();
        let off = (self.cascade % 5) * 28;
        self.cascade += 1;
        let (x, y) = (140 + off, y0 + 50 + off);
        match l {
            Launch::Terminal => {
                let _ = self.spawn_terminal(self.sw - 660, (y1 - 424).max(y0 + 10));
            }
            Launch::Settings => {
                let _ = self.spawn_builtin("settings", Kind::Settings, name, x + 40, y, SET_W, SET_H, self.pal.win_bg);
            }
            Launch::Perms => {
                self.refresh_perms();
                let _ = self.spawn_builtin("perms", Kind::Perms, name, x + 10, y, PERMS_W, PERMS_H, self.pal.win_bg);
            }
            Launch::Tasks => {
                self.refresh_tasks();
                let _ = self.spawn_builtin("tasks", Kind::Tasks, name, x + 30, y, TASKS_W, TASKS_H, self.pal.win_bg);
            }
            Launch::Files => {
                self.refresh_files();
                let _ = self.spawn_builtin("files", Kind::Files, name, x + 20, y, FILES_W, FILES_H, self.pal.win_bg);
            }
            Launch::Monitor => {
                let _ = self.spawn_app(key, name, 11, x + 200, y, 380, 230);
            }
            Launch::Anim => {
                let _ = self.spawn_app(key, name, 10, x, y, 320, 200);
            }
            Launch::Bars => {
                let _ = self.spawn_app(key, name, 12, x, y, 320, 200);
            }
            _ => {}
        }
    }

    // ------------------------------------------------------------ permissions ----

    fn refresh_perms(&mut self) {
        let rows: Vec<PRow> = crate::perm::list().into_iter().filter(|e| !e.once).map(|e| PRow { name: e.name, net: e.net, read: e.read, write: e.write }).collect();
        if self.perms.sel.map_or(false, |i| i >= rows.len()) {
            self.perms.sel = None;
        }
        self.perms.rows = rows;
    }

    fn perms_action(&mut self, act: u8) {
        let Some(row) = self.perms.sel.and_then(|i| self.perms.rows.get(i)).cloned() else {
            self.perms.status = String::from("select a rule first");
            return;
        };
        let what = match row.net {
            Some(r) => crate::perm::describe(&r),
            None => String::from("files"),
        };
        // the hash keys the rule: re-derive it from the program file (initramfs or store)
        let hash = || {
            crate::fs::root()
                .and_then(|d| d.lookup(&row.name))
                .map(|f| f.data.to_vec())
                .or_else(|| crate::store::with(|s| s.read(&row.name)).ok().and_then(|r| r.ok()))
                .map(|d| crate::perm::image_hash(&d))
        };
        match act {
            0 => {
                match row.net {
                    Some(r) => crate::perm::remove_net(&row.name, r.dest),
                    None => crate::perm::remove_files(&row.name),
                };
                self.perms.status = alloc::format!("revoked {} for {}", what, row.name);
                log::info!("[deloxy-de] perms: revoked '{}' ({})", row.name, what);
            }
            1 | 2 => {
                let allow = act == 1;
                let Some(h) = hash() else {
                    self.perms.status = String::from("program file not found (revoke instead)");
                    return;
                };
                match row.net {
                    Some(r) => crate::perm::set_net(&row.name, &h, r, allow),
                    None => crate::perm::set(&row.name, &h, allow, allow, false),
                }
                self.perms.status = alloc::format!("{} {} for {}", if allow { "allowed" } else { "denied" }, what, row.name);
                log::info!("[deloxy-de] perms: set '{}' {} {}", row.name, what, if allow { "allow" } else { "deny" });
            }
            3 | 4 => {
                let (Some(h), Some(r)) = (hash(), row.net) else {
                    self.perms.status = String::from("select a network rule (and keep the program file)");
                    return;
                };
                if act == 3 {
                    // full access: any host, no limits (replaces this row)
                    if r.dest.is_some() {
                        crate::perm::remove_net(&row.name, r.dest);
                    }
                    crate::perm::set_net(&row.name, &h, crate::perm::NetRule::full(), true);
                    self.perms.status = alloc::format!("full access for {} (any host, no limits)", row.name);
                    log::info!("[deloxy-de] perms: full access for '{}'", row.name);
                } else {
                    // cycle limit presets: unlimited -> 1 h / 1 GiB -> 10 min / 64 MiB -> 5 min / 10 MiB
                    const PRESETS: [(u32, u32); 4] = [(0, 0), (3600, 1 << 20), (600, 64 << 10), (300, 10 << 10)];
                    let cur = PRESETS.iter().position(|p| *p == (r.secs, r.kib)).unwrap_or(0);
                    let (secs, kib) = PRESETS[(cur + 1) % PRESETS.len()];
                    let nr = crate::perm::NetRule { secs, kib, ..r };
                    crate::perm::set_net(&row.name, &h, nr, row.read);
                    self.perms.status = alloc::format!("limits for {}: {}", row.name, crate::perm::fmt_rule(&nr));
                    log::info!("[deloxy-de] perms: limits for '{}' {}s {} KiB", row.name, secs, kib);
                }
            }
            _ => {}
        }
        self.refresh_perms();
        let m = self.perms.status.clone();
        self.notify(&m);
    }

    fn perms_click(&mut self, lx: i32, ly: i32) {
        if Rect::new(8, 6, 70, 24).contains(lx, ly) {
            self.perms_action(0);
        } else if Rect::new(86, 6, 60, 24).contains(lx, ly) {
            self.perms_action(1);
        } else if Rect::new(154, 6, 60, 24).contains(lx, ly) {
            self.perms_action(2);
        } else if Rect::new(222, 6, 60, 24).contains(lx, ly) {
            self.perms_action(3);
        } else if Rect::new(290, 6, 70, 24).contains(lx, ly) {
            self.perms_action(4);
        } else if Rect::new(368, 6, 70, 24).contains(lx, ly) {
            self.refresh_perms();
            self.perms.status = String::from("refreshed");
        } else {
            for i in 0..PERM_ROWS {
                if i < self.perms.rows.len() && Rect::new(8, 58 + i as i32 * 22, 540, 22).contains(lx, ly) {
                    self.perms.sel = Some(i);
                    let r = &self.perms.rows[i];
                    log::info!("[deloxy-de] perms: select '{}' ({})", r.name, if r.net.is_some() { "net" } else { "files" });
                    break;
                }
            }
        }
        self.redraw_settings_surfaces();
    }

    // ------------------------------------------------- tasks / toasts / ctx ----

    fn refresh_tasks(&mut self) {
        let mut rows = Vec::new();
        for pr in crate::task::list_processes() {
            if pr.has_exited() {
                continue;
            }
            rows.push(TRow {
                pid: pr.pid,
                name: pr.name.clone(),
                thr: pr.live_threads.load(core::sync::atomic::Ordering::Relaxed) as u32,
                mem_kib: (pr.mem_pages() * 4) as u32,
                abi: ["native", "linux", "windows"].get(pr.abi() as usize).copied().unwrap_or("?"),
            });
        }
        if let Some(sel) = self.tasks.sel {
            if !rows.iter().any(|r| r.pid == sel) {
                self.tasks.sel = None;
            }
        }
        self.tasks.rows = rows;
    }

    fn end_selected_task(&mut self) {
        let Some(pid) = self.tasks.sel else {
            self.tasks.status = String::from("select a process first");
            return;
        };
        let Some(row) = self.tasks.rows.iter().find(|r| r.pid == pid).cloned() else { return };
        if row.name == "deloxy-sh" || row.pid <= 1 {
            self.tasks.status = String::from("the shell is protected (it owns the terminal)");
            return;
        }
        let target = crate::task::list_processes().into_iter().find(|p| p.pid == pid);
        let ok = target.map_or(false, |p| crate::task::sched::kill_process(&p, 137));
        log::info!("[deloxy-de] tasks: ended '{}' (pid {}): {}", row.name, pid, ok);
        self.tasks.status = if ok { alloc::format!("ended {} (pid {})", row.name, pid) } else { String::from("could not end the process") };
        if ok {
            self.notify(&alloc::format!("Ended {}", row.name));
        }
        self.refresh_tasks();
    }

    fn tasks_click(&mut self, lx: i32, ly: i32) {
        if Rect::new(8, 6, 110, 24).contains(lx, ly) {
            self.end_selected_task();
        } else if Rect::new(126, 6, 76, 24).contains(lx, ly) {
            self.refresh_tasks();
            self.tasks.status = String::from("refreshed");
        } else {
            for i in 0..TASK_ROWS {
                if let Some(r) = self.tasks.rows.get(i) {
                    if Rect::new(8, 58 + i as i32 * 22, 480, 22).contains(lx, ly) {
                        self.tasks.sel = Some(r.pid);
                        log::info!("[deloxy-de] tasks: select '{}' (pid {})", r.name, r.pid);
                        break;
                    }
                }
            }
        }
        self.redraw_settings_surfaces();
    }

    fn toast_area(&self) -> Rect {
        let y0 = self.work_y().0 + 8;
        Rect::new(self.sw - 316, y0, 308, 4 * 56)
    }

    fn notify(&mut self, msg: &str) {
        log::info!("[deloxy-de] notify: {}", msg);
        let exp = crate::time::uptime_ms() + 4000;
        self.toasts.push((String::from(msg), exp));
        if self.toasts.len() > 4 {
            self.toasts.remove(0);
        }
        let a = self.toast_area();
        self.add_damage(Rect::new(a.x - 12, a.y - 12, a.w + 24, a.h + 24));
    }

    fn expire_toasts(&mut self) {
        let now = crate::time::uptime_ms();
        let before = self.toasts.len();
        self.toasts.retain(|t| t.1 > now);
        if self.toasts.len() != before {
            let a = self.toast_area();
            self.add_damage(Rect::new(a.x - 12, a.y - 12, a.w + 24, a.h + 24));
        }
    }

    fn ctx_rect(&self) -> Option<Rect> {
        let (x, y) = self.ctx?;
        let (w, h) = (196, CTX_ITEMS.len() as i32 * 30 + 12);
        Some(Rect::new(x.min(self.sw - w - 4), y.min(self.sh - h - 4), w, h))
    }

    fn close_ctx(&mut self) {
        if let Some(r) = self.ctx_rect() {
            self.ctx = None;
            self.add_damage(Rect::new(r.x - 12, r.y - 12, r.w + 24, r.h + 28));
        }
    }

    fn ctx_hit(&self, x: i32, y: i32) -> Option<usize> {
        let r = self.ctx_rect()?;
        (0..CTX_ITEMS.len()).find(|i| Rect::new(r.x + 6, r.y + 6 + *i as i32 * 30, r.w - 12, 30).contains(x, y))
    }

    fn ctx_action(&mut self, i: usize) {
        log::info!("[deloxy-de] ctx -> {}", CTX_ITEMS[i]);
        match i {
            0 => self.launch(Launch::Terminal),
            1 => self.launch(Launch::Files),
            2 => self.launch(Launch::Tasks),
            3 => self.launch(Launch::Settings),
            _ => {
                let n = (self.theme.wallpaper + 1) % 4;
                self.apply_act(Act::Wall(n));
                self.notify(&alloc::format!("Wallpaper: {}", theme::WALLPAPERS[n as usize]));
            }
        }
    }

    // ------------------------------------------------------- files / viewer ----

    fn refresh_files(&mut self) {
        let mut v: Vec<FEntry> = Vec::new();
        if let Some(root) = crate::fs::root() {
            for f in root.files.iter() {
                v.push(FEntry { name: f.name.clone(), size: f.data.len() as u64, store: false });
            }
        }
        let _ = crate::store::with(|s| {
            for e in s.list() {
                v.push(FEntry { name: e.name.clone(), size: e.size, store: true });
            }
        });
        self.files.gen = crate::store::with(|s| s.stats().generation).unwrap_or(0);
        if let Some(i) = self.files.sel {
            if i >= v.len() {
                self.files.sel = None;
            }
        }
        self.files.entries = v;
        self.files.scroll = self.files.scroll.min(self.files.entries.len().saturating_sub(FILE_ROWS));
    }

    fn entry_data(e: &FEntry) -> Option<Vec<u8>> {
        if e.store {
            crate::store::with(|s| s.read(&e.name)).ok()?.ok()
        } else {
            crate::fs::root()?.lookup(&e.name).map(|f| f.data.to_vec())
        }
    }

    fn run_program(&mut self, name: &str, data: &[u8]) -> String {
        let mut fcaps: Vec<(CapObject, Rights)> = Vec::new();
        if let Some(root) = crate::fs::root() {
            fcaps.push((CapObject::Dir(root), Rights::READ));
        }
        fcaps.push((CapObject::Store, Rights::READ | Rights::WRITE));
        let caps = [(CapObject::Tty, Rights::WRITE)];
        let args = [name];
        match crate::exec::spawn(name, data, &crate::exec::SpawnOpts { args: &args, console: true, caps: &caps, foreign_caps: &fcaps }) {
            Ok(p) => {
                log::info!("[deloxy-de] files: started '{}' (pid {})", name, p.pid);
                alloc::format!("started {} (output is in the terminal)", name)
            }
            Err(e) => alloc::format!("cannot start {}: {:?}", name, e),
        }
    }

    fn make_lines(data: &[u8]) -> Vec<String> {
        let mut out = Vec::new();
        match core::str::from_utf8(data) {
            Ok(t) => {
                for line in t.split('\n') {
                    let clean: String = line.chars().map(|c| if c == '\t' { ' ' } else if c.is_control() || !c.is_ascii() { '?' } else { c }).collect();
                    if clean.is_empty() {
                        out.push(String::new());
                    }
                    let b = clean.as_bytes();
                    for ch in b.chunks(62) {
                        out.push(String::from_utf8_lossy(ch).into_owned());
                    }
                }
            }
            Err(_) => {
                out.push(alloc::format!("(binary file, {} bytes - first 512 bytes as hex)", data.len()));
                for (i, ch) in data.iter().take(512).collect::<Vec<_>>().chunks(16).enumerate() {
                    let mut l = alloc::format!("{:04x}  ", i * 16);
                    for b in ch {
                        l.push_str(&alloc::format!("{:02x} ", **b));
                    }
                    out.push(l);
                }
            }
        }
        out
    }

    fn open_viewer(&mut self, name: &str, data: &[u8]) {
        self.viewer = ViewerState { title: String::from(name), lines: Self::make_lines(data), scroll: 0 };
        let title = alloc::format!("Viewer - {}", name);
        if let Some(w) = self.windows.iter_mut().find(|w| w.kind == Kind::Viewer) {
            w.title = title;
            let id = w.id;
            self.focus(id);
        } else {
            let (y0, _) = self.work_y();
            let _ = self.spawn_builtin("viewer", Kind::Viewer, &title, 220, y0 + 70, VIEW_W, VIEW_H, self.pal.win_bg);
        }
        self.redraw_settings_surfaces();
    }

    fn open_entry(&mut self, idx: usize) {
        let Some(e) = self.files.entries.get(idx).cloned() else { return };
        let lower = e.name.to_ascii_lowercase();
        log::info!("[deloxy-de] files: open '{}'", e.name);
        let Some(data) = Self::entry_data(&e) else {
            self.files.status = alloc::format!("cannot read {}", e.name);
            return;
        };
        if lower.ends_with(".elf") || lower.ends_with(".exe") {
            self.files.status = self.run_program(&e.name, &data);
            let m = self.files.status.clone();
            self.notify(&m);
            self.launch(Launch::Terminal);
        } else if lower.ends_with(".ppm") {
            let mut t = self.theme;
            t.wall_file = [0; 32];
            if e.name.len() < 32 {
                t.wall_file[..e.name.len()].copy_from_slice(e.name.as_bytes());
            }
            self.set_theme(t, true);
            self.files.status = if self.wall_note.is_empty() { alloc::format!("wallpaper set to {}", e.name) } else { String::from(self.wall_note) };
        } else {
            self.open_viewer(&e.name, &data);
            self.files.status = alloc::format!("opened {}", e.name);
        }
        self.redraw_settings_surfaces();
    }

    fn delete_entry(&mut self, idx: usize) {
        let Some(e) = self.files.entries.get(idx).cloned() else { return };
        self.files.status = if !e.store {
            String::from("system files are read-only")
        } else if crate::store::is_reserved(&e.name) || e.name == "de.conf" {
            String::from("this file is managed by the system")
        } else {
            match crate::store::with(|s| s.delete(&e.name)) {
                Ok(Ok(())) => {
                    log::info!("[deloxy-de] files: deleted '{}'", e.name);
                    self.notify(&alloc::format!("Deleted {}", e.name));
                    alloc::format!("deleted {}", e.name)
                }
                _ => String::from("delete failed"),
            }
        };
        self.refresh_files();
        self.redraw_settings_surfaces();
    }

    fn files_click(&mut self, lx: i32, ly: i32) {
        if files_open_btn().contains(lx, ly) {
            match self.files.sel {
                Some(i) => self.open_entry(i),
                None => self.files.status = String::from("select a file first"),
            }
        } else if files_del_btn().contains(lx, ly) {
            match self.files.sel {
                Some(i) => self.delete_entry(i),
                None => self.files.status = String::from("select a file first"),
            }
        } else if files_refresh_btn().contains(lx, ly) {
            self.refresh_files();
            self.files.status = String::from("refreshed");
        } else if files_up_btn().contains(lx, ly) {
            self.files.scroll = self.files.scroll.saturating_sub(FILE_ROWS / 2);
        } else if files_down_btn().contains(lx, ly) {
            self.files.scroll = (self.files.scroll + FILE_ROWS / 2).min(self.files.entries.len().saturating_sub(FILE_ROWS));
        } else {
            for i in 0..FILE_ROWS {
                let idx = self.files.scroll + i;
                if idx < self.files.entries.len() && files_row_rect(i).contains(lx, ly) {
                    let now = crate::time::uptime_ms();
                    let dbl = self.files.last_click.0 == idx && now.saturating_sub(self.files.last_click.1) < 600 && self.files.sel == Some(idx);
                    self.files.sel = Some(idx);
                    self.files.last_click = (idx, now);
                    log::info!("[deloxy-de] files: select '{}'", self.files.entries[idx].name);
                    if dbl {
                        self.open_entry(idx);
                    }
                    break;
                }
            }
        }
        self.redraw_settings_surfaces();
    }

    fn app_key(&mut self, kind: Kind, code: u16, ascii: i32) {
        match kind {
            Kind::Files => {
                let n = self.files.entries.len();
                match code {
                    0x148 => self.files.sel = Some(self.files.sel.map_or(0, |i| i.saturating_sub(1))),
                    0x150 => self.files.sel = Some(self.files.sel.map_or(0, |i| (i + 1).min(n.saturating_sub(1)))),
                    0x1C => {
                        if let Some(i) = self.files.sel {
                            self.open_entry(i);
                        }
                    }
                    0x153 => {
                        if let Some(i) = self.files.sel {
                            self.delete_entry(i);
                        }
                    }
                    _ => return,
                }
                if let Some(i) = self.files.sel {
                    if i < self.files.scroll {
                        self.files.scroll = i;
                    } else if i >= self.files.scroll + FILE_ROWS {
                        self.files.scroll = i + 1 - FILE_ROWS;
                    }
                }
            }
            Kind::Viewer => {
                let max = self.viewer.lines.len().saturating_sub(VIEW_ROWS);
                let v = &mut self.viewer.scroll;
                match (code, ascii as u8) {
                    (0x150, _) | (_, b'j') => *v = (*v + 1).min(max),
                    (0x148, _) | (_, b'k') => *v = v.saturating_sub(1),
                    (0x151, _) | (_, b' ') => *v = (*v + VIEW_ROWS - 1).min(max),
                    (0x149, _) | (_, b'b') => *v = v.saturating_sub(VIEW_ROWS - 1),
                    _ => return,
                }
            }
            _ => return,
        }
        self.redraw_settings_surfaces();
    }

    // ------------------------------------------------------------ shortcuts ----

    fn close_window(&mut self, id: u32) {
        let Some(w) = self.windows.iter().find(|w| w.id == id) else { return };
        match w.kind {
            Kind::Terminal => self.minimize(id),
            Kind::Client => w.send(WmMsg::new(S_CLOSE, id, 0, 0, 0, 0)),
            _ => {
                if let Some(w) = self.windows.iter_mut().find(|w| w.id == id) {
                    w.closing = true;
                }
            }
        }
    }

    fn alt_tab(&mut self) {
        let ids = self.task_order();
        if ids.is_empty() {
            return;
        }
        let cur = self.windows.iter().rev().find(|w| w.focused && !w.minimized).map(|w| w.id);
        let next = match cur.and_then(|c| ids.iter().position(|i| *i == c)) {
            Some(p) => ids[(p + 1) % ids.len()],
            None => ids[0],
        };
        if let Some(w) = self.windows.iter().find(|w| w.id == next) {
            log::info!("[deloxy-de] alt-tab -> window {} '{}'", w.id, w.title);
        }
        self.focus(next);
    }

    fn toggle_calendar(&mut self) {
        self.cal_open = !self.cal_open;
        let r = self.cal_rect();
        self.add_damage(Rect::new(r.x - 12, r.y - 12, r.w + 24, r.h + 28));
    }

    fn cal_rect(&self) -> Rect {
        let tb = self.taskbar_rect();
        let (w, h) = (232, 244);
        let y = if self.theme.taskbar_top { tb.bottom() + 8 } else { tb.y - h - 8 };
        Rect::new(tb.right() - w - 4, y, w, h)
    }

    // ------------------------------------------------------------- input ----

    fn handle_input(&mut self) {
        while let Some(ev) = input::pop() {
            match ev.kind {
                EV_MOUSE_MOVE => self.on_move(ev.x, ev.y),
                EV_MOUSE_ABS => {
                    // tablets: 0..32767 across the whole screen -> a relative move to that point
                    let tx = (ev.x as i64 * (self.sw - 1) as i64 / 32767) as i32;
                    let ty = (ev.y as i64 * (self.sh - 1) as i64 / 32767) as i32;
                    self.on_move(tx - self.cx, ty - self.cy);
                }
                EV_MOUSE_BUTTON => self.on_button(ev.code, ev.value != 0),
                EV_KEY => self.on_key(ev),
                _ => {}
            }
        }
    }

    fn hover_at(&self, x: i32, y: i32) -> Hover {
        if let Some(i) = self.ctx_hit(x, y) {
            return Hover::Ctx(i);
        }
        if self.menu_open {
            let (m, rows) = self.menu_rows();
            if m.contains(x, y) {
                for (r, i) in rows {
                    if r.contains(x, y) {
                        return Hover::Menu(i);
                    }
                }
                return Hover::None;
            }
        }
        if self.taskbar_rect().contains(x, y) {
            if self.start_rect().contains(x, y) {
                return Hover::Start;
            }
            for (i, id) in self.task_order().iter().enumerate() {
                if self.task_btn_rect(i).contains(x, y) {
                    return Hover::Task(*id);
                }
            }
            return Hover::None;
        }
        if self.windows.iter().any(|w| !w.minimized && w.outer().contains(x, y)) {
            return Hover::None;
        }
        for i in 0..ICONS.len() {
            if self.icon_cell(i).contains(x, y) {
                return Hover::Icon(i);
            }
        }
        Hover::None
    }

    fn hover_rect(&self, h: Hover) -> Rect {
        match h {
            Hover::None => Rect::new(0, 0, 0, 0),
            Hover::Start => self.start_rect(),
            Hover::Task(id) => {
                let i = self.task_order().iter().position(|x| *x == id).unwrap_or(0);
                self.task_btn_rect(i)
            }
            Hover::Menu(_) => self.menu_rows().0,
            Hover::Icon(i) => self.icon_cell(i),
            Hover::Ctx(_) => self.ctx_rect().unwrap_or(Rect::new(0, 0, 0, 0)),
        }
    }

    fn on_move(&mut self, dx: i32, dy: i32) {
        let old = self.cursor_rect();
        self.cx = (self.cx + dx).clamp(0, self.sw - 1);
        self.cy = (self.cy + dy).clamp(0, self.sh - 1);
        self.add_damage(old);
        self.add_damage(self.cursor_rect());
        if let Some((id, ox, oy)) = self.drag {
            let (y0, y1) = self.work_y();
            let (nx, ny) = (self.cx - ox, (self.cy - oy).clamp(y0, y1 - TITLE_H));
            if let Some(w) = self.windows.iter_mut().find(|w| w.id == id) {
                let before = w.outer();
                w.x = nx;
                w.y = ny;
                let after = w.outer();
                let grow = |r: Rect| Rect::new(r.x - 12, r.y - 12, r.w + 24, r.h + 28);
                self.add_damage(grow(before));
                self.add_damage(grow(after));
            }
            return;
        }
        let nh = self.hover_at(self.cx, self.cy);
        if nh != self.hover {
            let (a, b) = (self.hover_rect(self.hover), self.hover_rect(nh));
            self.hover = nh;
            self.add_damage(a);
            self.add_damage(b);
        }
        // pointer motion inside the topmost window's content
        let (cx, cy, b) = (self.cx, self.cy, self.buttons as i32);
        if let Some(w) = self.windows.iter().rev().find(|w| !w.minimized && w.outer().contains(cx, cy)) {
            let c = w.content();
            if c.contains(cx, cy) && w.focused && w.kind == Kind::Client {
                w.send(WmMsg::new(S_POINTER, w.id, cx - c.x, cy - c.y, b, 0));
            }
        }
    }

    fn close_menu(&mut self) {
        if self.menu_open {
            self.menu_open = false;
            let (m, _) = self.menu_rows();
            self.add_damage(Rect::new(m.x - 12, m.y - 12, m.w + 24, m.h + 28));
        }
    }

    fn on_button(&mut self, code: u16, down: bool) {
        let bit = 1u8 << code.min(7);
        if down {
            self.buttons |= bit;
        } else {
            self.buttons &= !bit;
        }
        if code == 1 && down {
            // right click: desktop context menu (only on empty desktop)
            let (cx, cy) = (self.cx, self.cy);
            let on_win = self.windows.iter().any(|w| !w.minimized && w.outer().contains(cx, cy));
            self.close_ctx();
            if !on_win && !self.taskbar_rect().contains(cx, cy) {
                self.close_menu();
                self.ctx = Some((cx, cy));
                if let Some(r) = self.ctx_rect() {
                    self.add_damage(Rect::new(r.x - 12, r.y - 12, r.w + 24, r.h + 28));
                }
                log::info!("[deloxy-de] right click ({},{}) -> context menu", cx, cy);
            }
            return;
        }
        if code != 0 {
            return;
        }
        let (cx, cy) = (self.cx, self.cy);
        if down && self.ctx.is_some() {
            let hit = self.ctx_hit(cx, cy);
            self.close_ctx();
            if let Some(i) = hit {
                self.ctx_action(i);
            }
            return;
        }
        if !down {
            if let Some((id, _, _)) = self.drag.take() {
                if let Some(w) = self.windows.iter().find(|w| w.id == id) {
                    log::info!("[deloxy-de] window {} moved to ({},{})", w.id, w.x, w.y);
                }
            } else if let Some(w) = self.windows.last() {
                let c = w.content();
                if w.focused && !w.minimized && w.kind == Kind::Client && c.contains(cx, cy) {
                    w.send(WmMsg::new(S_POINTER, w.id, cx - c.x, cy - c.y, self.buttons as i32, 2));
                }
            }
            return;
        }
        if self.cal_open {
            let (inside, on_clock) = (self.cal_rect().contains(cx, cy), self.clock_rect().contains(cx, cy));
            if !inside && !on_clock {
                self.toggle_calendar();
            } else if inside {
                return;
            }
        }
        // start menu
        if self.menu_open {
            let h = self.hover_at(cx, cy);
            self.close_menu();
            if let Hover::Menu(i) = h {
                if let Some(l) = MENU[i].0 {
                    log::info!("[deloxy-de] menu -> {}", MENU[i].1);
                    self.launch(l);
                }
                return;
            }
            if h == Hover::Start {
                return; // clicking the start button again just closes the menu
            }
        }
        // taskbar
        if self.taskbar_rect().contains(cx, cy) {
            if self.clock_rect().contains(cx, cy) {
                log::info!("[deloxy-de] click ({},{}) -> clock (calendar)", cx, cy);
                self.toggle_calendar();
                return;
            }
            if self.start_rect().contains(cx, cy) {
                log::info!("[deloxy-de] click ({},{}) -> start button", cx, cy);
                self.menu_open = !self.menu_open;
                let (m, _) = self.menu_rows();
                let sr = self.start_rect();
                self.add_damage(sr);
                self.add_damage(Rect::new(m.x - 12, m.y - 12, m.w + 24, m.h + 28));
                return;
            }
            let ids = self.task_order();
            for (i, id) in ids.iter().enumerate() {
                if self.task_btn_rect(i).contains(cx, cy) {
                    log::info!("[deloxy-de] click ({},{}) -> taskbar button {}", cx, cy, id);
                    let w = self.windows.iter().find(|w| w.id == *id).unwrap();
                    if w.focused && !w.minimized {
                        self.minimize(*id);
                    } else {
                        self.focus(*id);
                    }
                    return;
                }
            }
            return;
        }
        let hit = self.windows.iter().rev().find(|w| !w.minimized && w.outer().contains(cx, cy)).map(|w| w.id);
        let Some(id) = hit else {
            // desktop icons
            for (i, (l, name)) in ICONS.iter().enumerate() {
                if self.icon_cell(i).contains(cx, cy) {
                    log::info!("[deloxy-de] click ({},{}) -> desktop icon {}", cx, cy, name);
                    self.launch(*l);
                    return;
                }
            }
            log::info!("[deloxy-de] click ({},{}) -> desktop", cx, cy);
            return;
        };
        self.focus(id);
        let w = self.windows.last().unwrap();
        let (kind, wid) = (w.kind, w.id);
        if w.close_box().contains(cx, cy) {
            match kind {
                Kind::Terminal => {
                    log::info!("[deloxy-de] click ({},{}) -> close box of terminal (hides it; the shell keeps running)", cx, cy);
                    self.minimize(wid);
                }
                Kind::Settings | Kind::Files | Kind::Viewer | Kind::Tasks | Kind::Perms => {
                    log::info!("[deloxy-de] click ({},{}) -> close box of window {}", cx, cy, wid);
                    if let Some(w) = self.windows.iter_mut().find(|w| w.id == wid) {
                        w.closing = true;
                    }
                }
                Kind::Client => {
                    log::info!("[deloxy-de] click ({},{}) -> close box of window {}", cx, cy, wid);
                    w.send(WmMsg::new(S_CLOSE, wid, 0, 0, 0, 0));
                }
            }
        } else if w.min_box().contains(cx, cy) {
            log::info!("[deloxy-de] click ({},{}) -> minimize box of window {}", cx, cy, wid);
            self.minimize(wid);
        } else if w.title_bar().contains(cx, cy) {
            log::info!("[deloxy-de] click ({},{}) -> title bar of window {} '{}'", cx, cy, w.id, w.title);
            self.drag = Some((w.id, cx - w.x, cy - w.y));
        } else {
            let c = w.content();
            match kind {
                Kind::Settings => {
                    let (lx, ly) = (cx - c.x, cy - c.y);
                    let hit = settings_layout(&self.theme).into_iter().find(|it| it.rect.contains(lx, ly)).map(|it| it.act);
                    log::info!("[deloxy-de] click ({},{}) -> settings {:?}", cx, cy, hit);
                    if let Some(a) = hit {
                        self.apply_act(a);
                    }
                }
                Kind::Files => {
                    let (lx, ly) = (cx - c.x, cy - c.y);
                    self.files_click(lx, ly);
                }
                Kind::Tasks => {
                    let (lx, ly) = (cx - c.x, cy - c.y);
                    self.tasks_click(lx, ly);
                }
                Kind::Perms => {
                    let (lx, ly) = (cx - c.x, cy - c.y);
                    self.perms_click(lx, ly);
                }
                Kind::Terminal | Kind::Viewer => {}
                Kind::Client => {
                    log::info!("[deloxy-de] click ({},{}) -> content of window {} '{}'", cx, cy, w.id, w.title);
                    w.send(WmMsg::new(S_POINTER, w.id, cx - c.x, cy - c.y, self.buttons as i32, 1));
                }
            }
        }
    }

    fn on_key(&mut self, ev: InputEvent) {
        if ev.value != 0 {
            log::info!(
                "[deloxy-de] key {} (scancode {:#x}) -> {}",
                if ev.x != 0 { alloc::format!("'{}'", ev.x as u8 as char) } else { String::from("<none>") },
                ev.code,
                self.windows.last().map_or("nobody", |w| w.title.as_str())
            );
            let (alt, ctrl) = (ev.y & 4 != 0, ev.y & 2 != 0);
            if alt && ev.code == 0x0F {
                self.alt_tab();
                return;
            }
            if alt && ev.code == 0x3E {
                if let Some(id) = self.windows.iter().rev().find(|w| w.focused && !w.minimized).map(|w| w.id) {
                    log::info!("[deloxy-de] alt-f4 -> window {}", id);
                    self.close_window(id);
                }
                return;
            }
            if alt && ctrl && ev.code == 0x14 {
                log::info!("[deloxy-de] shortcut ctrl-alt-t -> terminal");
                self.launch(Launch::Terminal);
                return;
            }
            if ev.code == 0x15B || ev.code == 0x15C {
                log::info!("[deloxy-de] super -> start menu");
                self.menu_open = !self.menu_open;
                let (m, _) = self.menu_rows();
                let sr = self.start_rect();
                self.add_damage(sr);
                self.add_damage(Rect::new(m.x - 12, m.y - 12, m.w + 24, m.h + 28));
                return;
            }
            if ev.x == 27 {
                if self.ctx.is_some() {
                    self.close_ctx();
                    return;
                }
                if self.menu_open {
                    self.close_menu();
                    return;
                }
                if self.cal_open {
                    self.toggle_calendar();
                    return;
                }
            }
        }
        let fk = self.windows.iter().rev().find(|w| w.focused && !w.minimized).map(|w| w.kind);
        if let Some(Kind::Perms) = fk {
            if ev.value != 0 {
                let n = self.perms.rows.len();
                match ev.code {
                    0x148 => self.perms.sel = Some(self.perms.sel.map_or(0, |i| i.saturating_sub(1))),
                    0x150 => self.perms.sel = Some(self.perms.sel.map_or(0, |i| (i + 1).min(n.saturating_sub(1)))),
                    0x153 => self.perms_action(0),
                    _ => {}
                }
                self.redraw_settings_surfaces();
            }
            return;
        }
        if let Some(Kind::Tasks) = fk {
            if ev.value != 0 {
                let n = self.tasks.rows.len();
                let cur = self.tasks.sel.and_then(|p| self.tasks.rows.iter().position(|r| r.pid == p));
                match ev.code {
                    0x148 => self.tasks.sel = self.tasks.rows.get(cur.map_or(0, |i| i.saturating_sub(1))).map(|r| r.pid),
                    0x150 => self.tasks.sel = self.tasks.rows.get(cur.map_or(0, |i| (i + 1).min(n.saturating_sub(1)))).map(|r| r.pid),
                    0x153 => self.end_selected_task(),
                    _ => {}
                }
                self.redraw_settings_surfaces();
            }
            return;
        }
        if let Some(k @ (Kind::Files | Kind::Viewer)) = fk {
            if ev.value != 0 {
                self.app_key(k, ev.code, ev.x);
            }
            return;
        }
        if let Some(w) = self.windows.iter().rev().find(|w| w.focused && !w.minimized) {
            if w.term.is_some() {
                // Terminal: pressed keys with an ASCII value go to the kernel TTY (the shell reads it).
                if ev.value != 0 && (1..128).contains(&ev.x) {
                    crate::tty::push_input(&[ev.x as u8]);
                }
            } else if w.kind == Kind::Client {
                w.send(WmMsg::new(S_KEY, w.id, ev.x, ev.code as i32, ev.value, 0));
            }
        }
    }

    // ------------------------------------------------------------ render ----

    fn clock_strings(&self) -> (String, String) {
        match crate::time::wall_clock() {
            Some(c) => {
                let date = alloc::format!("{} {}", c.day, MONTHS[(c.month as usize - 1).min(11)]);
                if self.theme.clock12 {
                    let (h, ap) = (if c.hour % 12 == 0 { 12 } else { c.hour % 12 }, if c.hour >= 12 { "PM" } else { "AM" });
                    (alloc::format!("{}:{:02} {}", h, c.min, ap), date)
                } else {
                    (alloc::format!("{:02}:{:02}", c.hour, c.min), date)
                }
            }
            None => {
                let up = crate::time::uptime_ms() / 1000;
                (alloc::format!("{:02}:{:02}", up / 60 % 100, up % 60), String::from("uptime"))
            }
        }
    }

    fn compose(&mut self) {
        let d = self.damage;
        if d.is_empty() {
            return;
        }
        self.damage = Rect::new(0, 0, 0, 0);
        let (sw, sh) = (self.sw, self.sh);
        let (cx, cy) = (self.cx, self.cy);
        let pal = self.pal;
        let th = self.theme;
        let rad = th.radius();
        let tb = self.taskbar_rect();
        let start = self.start_rect();
        let (menu_rect, menu_rows) = self.menu_rows();
        let clock = self.clock_strings();
        let wc = if self.cal_open { crate::time::wall_clock() } else { None };
        let cal_r = self.cal_rect();
        let toast_area = self.toast_area();
        let toasts = self.toasts.clone();
        let ctx_r = self.ctx_rect();
        let order = self.task_order();
        let task_rects: Vec<Rect> = (0..order.len()).map(|i| self.task_btn_rect(i)).collect();
        let icon_cells: Vec<Rect> = (0..ICONS.len()).map(|i| self.icon_cell(i)).collect();
        let (tray, clock_r) = (self.tray_rect(), self.clock_rect());
        let (has_nic, disk_ok) = (crate::net::has_nic(), crate::store::state() == crate::store::State::Ready);
        {
            let mut s = Surface::new(&mut self.back, sw, sh, sw);
            s.set_clip(d);
            s.blit(d.x, d.y, &self.wall, sw, sh, sw, d);

            // desktop icons
            for (i, (l, name)) in ICONS.iter().enumerate() {
                let cell = icon_cells[i];
                if cell.intersect(&d).is_empty() {
                    continue;
                }
                if self.hover == Hover::Icon(i) {
                    s.fill_round_alpha(cell, rad.max(4), rgb(255, 255, 255), 38);
                }
                draw_icon(&mut s, *l, Rect::new(cell.x + 18, cell.y + 6, 48, 48), &pal, th.accent, rad.max(6));
                let t = name.as_bytes();
                let tx = cell.x + (cell.w - Surface::text_width(t.len())) / 2;
                s.draw_text(tx + 1, cell.y + 60, t, 0, None);
                s.draw_text(tx, cell.y + 59, t, rgb(250, 252, 255), None);
            }

            // windows
            for w in self.windows.iter().filter(|w| !w.minimized) {
                let o = w.outer();
                let grown = Rect::new(o.x - 12, o.y - 12, o.w + 24, o.h + 28);
                if grown.intersect(&d).is_empty() {
                    continue;
                }
                if th.shadow > 0 {
                    let base = if th.shadow == 2 { pal.shadow * 2 } else { pal.shadow };
                    s.shadow(o, 10, 4, if w.focused { base } else { base * 2 / 3 });
                }
                let border = if w.focused { mix(pal.border, th.accent, 90) } else { pal.border };
                s.fill_round_top(o, rad, border);
                let (t0, t1, tc) = if w.focused { (pal.title_top, pal.title_bot, pal.title_text) } else { (pal.title_idle_top, pal.title_idle_bot, pal.title_text_idle) };
                if th.flat_titles {
                    s.fill_round_top(w.title_bar(), (rad - 1).max(0), t1);
                } else {
                    s.fill_round_top_gradient(w.title_bar(), (rad - 1).max(0), t0, t1);
                }
                let maxc = ((w.w - 2 * (BTN_W + 8) - 20) / 8).max(0) as usize;
                let t = w.title.as_bytes();
                s.draw_text(w.x + 12, w.y + 6, &t[..t.len().min(maxc)], tc, None);
                let mb = w.min_box();
                s.fill_round_alpha(mb, rad.min(6), rgb(255, 255, 255), if w.focused { 46 } else { 24 });
                s.fill_rect(Rect::new(mb.x + 6, mb.y + 12, mb.w - 12, 2), tc);
                let cb = w.close_box();
                s.fill_round(cb, rad.min(6), if w.focused { rgb(214, 68, 68) } else { mix(pal.title_idle_bot, rgb(214, 68, 68), 90) });
                s.draw_char(cb.x + (BTN_W - 8) / 2, cb.y + 1, b'x', rgb(255, 255, 255), None);
                // SAFETY: `buf` is a live kernel view of w*h pixels owned by `_bufmem`.
                let src = unsafe { core::slice::from_raw_parts(w.buf, (w.w * w.h) as usize) };
                s.blit(w.content().x, w.content().y, src, w.w, w.h, w.w, Rect::new(0, 0, w.w, w.h));
            }

            // taskbar
            let tb_grown = Rect::new(tb.x - 12, tb.y - 12, tb.w + 24, tb.h + 24);
            if !tb_grown.intersect(&d).is_empty() {
                let alpha = if th.glass { 190 } else { 255 };
                if th.dock {
                    s.shadow(tb, 8, 3, pal.shadow);
                    s.fill_round_alpha(tb, 12, pal.panel, alpha);
                    // 1px outline (straight edges only; the rounded corners stay soft)
                    s.fill_rect(Rect::new(tb.x + 12, tb.y, tb.w - 24, 1), pal.panel_line);
                    s.fill_rect(Rect::new(tb.x + 12, tb.bottom() - 1, tb.w - 24, 1), pal.panel_line);
                    s.fill_rect(Rect::new(tb.x, tb.y + 12, 1, tb.h - 24), pal.panel_line);
                    s.fill_rect(Rect::new(tb.right() - 1, tb.y + 12, 1, tb.h - 24), pal.panel_line);
                } else {
                    s.fill_rect_alpha(tb, pal.panel, alpha);
                    let line = if th.taskbar_top { Rect::new(0, tb.bottom() - 1, sw, 1) } else { Rect::new(0, tb.y, sw, 1) };
                    s.fill_rect(line, pal.panel_line);
                }
                // start button
                let hov = self.hover == Hover::Start || self.menu_open;
                let (g0, g1) = (mix(th.accent, rgb(255, 255, 255), if hov { 70 } else { 36 }), mix(th.accent, 0, 30));
                s.fill_round_gradient(start, rad.min(8), g0, g1);
                s.draw_text(start.x + 12, start.y + (start.h - 16) / 2, b"Deloxy", rgb(255, 255, 255), None);
                s.fill_rect(Rect::new(start.x + 78, start.y + 10, 10, 2), rgb(255, 255, 255));
                s.fill_rect(Rect::new(start.x + 78, start.y + 14, 10, 2), rgb(255, 255, 255));
                s.fill_rect(Rect::new(start.x + 78, start.y + 18, 10, 2), rgb(255, 255, 255));
                for (i, id) in order.iter().enumerate() {
                    let Some(w) = self.windows.iter().find(|w| w.id == *id) else { continue };
                    let r = task_rects[i];
                    let active = w.focused && !w.minimized;
                    let hov = self.hover == Hover::Task(*id);
                    s.fill_round(r, rad.min(6), if active || hov { pal.button_hover } else { pal.button });
                    if active {
                        s.fill_rect(Rect::new(r.x + 8, r.bottom() - 3, r.w - 16, 2), th.accent);
                    }
                    let t = w.title.as_bytes();
                    s.draw_text(r.x + 10, r.y + (r.h - 16) / 2, &t[..t.len().min(15)], if w.minimized { pal.text_dim } else { pal.text }, None);
                }
                // tray: network + disk status, clock
                let ny = tray.y + (tray.h - 14) / 2;
                let nc = if has_nic { th.accent } else { pal.text_dim };
                for b in 0..3 {
                    s.fill_rect(Rect::new(tray.x + 4 + b * 6, ny + 10 - b * 4, 4, 4 + b * 4), nc);
                }
                let dc = if disk_ok { th.accent } else { pal.text_dim };
                s.fill_round(Rect::new(tray.x + 30, ny + 2, 16, 12), 3, dc);
                s.fill_rect(Rect::new(tray.x + 33, ny + 4, 10, 2), pal.panel);
                s.fill_rect(Rect::new(tray.x + 33, ny + 8, 10, 2), pal.panel);
                let tw = Surface::text_width(clock.0.len());
                s.draw_text(clock_r.x + clock_r.w - tw, clock_r.y + 3, clock.0.as_bytes(), pal.text, None);
                let dw = Surface::text_width(clock.1.len());
                s.draw_text(clock_r.x + clock_r.w - dw, clock_r.y + 19, clock.1.as_bytes(), pal.text_dim, None);
            }

            // start menu
            if self.menu_open && !Rect::new(menu_rect.x - 12, menu_rect.y - 12, menu_rect.w + 24, menu_rect.h + 28).intersect(&d).is_empty() {
                s.shadow(menu_rect, 10, 4, pal.shadow);
                s.fill_round(menu_rect, rad, pal.panel_line);
                s.fill_round(Rect::new(menu_rect.x + 1, menu_rect.y + 1, menu_rect.w - 2, menu_rect.h - 2), (rad - 1).max(0), pal.menu_bg);
                let mut cyy = menu_rect.y + 6;
                for (i, (l, name)) in MENU.iter().enumerate() {
                    if l.is_none() {
                        s.fill_rect(Rect::new(menu_rect.x + 14, cyy + 4, menu_rect.w - 28, 1), pal.panel_line);
                        cyy += 10;
                        continue;
                    }
                    let r = Rect::new(menu_rect.x + 6, cyy, menu_rect.w - 12, 30);
                    let hot = self.hover == Hover::Menu(i);
                    if hot {
                        s.fill_round(r, rad.min(6), pal.menu_hover);
                    }
                    let c = if hot { rgb(255, 255, 255) } else { pal.text };
                    let li = match l.unwrap() {
                        Launch::Terminal => b">_",
                        Launch::Files => b"[]",
                        Launch::Tasks => b"%%",
                        Launch::Perms => b"!!",
                        Launch::Monitor => b"|:",
                        Launch::Anim => b"~~",
                        Launch::Bars => b"==",
                        Launch::Settings => b"**",
                        Launch::Restart => b"<>",
                        Launch::Shutdown => b"()",
                    };
                    s.draw_text(r.x + 10, r.y + 7, li, if hot { c } else { th.accent }, None);
                    s.draw_text(r.x + 40, r.y + 7, name.as_bytes(), c, None);
                    cyy += 30;
                }
            }

            // toasts
            if !toast_area.intersect(&d).is_empty() || !Rect::new(toast_area.x - 12, toast_area.y - 12, toast_area.w + 24, toast_area.h + 24).intersect(&d).is_empty() {
                for (i, (msg, _)) in toasts.iter().enumerate() {
                    let r = Rect::new(toast_area.x, toast_area.y + i as i32 * 56, 300, 46);
                    s.shadow(r, 8, 3, pal.shadow);
                    s.fill_round(r, rad.max(4), pal.menu_bg);
                    s.fill_round(Rect::new(r.x, r.y, 6, r.h), rad.min(4), th.accent);
                    let b = msg.as_bytes();
                    s.draw_text(r.x + 18, r.y + 15, &b[..b.len().min(34)], pal.text, None);
                }
            }
            // context menu
            if let Some(cr) = ctx_r {
                if !Rect::new(cr.x - 12, cr.y - 12, cr.w + 24, cr.h + 28).intersect(&d).is_empty() {
                    s.shadow(cr, 10, 4, pal.shadow);
                    s.fill_round(cr, rad, pal.panel_line);
                    s.fill_round(Rect::new(cr.x + 1, cr.y + 1, cr.w - 2, cr.h - 2), (rad - 1).max(0), pal.menu_bg);
                    for (i, name) in CTX_ITEMS.iter().enumerate() {
                        let rr = Rect::new(cr.x + 6, cr.y + 6 + i as i32 * 30, cr.w - 12, 30);
                        let hot = self.hover == Hover::Ctx(i);
                        if hot {
                            s.fill_round(rr, rad.min(6), pal.menu_hover);
                        }
                        s.draw_text(rr.x + 12, rr.y + 7, name.as_bytes(), if hot { rgb(255, 255, 255) } else { pal.text }, None);
                    }
                }
            }
            if self.cal_open {
                let cr_ = cal_r;
                if !Rect::new(cr_.x - 12, cr_.y - 12, cr_.w + 24, cr_.h + 28).intersect(&d).is_empty() {
                    draw_calendar(&mut s, cr_, &pal, &th, wc);
                }
            }

            // cursor
            let cr = Rect::new(cx, cy, 16, 16);
            if !cr.intersect(&d).is_empty() {
                for (row, line) in ARROW.iter().enumerate() {
                    for (col, ch) in line.bytes().enumerate() {
                        match ch {
                            b'X' => s.put(cx + col as i32, cy + row as i32, rgb(0, 0, 0)),
                            b'.' => s.put(cx + col as i32, cy + row as i32, rgb(255, 255, 255)),
                            _ => {}
                        }
                    }
                }
            }
        }
        // SAFETY: `d` was clipped to the screen and `back` is sw*sh pixels.
        unsafe { self.fb.present(&self.back, sw as usize, d.x as usize, d.y as usize, d.w as usize, d.h as usize) };
    }

    fn tick_clock(&mut self) {
        let sec = crate::time::uptime_ms() / 1000;
        if sec != self.last_clock_sec {
            self.last_clock_sec = sec;
            let (c, t) = (self.clock_rect(), self.tray_rect());
            self.add_damage(c);
            self.add_damage(t);
            self.expire_toasts();
            if self.windows.iter().any(|w| w.kind == Kind::Perms) {
                self.refresh_perms();
                self.redraw_settings_surfaces();
            }
            if self.windows.iter().any(|w| w.kind == Kind::Tasks) {
                self.refresh_tasks();
                self.redraw_settings_surfaces();
            }
            if self.windows.iter().any(|w| w.kind == Kind::Files) {
                let g = crate::store::with(|s| s.stats().generation).unwrap_or(0);
                if g != self.files.gen {
                    self.refresh_files();
                    self.redraw_settings_surfaces();
                }
            }
            self.load_theme(); // hot-reload de.conf when the store changed (e.g. `save de.conf accent=orange` in the shell)
        }
    }
}

fn draw_icon(s: &mut Surface, l: Launch, r: Rect, pal: &Palette, accent: u32, rad: i32) {
    match l {
        Launch::Terminal => {
            s.fill_round(r, rad, rgb(14, 17, 22));
            s.fill_round_alpha(Rect::new(r.x, r.y, r.w, 10), rad, rgb(255, 255, 255), 24);
            draw_glyph_scaled(s, r.x + 6, r.y + 12, b'>', 2, rgb(110, 230, 140));
            s.fill_rect(Rect::new(r.x + 26, r.y + 36, 14, 3), rgb(110, 230, 140));
        }
        Launch::Files => {
            // folder
            s.fill_round(Rect::new(r.x + 2, r.y + 10, 20, 8), 3, mix(rgb(240, 190, 80), 0, 40));
            s.fill_round(Rect::new(r.x + 2, r.y + 14, r.w - 4, r.h - 18), rad.min(8), rgb(244, 200, 92));
            s.fill_round_alpha(Rect::new(r.x + 2, r.y + 14, r.w - 4, 10), rad.min(8), rgb(255, 255, 255), 50);
        }
        Launch::Tasks => {
            s.fill_round(r, rad, rgb(30, 36, 46));
            s.fill_round_alpha(Rect::new(r.x, r.y, r.w, 10), rad, rgb(255, 255, 255), 24);
            for i in 0..4 {
                s.fill_rect(Rect::new(r.x + 8, r.y + 14 + i * 8, 6, 4), rgb(110, 230, 140));
                s.fill_rect(Rect::new(r.x + 18, r.y + 14 + i * 8, 22 - (i * 4), 4), rgb(200, 206, 216));
            }
        }
        Launch::Monitor => {
            s.fill_round(r, rad, mix(accent, 0, 120));
            s.fill_round_alpha(Rect::new(r.x, r.y, r.w, 10), rad, rgb(255, 255, 255), 30);
            for i in 0..5 {
                let h = 8 + i * 6;
                s.fill_rect(Rect::new(r.x + 7 + i * 8, r.bottom() - 7 - h, 5, h), rgb(240, 244, 250));
            }
        }
        _ => {
            s.fill_round(r, rad, pal.widget);
            s.fill_round_alpha(Rect::new(r.x, r.y, r.w, 10), rad, rgb(255, 255, 255), 30);
            for i in 0..3 {
                let y = r.y + 12 + i * 11;
                s.fill_rect(Rect::new(r.x + 8, y + 3, r.w - 16, 3), pal.text_dim);
                s.fill_round(Rect::new(r.x + 10 + ((i * 17 + 9) % 24), y, 8, 9), 3, accent);
            }
        }
    }
}

fn draw_settings(s: &mut Surface, t: &Theme, pal: &Palette, note: &str) {
    s.fill_rect(Rect::new(0, 0, SET_W, SET_H), pal.win_bg);
    s.draw_text(16, 10, b"Appearance", pal.text, None);
    s.fill_rect(Rect::new(16, 28, SET_W - 32, 1), pal.widget);
    let rad = t.radius().min(8);
    let label = |s: &mut Surface, y: i32, txt: &[u8]| {
        s.draw_text(16, y, txt, pal.text_dim, None);
    };
    label(s, 42, b"Theme");
    label(s, 82, b"Accent");
    label(s, 118, b"Wallpaper");
    label(s, 212, b"Taskbar");
    label(s, 248, b"Corners");
    label(s, 284, b"Clock");
    label(s, 320, b"Panel");
    label(s, 356, b"Panel look");
    label(s, 392, b"Titles");
    label(s, 428, b"Shadows");
    for it in settings_layout(t) {
        match it.look {
            Look::Toggle(txt) => {
                let bg = if it.selected { t.accent } else { pal.widget };
                s.fill_round(it.rect, rad.min(6), bg);
                s.draw_text_centered(it.rect, txt.as_bytes(), if it.selected { rgb(255, 255, 255) } else { pal.text });
            }
            Look::Swatch(c) => {
                if it.selected {
                    s.fill_round(Rect::new(it.rect.x - 3, it.rect.y - 3, it.rect.w + 6, it.rect.h + 6), rad.min(8) + 2, pal.text);
                }
                s.fill_round(it.rect, rad.min(8), c);
            }
            Look::Thumb(k) => {
                if it.selected {
                    s.fill_round(Rect::new(it.rect.x - 3, it.rect.y - 3, it.rect.w + 6, it.rect.h + 6), rad.min(8) + 2, t.accent);
                }
                let r = it.rect;
                for y in 0..r.h {
                    for x in 0..r.w {
                        s.put(r.x + x, r.y + y, theme::wallpaper_px(k, x, y, r.w, r.h));
                    }
                }
                s.draw_text_centered(Rect::new(r.x, r.bottom() - 18, r.w, 16), theme::WALLPAPERS[k as usize].as_bytes(), rgb(255, 255, 255));
            }
        }
    }
    s.draw_text(16, SET_H - 26, note.as_bytes(), pal.text_dim, None);
    s.draw_text(16, SET_H - 44, b"or: de.conf wallpaper=file:NAME", pal.text_dim, None);
}

/// Compositor thread entry. Holds the boot console on screen briefly, then takes over.
pub fn run() -> ! {
    let Some(info) = fb::info() else {
        log::warn!("[deloxy-de] no framebuffer: compositor not started");
        task::sched::exit_thread();
    };
    task::sleep_ms(1500); // let the boot log stay visible
    fb::console::disable();
    let mut srv = Server::new(info);
    srv.load_theme();
    let (sw, sh) = (srv.sw, srv.sh);
    let (y0, y1) = srv.work_y();
    srv.spawn_app("anim", "anim", 10, 140, y0 + 60, 320, 200);
    srv.spawn_app("diag", "diag", 11, (sw / 2).max(480), y0 + 60, 380, 230);
    srv.spawn_app("bars", "bars", 12, 200, (sh / 2).min(sh - 300).max(y0 + 20), 320, 200);
    srv.spawn_terminal((sw - 660).max(20), (y1 - 424).max(y0 + 10));
    log::info!("[deloxy-de] desktop ready ({}x{})", sw, sh);
    loop {
        srv.handle_input();
        srv.pump_terminal();
        srv.poll_clients();
        srv.reap_dead();
        srv.tick_clock();
        srv.compose();
        task::sleep_ms(8);
    }
}

fn fmt_size(n: u64) -> String {
    if n < 1024 { alloc::format!("{} B", n) } else if n < 1024 * 1024 { alloc::format!("{}.{} KiB", n / 1024, n % 1024 * 10 / 1024) } else { alloc::format!("{}.{} MiB", n >> 20, (n & 0xFFFFF) * 10 >> 20) }
}

fn draw_files(s: &mut Surface, t: &Theme, pal: &Palette, f: &FilesState) {
    s.fill_rect(Rect::new(0, 0, FILES_W, FILES_H), pal.win_bg);
    let rad = t.radius().min(6);
    for (r, txt) in [(files_open_btn(), "Open"), (files_del_btn(), "Delete"), (files_refresh_btn(), "Refresh")] {
        s.fill_round(r, rad, pal.widget);
        s.draw_text_centered(r, txt.as_bytes(), pal.text);
    }
    s.draw_text(12, 38, b"Name", pal.text_dim, None);
    s.draw_text(300, 38, b"Size", pal.text_dim, None);
    s.draw_text(392, 38, b"Where", pal.text_dim, None);
    s.fill_rect(Rect::new(8, 55, 440, 1), pal.widget);
    for i in 0..FILE_ROWS {
        let idx = f.scroll + i;
        let Some(e) = f.entries.get(idx) else { break };
        let r = files_row_rect(i);
        let sel = f.sel == Some(idx);
        if sel {
            s.fill_round(r, rad, t.accent);
        }
        let fg = if sel { rgb(255, 255, 255) } else { pal.text };
        let nm = e.name.as_bytes();
        s.draw_text(14, r.y + 3, &nm[..nm.len().min(34)], fg, None);
        s.draw_text(300, r.y + 3, fmt_size(e.size).as_bytes(), fg, None);
        s.draw_text(392, r.y + 3, if e.store { b"store" } else { b"system" }, if sel { fg } else { pal.text_dim }, None);
    }
    for (r, g) in [(files_up_btn(), b"^"), (files_down_btn(), b"v")] {
        s.fill_round(r, rad, pal.widget);
        s.draw_text_centered(r, g, pal.text);
    }
    let st = f.status.as_bytes();
    s.draw_text(12, FILES_H - 22, &st[..st.len().min(56)], pal.text_dim, None);
}

fn draw_viewer(s: &mut Surface, pal: &Palette, v: &ViewerState) {
    s.fill_rect(Rect::new(0, 0, VIEW_W, VIEW_H), pal.win_bg);
    for i in 0..VIEW_ROWS {
        let Some(l) = v.lines.get(v.scroll + i) else { break };
        s.draw_text(10, 6 + i as i32 * 16, l.as_bytes(), pal.text, None);
    }
    let last = (v.scroll + VIEW_ROWS).min(v.lines.len());
    let st = alloc::format!("{}  lines {}-{} of {}   (j/k, space/b)", v.title, (v.scroll + 1).min(v.lines.len()), last, v.lines.len());
    s.fill_rect(Rect::new(0, VIEW_H - 24, VIEW_W, 1), pal.widget);
    let b = st.as_bytes();
    s.draw_text(10, VIEW_H - 20, &b[..b.len().min(64)], pal.text_dim, None);
}

fn days_in_month(y: u16, m: u8) -> u8 {
    match m {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        _ => if (y % 4 == 0 && y % 100 != 0) || y % 400 == 0 { 29 } else { 28 },
    }
}

/// 0 = Monday .. 6 = Sunday (Sakamoto's algorithm).
fn weekday_mon0(y: u16, m: u8, d: u8) -> usize {
    let t = [0i32, 3, 2, 5, 0, 3, 5, 1, 4, 6, 2, 4];
    let yy = y as i32 - (m < 3) as i32;
    let dow = (yy + yy / 4 - yy / 100 + yy / 400 + t[(m as usize - 1).min(11)] + d as i32) % 7; // 0 = Sunday
    ((dow + 6) % 7) as usize
}

fn draw_calendar(s: &mut Surface, r: Rect, pal: &Palette, th: &Theme, wc: Option<crate::time::WallClock>) {
    let rad = th.radius();
    s.shadow(r, 10, 4, pal.shadow);
    s.fill_round(r, rad, pal.panel_line);
    s.fill_round(Rect::new(r.x + 1, r.y + 1, r.w - 2, r.h - 2), (rad - 1).max(0), pal.menu_bg);
    let Some(c) = wc else {
        s.draw_text_centered(r, b"clock unavailable", pal.text_dim);
        return;
    };
    let title = alloc::format!("{} {}", MONTHS_LONG[(c.month as usize - 1).min(11)], c.year);
    s.draw_text_centered(Rect::new(r.x, r.y + 8, r.w, 20), title.as_bytes(), pal.text);
    let days = ["Mo", "Tu", "We", "Th", "Fr", "Sa", "Su"];
    for (i, d) in days.iter().enumerate() {
        s.draw_text(r.x + 10 + i as i32 * 30 + 7, r.y + 40, d.as_bytes(), pal.text_dim, None);
    }
    let first = weekday_mon0(c.year, c.month, 1);
    for day in 1..=days_in_month(c.year, c.month) {
        let idx = first + day as usize - 1;
        let (col, row) = ((idx % 7) as i32, (idx / 7) as i32);
        let cell = Rect::new(r.x + 10 + col * 30, r.y + 62 + row * 28, 28, 26);
        let today = day == c.day;
        if today {
            s.fill_round(cell, 13, th.accent);
        }
        let txt = alloc::format!("{}", day);
        s.draw_text_centered(cell, txt.as_bytes(), if today { rgb(255, 255, 255) } else if col >= 5 { pal.text_dim } else { pal.text });
    }
}

const MONTHS_LONG: [&str; 12] = ["January", "February", "March", "April", "May", "June", "July", "August", "September", "October", "November", "December"];

fn draw_tasks(s: &mut Surface, t: &Theme, pal: &Palette, st: &TasksState) {
    s.fill_rect(Rect::new(0, 0, TASKS_W, TASKS_H), pal.win_bg);
    let rad = t.radius().min(6);
    for (r, txt) in [(Rect::new(8, 6, 110, 24), "End process"), (Rect::new(126, 6, 76, 24), "Refresh")] {
        s.fill_round(r, rad, pal.widget);
        s.draw_text_centered(r, txt.as_bytes(), pal.text);
    }
    for (x, h) in [(12, "PID"), (60, "Name"), (292, "Thr"), (336, "Memory"), (424, "Type")] {
        s.draw_text(x, 38, h.as_bytes(), pal.text_dim, None);
    }
    s.fill_rect(Rect::new(8, 55, 480, 1), pal.widget);
    for i in 0..TASK_ROWS {
        let Some(r) = st.rows.get(i) else { break };
        let rr = Rect::new(8, 58 + i as i32 * 22, 480, 22);
        let sel = st.sel == Some(r.pid);
        if sel {
            s.fill_round(rr, rad, t.accent);
        }
        let fg = if sel { rgb(255, 255, 255) } else { pal.text };
        s.draw_text(12, rr.y + 3, alloc::format!("{}", r.pid).as_bytes(), fg, None);
        let nm = r.name.as_bytes();
        s.draw_text(60, rr.y + 3, &nm[..nm.len().min(28)], fg, None);
        s.draw_text(292, rr.y + 3, alloc::format!("{}", r.thr).as_bytes(), fg, None);
        s.draw_text(336, rr.y + 3, fmt_size(r.mem_kib as u64 * 1024).as_bytes(), fg, None);
        s.draw_text(424, rr.y + 3, r.abi.as_bytes(), if sel { fg } else { pal.text_dim }, None);
    }
    let total: u64 = st.rows.iter().map(|r| r.mem_kib as u64).sum();
    let line = alloc::format!("{} processes, {} in use", st.rows.len(), fmt_size(total * 1024));
    s.draw_text(12, TASKS_H - 40, line.as_bytes(), pal.text, None);
    let b = st.status.as_bytes();
    s.draw_text(12, TASKS_H - 22, &b[..b.len().min(60)], pal.text_dim, None);
}

fn draw_perms(s: &mut Surface, t: &Theme, pal: &Palette, st: &PermsState) {
    s.fill_rect(Rect::new(0, 0, PERMS_W, PERMS_H), pal.win_bg);
    let rad = t.radius().min(6);
    for (r, txt) in [(Rect::new(8, 6, 70, 24), "Revoke"), (Rect::new(86, 6, 60, 24), "Allow"), (Rect::new(154, 6, 60, 24), "Deny"), (Rect::new(222, 6, 60, 24), "Full"), (Rect::new(290, 6, 70, 24), "Limits"), (Rect::new(368, 6, 70, 24), "Refresh")] {
        s.fill_round(r, rad, pal.widget);
        s.draw_text_centered(r, txt.as_bytes(), pal.text);
    }
    for (x, h) in [(12, "Program"), (212, "Access"), (404, "Limits"), (488, "Decision")] {
        s.draw_text(x, 38, h.as_bytes(), pal.text_dim, None);
    }
    s.fill_rect(Rect::new(8, 55, 540, 1), pal.widget);
    if st.rows.is_empty() {
        s.draw_text(12, 70, b"No stored decisions. Programs are asked when they first use files or the network.", pal.text_dim, None);
    }
    for i in 0..PERM_ROWS {
        let Some(r) = st.rows.get(i) else { break };
        let rr = Rect::new(8, 58 + i as i32 * 22, 540, 22);
        let sel = st.sel == Some(i);
        if sel {
            s.fill_round(rr, rad, t.accent);
        }
        let fg = if sel { rgb(255, 255, 255) } else { pal.text };
        let nm = r.name.as_bytes();
        s.draw_text(12, rr.y + 3, &nm[..nm.len().min(24)], fg, None);
        let (what, limits, allowed) = match r.net {
            Some(n) => {
                let what = crate::perm::describe(&n);
                let lim = if n.secs == 0 && n.kib == 0 { String::from("none") } else { alloc::format!("{}s/{}M", n.secs, n.kib / 1024) };
                (what, lim, r.read)
            }
            None => (String::from(if r.write { "files (read+write)" } else if r.read { "files (read only)" } else { "files" }), String::from("-"), r.read),
        };
        s.draw_text(212, rr.y + 3, &what.as_bytes()[..what.len().min(23)], fg, None);
        s.draw_text(404, rr.y + 3, &limits.as_bytes()[..limits.len().min(10)], if sel { fg } else { pal.text_dim }, None);
        let (txt, col) = if allowed { ("ALLOWED", if sel { fg } else { rgb(110, 210, 140) }) } else { ("DENIED", if sel { fg } else { rgb(230, 110, 110) }) };
        s.draw_text(488, rr.y + 3, txt.as_bytes(), col, None);
    }
    let b = st.status.as_bytes();
    s.draw_text(12, PERMS_H - 22, &b[..b.len().min(66)], pal.text_dim, None);
}
