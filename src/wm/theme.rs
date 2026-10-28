//! deloxy-de theme engine: everything a user can customise, its palette, wallpapers and the `de.conf` text format.
//!
//! `de.conf` is plain text, one `key=value` per line OR several pairs separated by spaces (so it can be edited
//! from the shell: `save de.conf theme=light accent=orange wallpaper=dusk taskbar=top corners=round clock=12`).
//! Unknown keys/values are ignored, so a half-valid file still applies what it can.

use alloc::string::String;

use crate::gfx::draw::{mix, rgb};

pub const ACCENTS: [(&str, u32); 8] = [
    ("blue", rgb(52, 101, 196)),
    ("teal", rgb(18, 132, 138)),
    ("green", rgb(44, 140, 88)),
    ("orange", rgb(204, 100, 28)),
    ("red", rgb(196, 58, 58)),
    ("pink", rgb(190, 66, 134)),
    ("purple", rgb(122, 86, 196)),
    ("gray", rgb(92, 102, 116)),
];

pub const WALLPAPERS: [&str; 4] = ["midnight", "aurora", "dusk", "graphite"];

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Theme {
    pub dark: bool,
    pub accent: u32,
    pub wallpaper: u8,
    pub taskbar_top: bool,
    pub round: bool,
    pub clock12: bool,
    /// floating, rounded dock instead of a full-width bar
    pub dock: bool,
    /// translucent panel/dock (blends with what is behind it)
    pub glass: bool,
    pub flat_titles: bool,
    /// 0 off, 1 soft, 2 strong
    pub shadow: u8,
    /// custom wallpaper: name of a P6 PPM in the initramfs or store (empty = built-in wallpaper)
    pub wall_file: [u8; 32],
}

impl Theme {
    pub const fn default() -> Theme {
        Theme { dark: true, accent: ACCENTS[0].1, wallpaper: 0, taskbar_top: false, round: true, clock12: false, dock: false, glass: false, flat_titles: false, shadow: 1, wall_file: [0; 32] }
    }

    pub fn wall_file_str(&self) -> &str {
        let n = self.wall_file.iter().position(|&b| b == 0).unwrap_or(32);
        core::str::from_utf8(&self.wall_file[..n]).unwrap_or("")
    }

    pub fn radius(&self) -> i32 {
        if self.round { 8 } else { 0 }
    }

    pub fn palette(&self) -> Palette {
        let a = self.accent;
        if self.dark {
            Palette {
                border: rgb(6, 8, 12),
                title_top: mix(a, rgb(255, 255, 255), 28),
                title_bot: mix(a, 0, 36),
                title_idle_top: rgb(70, 78, 92),
                title_idle_bot: rgb(52, 58, 70),
                title_text: rgb(255, 255, 255),
                title_text_idle: rgb(190, 198, 210),
                panel: rgb(17, 21, 29),
                panel_line: mix(rgb(17, 21, 29), a, 90),
                button: rgb(36, 43, 55),
                button_hover: rgb(52, 61, 76),
                text: rgb(232, 236, 242),
                text_dim: rgb(150, 160, 175),
                menu_bg: rgb(26, 31, 41),
                menu_hover: a,
                win_bg: rgb(30, 35, 45),
                widget: rgb(46, 54, 68),
                shadow: 110,
            }
        } else {
            Palette {
                border: rgb(150, 158, 170),
                title_top: mix(a, rgb(255, 255, 255), 40),
                title_bot: mix(a, rgb(255, 255, 255), 8),
                title_idle_top: rgb(232, 236, 242),
                title_idle_bot: rgb(212, 218, 227),
                title_text: rgb(255, 255, 255),
                title_text_idle: rgb(70, 78, 92),
                panel: rgb(238, 241, 246),
                panel_line: mix(rgb(238, 241, 246), a, 120),
                button: rgb(214, 220, 229),
                button_hover: rgb(196, 204, 216),
                text: rgb(28, 33, 42),
                text_dim: rgb(98, 108, 124),
                menu_bg: rgb(248, 249, 252),
                menu_hover: a,
                win_bg: rgb(244, 246, 250),
                widget: rgb(222, 227, 235),
                shadow: 70,
            }
        }
    }

    /// Parse `de.conf` text on top of `self` (unknown / invalid entries leave the current value).
    pub fn apply_text(&mut self, text: &str) {
        for tok in text.split(|c: char| c.is_whitespace() || c == ';') {
            let Some((k, v)) = tok.split_once('=') else { continue };
            let v = v.trim();
            match k.trim() {
                "theme" => match v {
                    "dark" => self.dark = true,
                    "light" => self.dark = false,
                    _ => {}
                },
                "accent" => {
                    if let Some(c) = ACCENTS.iter().find(|a| a.0 == v) {
                        self.accent = c.1;
                    } else if let Some(h) = v.strip_prefix('#') {
                        if h.len() == 6 {
                            if let Ok(n) = u32::from_str_radix(h, 16) {
                                self.accent = n;
                            }
                        }
                    }
                }
                "wallpaper" => {
                    if let Some(f) = v.strip_prefix("file:") {
                        if crate::store::valid_name(f) && f.len() < 32 {
                            self.wall_file = [0; 32];
                            self.wall_file[..f.len()].copy_from_slice(f.as_bytes());
                        }
                    } else if let Some(i) = WALLPAPERS.iter().position(|w| *w == v) {
                        self.wallpaper = i as u8;
                        self.wall_file = [0; 32];
                    }
                }
                "panel" => match v {
                    "dock" => self.dock = true,
                    "bar" => self.dock = false,
                    _ => {}
                },
                "glass" => match v {
                    "on" => self.glass = true,
                    "off" => self.glass = false,
                    _ => {}
                },
                "titles" => match v {
                    "flat" => self.flat_titles = true,
                    "gradient" => self.flat_titles = false,
                    _ => {}
                },
                "shadows" => match v {
                    "off" => self.shadow = 0,
                    "soft" => self.shadow = 1,
                    "strong" => self.shadow = 2,
                    _ => {}
                },
                "taskbar" => match v {
                    "top" => self.taskbar_top = true,
                    "bottom" => self.taskbar_top = false,
                    _ => {}
                },
                "corners" => match v {
                    "round" => self.round = true,
                    "square" => self.round = false,
                    _ => {}
                },
                "clock" => match v {
                    "12" => self.clock12 = true,
                    "24" => self.clock12 = false,
                    _ => {}
                },
                _ => {}
            }
        }
    }

    pub fn to_text(&self) -> String {
        let accent = match ACCENTS.iter().find(|a| a.1 == self.accent) {
            Some(a) => String::from(a.0),
            None => alloc::format!("#{:06x}", self.accent & 0xFF_FFFF),
        };
        let wall = if self.wall_file_str().is_empty() { String::from(WALLPAPERS[(self.wallpaper as usize).min(WALLPAPERS.len() - 1)]) } else { alloc::format!("file:{}", self.wall_file_str()) };
        alloc::format!(
            "theme={}\naccent={}\nwallpaper={}\ntaskbar={}\ncorners={}\nclock={}\npanel={}\nglass={}\ntitles={}\nshadows={}\n",
            if self.dark { "dark" } else { "light" },
            accent,
            wall,
            if self.taskbar_top { "top" } else { "bottom" },
            if self.round { "round" } else { "square" },
            if self.clock12 { "12" } else { "24" },
            if self.dock { "dock" } else { "bar" },
            if self.glass { "on" } else { "off" },
            if self.flat_titles { "flat" } else { "gradient" },
            ["off", "soft", "strong"][(self.shadow as usize).min(2)],
        )
    }
}

#[derive(Clone, Copy)]
pub struct Palette {
    pub border: u32,
    pub title_top: u32,
    pub title_bot: u32,
    pub title_idle_top: u32,
    pub title_idle_bot: u32,
    pub title_text: u32,
    pub title_text_idle: u32,
    pub panel: u32,
    pub panel_line: u32,
    pub button: u32,
    pub button_hover: u32,
    pub text: u32,
    pub text_dim: u32,
    pub menu_bg: u32,
    pub menu_hover: u32,
    pub win_bg: u32,
    pub widget: u32,
    pub shadow: u32,
}

fn lerp3(t: i64, a: (i64, i64, i64), b: (i64, i64, i64)) -> (i64, i64, i64) {
    ((a.0 * (255 - t) + b.0 * t) / 255, (a.1 * (255 - t) + b.1 * t) / 255, (a.2 * (255 - t) + b.2 * t) / 255)
}

fn pack(c: (i64, i64, i64)) -> u32 {
    rgb(c.0.clamp(0, 255) as u8, c.1.clamp(0, 255) as u8, c.2.clamp(0, 255) as u8)
}

/// Colour of wallpaper `kind` at pixel (x, y) of a w*h screen. Integer maths only.
pub fn wallpaper_px(kind: u8, x: i32, y: i32, w: i32, h: i32) -> u32 {
    let (x, y, w, h) = (x as i64, y as i64, (w as i64).max(1), (h as i64).max(1));
    let ty = y * 255 / h;
    match kind {
        1 => {
            // aurora: deep blue-green with two soft glows
            let mut c = lerp3(ty, (8, 16, 36), (6, 34, 48));
            let glow = |cx: i64, cy: i64, r: i64| -> i64 {
                let (dx, dy) = (x - cx, y - cy);
                let d2 = dx * dx + dy * dy;
                (256 - d2 * 256 / (r * r)).max(0)
            };
            let g1 = glow(w / 4, h * 3 / 10, w * 11 / 20);
            let g2 = glow(w * 4 / 5, h * 7 / 10, w / 2);
            c.0 += 20 * g1 / 256 + 70 * g2 / 256 * 2 / 5;
            c.1 += 150 * g1 / 256 / 2 + 70 * g2 / 256 * 2 / 5;
            c.2 += 140 * g1 / 256 / 2 + 180 * g2 / 256 * 2 / 5;
            pack(c)
        }
        2 => {
            // dusk: purple -> magenta -> orange
            let c = if ty < 140 { lerp3(ty * 255 / 140, (38, 28, 82), (148, 58, 112)) } else { lerp3((ty - 140) * 255 / 115, (148, 58, 112), (236, 128, 82)) };
            pack(c)
        }
        3 => {
            // graphite: neutral grey with a soft vignette
            let (dx, dy) = (x - w / 2, y - h / 2);
            let d2 = dx * dx + dy * dy;
            let r = w * 3 / 5;
            let i = (256 - d2 * 256 / (r * r)).max(0);
            pack(lerp3(i * 255 / 256, (24, 27, 32), (58, 64, 74)))
        }
        _ => pack(lerp3(ty, (26, 43, 60), (14, 23, 32))), // midnight
    }
}
