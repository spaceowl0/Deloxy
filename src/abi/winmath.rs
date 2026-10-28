//! Floating-point C library for Windows programs (double and float variants), on the `libm` crate (a Rust port of musl).
//! Float arguments never cross the shim ABI directly: each of these gets a 32-byte user-mode trampoline stub
//! (`nt::FLOAT_OFF`) that moves xmm0/xmm1 into the integer argument registers, makes the syscall, and moves the result
//! from rax back into xmm0. `strtod`/`atof` return doubles the same way; `printf`/`scanf` read doubles from the
//! Win64 variadic integer registers/stack slots (callers duplicate variadic floats there).
use alloc::string::ToString;
use alloc::sync::Arc;
use crate::sys::uaccess::copy_to_user;
use crate::task::Process;
type A = [u64; 4];
fn d(a: u64) -> f64 { f64::from_bits(a) }
fn s(a: u64) -> f32 { f32::from_bits(a as u32) }
fn rd(v: f64) -> u64 { v.to_bits() }
fn rs(v: f32) -> u64 { v.to_bits() as u64 }

pub fn sin_d(_: &Arc<Process>, a: A) -> u64 { rd(libm::sin(d(a[0]))) }
pub fn sin_f(_: &Arc<Process>, a: A) -> u64 { rs(libm::sinf(s(a[0]))) }
pub fn cos_d(_: &Arc<Process>, a: A) -> u64 { rd(libm::cos(d(a[0]))) }
pub fn cos_f(_: &Arc<Process>, a: A) -> u64 { rs(libm::cosf(s(a[0]))) }
pub fn tan_d(_: &Arc<Process>, a: A) -> u64 { rd(libm::tan(d(a[0]))) }
pub fn tan_f(_: &Arc<Process>, a: A) -> u64 { rs(libm::tanf(s(a[0]))) }
pub fn asin_d(_: &Arc<Process>, a: A) -> u64 { rd(libm::asin(d(a[0]))) }
pub fn asin_f(_: &Arc<Process>, a: A) -> u64 { rs(libm::asinf(s(a[0]))) }
pub fn acos_d(_: &Arc<Process>, a: A) -> u64 { rd(libm::acos(d(a[0]))) }
pub fn acos_f(_: &Arc<Process>, a: A) -> u64 { rs(libm::acosf(s(a[0]))) }
pub fn atan_d(_: &Arc<Process>, a: A) -> u64 { rd(libm::atan(d(a[0]))) }
pub fn atan_f(_: &Arc<Process>, a: A) -> u64 { rs(libm::atanf(s(a[0]))) }
pub fn sinh_d(_: &Arc<Process>, a: A) -> u64 { rd(libm::sinh(d(a[0]))) }
pub fn sinh_f(_: &Arc<Process>, a: A) -> u64 { rs(libm::sinhf(s(a[0]))) }
pub fn cosh_d(_: &Arc<Process>, a: A) -> u64 { rd(libm::cosh(d(a[0]))) }
pub fn cosh_f(_: &Arc<Process>, a: A) -> u64 { rs(libm::coshf(s(a[0]))) }
pub fn tanh_d(_: &Arc<Process>, a: A) -> u64 { rd(libm::tanh(d(a[0]))) }
pub fn tanh_f(_: &Arc<Process>, a: A) -> u64 { rs(libm::tanhf(s(a[0]))) }
pub fn asinh_d(_: &Arc<Process>, a: A) -> u64 { rd(libm::asinh(d(a[0]))) }
pub fn asinh_f(_: &Arc<Process>, a: A) -> u64 { rs(libm::asinhf(s(a[0]))) }
pub fn acosh_d(_: &Arc<Process>, a: A) -> u64 { rd(libm::acosh(d(a[0]))) }
pub fn acosh_f(_: &Arc<Process>, a: A) -> u64 { rs(libm::acoshf(s(a[0]))) }
pub fn atanh_d(_: &Arc<Process>, a: A) -> u64 { rd(libm::atanh(d(a[0]))) }
pub fn atanh_f(_: &Arc<Process>, a: A) -> u64 { rs(libm::atanhf(s(a[0]))) }
pub fn exp_d(_: &Arc<Process>, a: A) -> u64 { rd(libm::exp(d(a[0]))) }
pub fn exp_f(_: &Arc<Process>, a: A) -> u64 { rs(libm::expf(s(a[0]))) }
pub fn exp2_d(_: &Arc<Process>, a: A) -> u64 { rd(libm::exp2(d(a[0]))) }
pub fn exp2_f(_: &Arc<Process>, a: A) -> u64 { rs(libm::exp2f(s(a[0]))) }
pub fn expm1_d(_: &Arc<Process>, a: A) -> u64 { rd(libm::expm1(d(a[0]))) }
pub fn expm1_f(_: &Arc<Process>, a: A) -> u64 { rs(libm::expm1f(s(a[0]))) }
pub fn log_d(_: &Arc<Process>, a: A) -> u64 { rd(libm::log(d(a[0]))) }
pub fn log_f(_: &Arc<Process>, a: A) -> u64 { rs(libm::logf(s(a[0]))) }
pub fn log2_d(_: &Arc<Process>, a: A) -> u64 { rd(libm::log2(d(a[0]))) }
pub fn log2_f(_: &Arc<Process>, a: A) -> u64 { rs(libm::log2f(s(a[0]))) }
pub fn log10_d(_: &Arc<Process>, a: A) -> u64 { rd(libm::log10(d(a[0]))) }
pub fn log10_f(_: &Arc<Process>, a: A) -> u64 { rs(libm::log10f(s(a[0]))) }
pub fn log1p_d(_: &Arc<Process>, a: A) -> u64 { rd(libm::log1p(d(a[0]))) }
pub fn log1p_f(_: &Arc<Process>, a: A) -> u64 { rs(libm::log1pf(s(a[0]))) }
pub fn sqrt_d(_: &Arc<Process>, a: A) -> u64 { rd(libm::sqrt(d(a[0]))) }
pub fn sqrt_f(_: &Arc<Process>, a: A) -> u64 { rs(libm::sqrtf(s(a[0]))) }
pub fn cbrt_d(_: &Arc<Process>, a: A) -> u64 { rd(libm::cbrt(d(a[0]))) }
pub fn cbrt_f(_: &Arc<Process>, a: A) -> u64 { rs(libm::cbrtf(s(a[0]))) }
pub fn fabs_d(_: &Arc<Process>, a: A) -> u64 { rd(libm::fabs(d(a[0]))) }
pub fn fabs_f(_: &Arc<Process>, a: A) -> u64 { rs(libm::fabsf(s(a[0]))) }
pub fn floor_d(_: &Arc<Process>, a: A) -> u64 { rd(libm::floor(d(a[0]))) }
pub fn floor_f(_: &Arc<Process>, a: A) -> u64 { rs(libm::floorf(s(a[0]))) }
pub fn ceil_d(_: &Arc<Process>, a: A) -> u64 { rd(libm::ceil(d(a[0]))) }
pub fn ceil_f(_: &Arc<Process>, a: A) -> u64 { rs(libm::ceilf(s(a[0]))) }
pub fn trunc_d(_: &Arc<Process>, a: A) -> u64 { rd(libm::trunc(d(a[0]))) }
pub fn trunc_f(_: &Arc<Process>, a: A) -> u64 { rs(libm::truncf(s(a[0]))) }
pub fn round_d(_: &Arc<Process>, a: A) -> u64 { rd(libm::round(d(a[0]))) }
pub fn round_f(_: &Arc<Process>, a: A) -> u64 { rs(libm::roundf(s(a[0]))) }
pub fn rint_d(_: &Arc<Process>, a: A) -> u64 { rd(libm::rint(d(a[0]))) }
pub fn rint_f(_: &Arc<Process>, a: A) -> u64 { rs(libm::rintf(s(a[0]))) }
pub fn erf_d(_: &Arc<Process>, a: A) -> u64 { rd(libm::erf(d(a[0]))) }
pub fn erf_f(_: &Arc<Process>, a: A) -> u64 { rs(libm::erff(s(a[0]))) }
pub fn erfc_d(_: &Arc<Process>, a: A) -> u64 { rd(libm::erfc(d(a[0]))) }
pub fn erfc_f(_: &Arc<Process>, a: A) -> u64 { rs(libm::erfcf(s(a[0]))) }
pub fn lgamma_d(_: &Arc<Process>, a: A) -> u64 { rd(libm::lgamma(d(a[0]))) }
pub fn lgamma_f(_: &Arc<Process>, a: A) -> u64 { rs(libm::lgammaf(s(a[0]))) }
pub fn tgamma_d(_: &Arc<Process>, a: A) -> u64 { rd(libm::tgamma(d(a[0]))) }
pub fn tgamma_f(_: &Arc<Process>, a: A) -> u64 { rs(libm::tgammaf(s(a[0]))) }
pub fn atan2_d(_: &Arc<Process>, a: A) -> u64 { rd(libm::atan2(d(a[0]), d(a[1]))) }
pub fn atan2_f(_: &Arc<Process>, a: A) -> u64 { rs(libm::atan2f(s(a[0]), s(a[1]))) }
pub fn pow_d(_: &Arc<Process>, a: A) -> u64 { rd(libm::pow(d(a[0]), d(a[1]))) }
pub fn pow_f(_: &Arc<Process>, a: A) -> u64 { rs(libm::powf(s(a[0]), s(a[1]))) }
pub fn hypot_d(_: &Arc<Process>, a: A) -> u64 { rd(libm::hypot(d(a[0]), d(a[1]))) }
pub fn hypot_f(_: &Arc<Process>, a: A) -> u64 { rs(libm::hypotf(s(a[0]), s(a[1]))) }
pub fn fmod_d(_: &Arc<Process>, a: A) -> u64 { rd(libm::fmod(d(a[0]), d(a[1]))) }
pub fn fmod_f(_: &Arc<Process>, a: A) -> u64 { rs(libm::fmodf(s(a[0]), s(a[1]))) }
pub fn fmin_d(_: &Arc<Process>, a: A) -> u64 { rd(libm::fmin(d(a[0]), d(a[1]))) }
pub fn fmin_f(_: &Arc<Process>, a: A) -> u64 { rs(libm::fminf(s(a[0]), s(a[1]))) }
pub fn fmax_d(_: &Arc<Process>, a: A) -> u64 { rd(libm::fmax(d(a[0]), d(a[1]))) }
pub fn fmax_f(_: &Arc<Process>, a: A) -> u64 { rs(libm::fmaxf(s(a[0]), s(a[1]))) }
pub fn copysign_d(_: &Arc<Process>, a: A) -> u64 { rd(libm::copysign(d(a[0]), d(a[1]))) }
pub fn copysign_f(_: &Arc<Process>, a: A) -> u64 { rs(libm::copysignf(s(a[0]), s(a[1]))) }
pub fn fdim_d(_: &Arc<Process>, a: A) -> u64 { rd(libm::fdim(d(a[0]), d(a[1]))) }
pub fn fdim_f(_: &Arc<Process>, a: A) -> u64 { rs(libm::fdimf(s(a[0]), s(a[1]))) }

/// ldexp(double, int) / scalbn
pub fn ldexp_d(_: &Arc<Process>, a: A) -> u64 { rd(libm::scalbn(d(a[0]), a[1] as i32)) }
pub fn ldexp_f(_: &Arc<Process>, a: A) -> u64 { rs(libm::scalbnf(s(a[0]), a[1] as i32)) }
/// frexp(double, int *exp)
pub fn frexp_d(p: &Arc<Process>, a: A) -> u64 {
    let (m, e) = libm::frexp(d(a[0]));
    let _ = copy_to_user(p, a[1], &e.to_le_bytes());
    rd(m)
}
/// modf(double, double *ip)
pub fn modf_d(p: &Arc<Process>, a: A) -> u64 {
    let (frac, int) = libm::modf(d(a[0]));
    let _ = copy_to_user(p, a[1], &int.to_bits().to_le_bytes());
    rd(frac)
}
pub fn isnan_d(_: &Arc<Process>, a: A) -> u64 { d(a[0]).is_nan() as u64 }
pub fn finite_d(_: &Arc<Process>, a: A) -> u64 { d(a[0]).is_finite() as u64 }
pub fn lround_d(_: &Arc<Process>, a: A) -> u64 { libm::round(d(a[0])) as i64 as u64 }
pub fn lrint_d(_: &Arc<Process>, a: A) -> u64 { libm::rint(d(a[0])) as i64 as u64 }

/// Parse the longest decimal floating-point prefix of `s` (after leading blanks): (value, bytes consumed). Handles
/// sign, digits, fraction, exponent, `inf`/`infinity`/`nan`. Rust's parser rounds correctly.
pub fn parse_float(s: &[u8]) -> (f64, usize) {
    let mut i = 0;
    while i < s.len() && (s[i] == b' ' || (9..=13).contains(&s[i])) {
        i += 1;
    }
    let start = i;
    if i < s.len() && (s[i] == b'+' || s[i] == b'-') {
        i += 1;
    }
    let low: alloc::vec::Vec<u8> = s[i..].iter().take(8).map(|c| c.to_ascii_lowercase()).collect();
    if low.starts_with(b"infinity") || low.starts_with(b"inf") || low.starts_with(b"nan") {
        let n = if low.starts_with(b"infinity") { 8 } else { 3 };
        let neg = s.get(start) == Some(&b'-');
        let v = if low.starts_with(b"nan") { f64::NAN } else if neg { f64::NEG_INFINITY } else { f64::INFINITY };
        return (v, i + n);
    }
    let ds = i;
    while i < s.len() && s[i].is_ascii_digit() { i += 1; }
    let mut digits = i - ds;
    if i < s.len() && s[i] == b'.' {
        i += 1;
        let fs = i;
        while i < s.len() && s[i].is_ascii_digit() { i += 1; }
        digits += i - fs;
    }
    if digits == 0 {
        return (0.0, 0);
    }
    if i < s.len() && (s[i] == b'e' || s[i] == b'E') {
        let mut j = i + 1;
        if j < s.len() && (s[j] == b'+' || s[j] == b'-') { j += 1; }
        let es = j;
        while j < s.len() && s[j].is_ascii_digit() { j += 1; }
        if j > es { i = j; }
    }
    let txt = core::str::from_utf8(&s[start..i]).unwrap_or("0");
    (txt.parse::<f64>().unwrap_or(0.0), i)
}
pub fn strtod(p: &Arc<Process>, a: A) -> u64 {
    let s = super::msvcrt::read_cstr(p, a[0], 4096);
    let (v, n) = parse_float(&s);
    if a[1] != 0 {
        let _ = copy_to_user(p, a[1], &(a[0] + n as u64).to_le_bytes());
    }
    rd(v)
}
pub fn atof(p: &Arc<Process>, a: A) -> u64 {
    let s = super::msvcrt::read_cstr(p, a[0], 4096);
    rd(parse_float(&s).0)
}
pub fn strtof(p: &Arc<Process>, a: A) -> u64 {
    let s = super::msvcrt::read_cstr(p, a[0], 4096);
    let (v, n) = parse_float(&s);
    if a[1] != 0 {
        let _ = copy_to_user(p, a[1], &(a[0] + n as u64).to_le_bytes());
    }
    rs(v as f32)
}

/// printf-style formatting of one double: conv in `fFeEgG`.
pub fn fmt_float(v: f64, conv: u8, prec: Option<usize>, alt: bool, upper: bool) -> alloc::vec::Vec<u8> {
    use alloc::format;
    let mut out = if v.is_nan() {
        alloc::string::String::from("nan")
    } else if v.is_infinite() {
        alloc::string::String::from("inf")
    } else {
        let a = libm::fabs(v);
        let p = prec.unwrap_or(6);
        match conv.to_ascii_lowercase() {
            b'f' => format!("{:.*}", p, a),
            b'e' => exp_form(a, p, alt),
            _ => {
                // %g: P significant digits; choose %e or %f by the decimal exponent X
                let pp = if p == 0 { 1 } else { p };
                let e = exp_form(a, pp - 1, false);
                let x: i32 = e.split('e').nth(1).and_then(|t| t.parse().ok()).unwrap_or(0);
                let mut r = if x < -4 || x >= pp as i32 { e } else { format!("{:.*}", (pp as i32 - 1 - x).max(0) as usize, a) };
                if !alt && r.contains('.') {
                    let (mant, ex) = match r.find('e') { Some(i) => (r[..i].to_string(), r[i..].to_string()), None => (r.clone(), alloc::string::String::new()) };
                    let m = mant.trim_end_matches('0').trim_end_matches('.').to_string();
                    r = m + &ex;
                }
                r
            }
        }
    };
    if upper {
        out = out.to_ascii_uppercase();
    }
    let mut b = out.into_bytes();
    if v.is_sign_negative() && !v.is_nan() {
        b.insert(0, b'-');
    }
    b
}
/// C-style `%e` body: d.ddde+XX (at least two exponent digits)
fn exp_form(a: f64, prec: usize, alt: bool) -> alloc::string::String {
    use alloc::format;
    let s = format!("{:.*e}", prec, a); // e.g. 1.234560e2 or 1e-5
    let (m, e) = s.split_once('e').unwrap_or((&s, "0"));
    let ex: i32 = e.parse().unwrap_or(0);
    let mut m = m.to_string();
    if alt && !m.contains('.') {
        m.push('.');
    }
    format!("{}e{}{:02}", m, if ex < 0 { '-' } else { '+' }, ex.abs())
}
