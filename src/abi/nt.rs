//! Win32 compatibility shim: a hand-written subset of kernel32, implemented inside the
//! kernel (no Microsoft code). A PE's imports resolve to 16-byte stubs in a per-process
//! thunk page; each stub is `mov r10, rcx; mov eax, <n>; syscall; ret`, so a Win32 call
//! becomes one SYSCALL handled here, following the Windows x64 calling convention
//! (RCX, RDX, R8, R9 -> r10, rdx, r8, r9).

use alloc::sync::Arc;
use alloc::vec::Vec;

use super::{console_write, msvcrt as c, vfs, win32 as w32, win32_thr as wt, win_extra as x, winmath as wm, winsock as ws};
use crate::arch::x86_64::syscall::SyscallFrame;
use crate::exec::{write_user, ExecError, Plan};
use crate::mm::layout::PAGE_SIZE;
use crate::mm::vmm::VmFlags;
use crate::sys::uaccess::{copy_from_user, copy_to_user};
use crate::task::{self, Process, USER_STACK_TOP};
use crate::time;
use x86_64::VirtAddr;

pub const NT_THUNK_BASE: u64 = 0x0000_7FFE_0000_0000;
pub const NT_DATA_BASE: u64 = NT_THUNK_BASE + 4 * PAGE_SIZE; // TEB, PEB, strings, msvcrt globals (4 pages)
pub const DATA_PAGE3: u64 = NT_DATA_BASE + 3 * PAGE_SIZE;

const STD_INPUT: u64 = 4;
const STD_OUTPUT: u64 = 8;
const STD_ERROR: u64 = 12;
const INVALID_HANDLE: u64 = u64::MAX;
const HEAP_HANDLE: u64 = 0x5000;

const ERROR_ACCESS_DENIED: u32 = 5;
const ERROR_INVALID_HANDLE: u32 = 6;
const ERROR_NOT_ENOUGH_MEMORY: u32 = 8;
const ERROR_NOT_SUPPORTED: u32 = 50;

type Shim = fn(&Arc<Process>, [u64; 4]) -> u64;

pub static SHIMS: &[(&str, Shim)] = &[
    ("ExitProcess", exit_process),
    ("GetStdHandle", get_std_handle),
    ("WriteFile", w32::write_file),
    ("WriteConsoleA", write_file),
    ("GetCommandLineA", get_command_line),
    ("GetModuleHandleA", x::get_module_handle_a),
    ("GetProcAddress", x::get_proc_address),
    ("VirtualAlloc", virtual_alloc),
    ("VirtualFree", virtual_free),
    ("GetProcessHeap", get_process_heap),
    ("HeapCreate", get_process_heap),
    ("HeapAlloc", heap_alloc),
    ("HeapReAlloc", heap_realloc),
    ("HeapFree", heap_free_shim),
    ("HeapSize", heap_size),
    ("GetLastError", get_last_error),
    ("SetLastError", set_last_error),
    ("WSAStartup", ws::startup),
    ("WSACleanup", ws::zero),
    ("WSAGetLastError", get_last_error),
    ("WSASetLastError", ws::set_wsa_error),
    ("socket", ws::socket),
    ("connect", ws::connect),
    ("send", ws::send),
    ("recv", ws::recv),
    ("closesocket", ws::closesocket),
    ("GetStartupInfoA", x::get_startup_info),
    ("GetStartupInfoW", x::get_startup_info),
    ("IsDebuggerPresent", x::zero),
    ("IsProcessorFeaturePresent", x::is_processor_feature_present),
    ("GetSystemInfo", x::get_system_info),
    ("GetNativeSystemInfo", x::get_system_info),
    ("GetVersion", x::get_version),
    ("GetVersionExA", x::get_version_ex),
    ("GetComputerNameA", x::get_computer_name),
    ("GetUserNameA", x::get_user_name),
    ("GetUserDefaultLCID", x::lcid),
    ("GetThreadLocale", x::lcid),
    ("GetUserDefaultLangID", x::lcid),
    ("GetACP", x::codepage),
    ("GetOEMCP", x::codepage),
    ("GetConsoleCP", x::codepage),
    ("GetConsoleOutputCP", x::codepage),
    ("SetConsoleCP", x::one),
    ("SetConsoleOutputCP", x::one),
    ("SetConsoleTitleA", x::one),
    ("SetConsoleTitleW", x::one),
    ("IsValidCodePage", x::one),
    ("GetCPInfo", x::get_cp_info),
    ("GetConsoleScreenBufferInfo", x::get_console_screen_buffer_info),
    ("GetProcessAffinityMask", x::get_affinity_mask),
    ("DuplicateHandle", x::duplicate_handle),
    ("GetHandleInformation", x::one),
    ("SetHandleInformation", x::one),
    ("SetThreadPriority", x::one),
    ("SetPriorityClass", x::one),
    ("SetThreadAffinityMask", x::one),
    ("SetErrorMode", x::zero),
    ("SetCurrentDirectoryA", x::one),
    ("GetCurrentProcessorNumber", x::zero),
    ("HeapDestroy", x::one),
    ("HeapValidate", x::one),
    ("HeapSetInformation", x::one),
    ("OutputDebugStringA", x::zero),
    ("OutputDebugStringW", x::zero),
    ("EncodePointer", x::ret_first),
    ("DecodePointer", x::ret_first),
    ("EncodeSystemPointer", x::ret_first),
    ("DecodeSystemPointer", x::ret_first),
    ("FlsAlloc", tls_alloc),
    ("FlsFree", one),
    ("FlsGetValue", tls_get),
    ("FlsSetValue", tls_set),
    ("InitializeSListHead", x::init_slist),
    ("InterlockedPushEntrySList", x::slist_push),
    ("InterlockedPopEntrySList", x::slist_pop),
    ("InterlockedFlushSList", x::slist_flush),
    ("QueryDepthSList", x::zero),
    ("InterlockedAnd", x::interlocked_and),
    ("InterlockedOr", x::interlocked_or),
    ("RaiseException", x::raise_exception),
    ("UnhandledExceptionFilter", x::zero),
    ("RtlCaptureContext", x::rtl_capture_context),
    ("RtlLookupFunctionEntry", x::zero),
    ("RtlVirtualUnwind", x::zero),
    ("RtlUnwindEx", x::zero),
    ("RtlUnwind", x::zero),
    ("GetModuleHandleW", x::get_module_handle_w),
    ("GetModuleHandleExW", x::get_module_handle_ex_w),
    ("LoadLibraryA", x::load_library_a),
    ("LoadLibraryW", x::load_library_w),
    ("LoadLibraryExA", x::load_library_a),
    ("LoadLibraryExW", x::load_library_w),
    ("FreeLibrary", x::one),
    ("LocalAlloc", x::local_alloc),
    ("GlobalAlloc", x::local_alloc),
    ("LocalFree", x::local_free),
    ("GlobalFree", x::local_free),
    ("LocalReAlloc", x::local_realloc),
    ("GlobalReAlloc", x::local_realloc),
    ("GlobalLock", x::ret_first),
    ("GlobalUnlock", x::one),
    ("GetCommandLineW", x::get_command_line_w),
    ("GetEnvironmentStringsW", x::get_environment_strings_w),
    ("GetEnvironmentStrings", x::get_environment_strings_w),
    ("FreeEnvironmentStringsW", x::one),
    ("FreeEnvironmentStringsA", x::one),
    ("GetEnvironmentVariableW", x::get_environment_variable_w),
    ("WriteConsoleW", x::write_console_w),
    ("CreateFileW", x::create_file_w),
    ("GetFileAttributesW", x::get_file_attributes_w),
    ("DeleteFileW", x::delete_file_w),
    ("CreateDirectoryW", x::create_directory_w),
    ("GetModuleFileNameW", x::get_module_file_name_w),
    ("GetFullPathNameA", x::get_full_path_name_a),
    ("GetLongPathNameA", x::get_full_path_name_a),
    ("GetFileSizeEx", x::get_file_size_ex),
    ("SetFilePointerEx", x::set_file_pointer_ex),
    ("GetStringTypeW", x::get_string_type_w),
    ("LCMapStringW", x::lc_map_string_w),
    ("lstrcmpiA", x::lstrcmpi),
    ("lstrlenW", x::wcslen_),
    ("CreateEventW", wt::create_event),
    ("CreateMutexW", wt::create_mutex),
    ("CreateSemaphoreW", wt::create_semaphore),
    ("GetSystemTimePreciseAsFileTime", w32_system_time_alias),
    ("_aligned_malloc", x::aligned_malloc),
    ("_aligned_free", x::aligned_free),
    ("strncat", x::strncat),
    ("strpbrk", x::strpbrk),
    ("strtok", x::strtok),
    ("_strlwr", x::strlwr),
    ("_strupr", x::strupr),
    ("strlwr", x::strlwr),
    ("strupr", x::strupr),
    ("labs", x::labs),
    ("_abs64", x::labs),
    ("llabs", x::labs),
    ("_itoa", x::itoa),
    ("_ltoa", x::itoa),
    ("_ultoa", x::ultoa),
    ("_i64toa", x::i64toa),
    ("_ui64toa", x::ui64toa),
    ("_getpid", x::getpid),
    ("getpid", x::getpid),
    ("_unlink", c::remove),
    ("wcscmp", x::wcscmp),
    ("_wcsicmp", x::wcsicmp),
    ("wcsncmp", x::wcsncmp),
    ("wcscpy", x::wcscpy),
    ("wcsncpy", x::wcsncpy),
    ("wcscat", x::wcscat),
    ("wcschr", x::wcschr),
    ("wcsrchr", x::wcsrchr),
    ("wcsstr", x::wcsstr),
    ("towlower", x::towlower),
    ("towupper", x::towupper),
    ("iswalpha", x::iswalpha),
    ("iswdigit", x::iswdigit),
    ("iswspace", x::iswspace),
    ("isgraph", x::isgraph),
    ("isascii", x::isascii),
    ("gmtime", x::gmtime),
    ("localtime", x::gmtime),
    ("_gmtime64", x::gmtime),
    ("_localtime64", x::gmtime),
    ("mktime", x::mktime),
    ("_mkgmtime", x::mktime),
    ("_mktime64", x::mktime),
    ("strftime", x::strftime),
    ("SystemFunction036", x::rtl_gen_random),
    ("RtlGenRandom", x::rtl_gen_random),
    ("BCryptGenRandom", x::bcrypt_gen_random),
    ("CryptGenRandom", x::crypt_gen_random),
    ("CryptAcquireContextA", x::crypt_acquire_context),
    ("CryptAcquireContextW", x::crypt_acquire_context),
    ("CryptReleaseContext", x::one),
    ("rand_s", x::rand_s),
    ("sin", wm::sin_d),
    ("sinf", wm::sin_f),
    ("cos", wm::cos_d),
    ("cosf", wm::cos_f),
    ("tan", wm::tan_d),
    ("tanf", wm::tan_f),
    ("asin", wm::asin_d),
    ("asinf", wm::asin_f),
    ("acos", wm::acos_d),
    ("acosf", wm::acos_f),
    ("atan", wm::atan_d),
    ("atanf", wm::atan_f),
    ("sinh", wm::sinh_d),
    ("sinhf", wm::sinh_f),
    ("cosh", wm::cosh_d),
    ("coshf", wm::cosh_f),
    ("tanh", wm::tanh_d),
    ("tanhf", wm::tanh_f),
    ("asinh", wm::asinh_d),
    ("asinhf", wm::asinh_f),
    ("acosh", wm::acosh_d),
    ("acoshf", wm::acosh_f),
    ("atanh", wm::atanh_d),
    ("atanhf", wm::atanh_f),
    ("exp", wm::exp_d),
    ("expf", wm::exp_f),
    ("exp2", wm::exp2_d),
    ("exp2f", wm::exp2_f),
    ("expm1", wm::expm1_d),
    ("expm1f", wm::expm1_f),
    ("log", wm::log_d),
    ("logf", wm::log_f),
    ("log2", wm::log2_d),
    ("log2f", wm::log2_f),
    ("log10", wm::log10_d),
    ("log10f", wm::log10_f),
    ("log1p", wm::log1p_d),
    ("log1pf", wm::log1p_f),
    ("sqrt", wm::sqrt_d),
    ("sqrtf", wm::sqrt_f),
    ("cbrt", wm::cbrt_d),
    ("cbrtf", wm::cbrt_f),
    ("fabs", wm::fabs_d),
    ("fabsf", wm::fabs_f),
    ("floor", wm::floor_d),
    ("floorf", wm::floor_f),
    ("ceil", wm::ceil_d),
    ("ceilf", wm::ceil_f),
    ("trunc", wm::trunc_d),
    ("truncf", wm::trunc_f),
    ("round", wm::round_d),
    ("roundf", wm::round_f),
    ("rint", wm::rint_d),
    ("rintf", wm::rint_f),
    ("erf", wm::erf_d),
    ("erff", wm::erf_f),
    ("erfc", wm::erfc_d),
    ("erfcf", wm::erfc_f),
    ("lgamma", wm::lgamma_d),
    ("lgammaf", wm::lgamma_f),
    ("tgamma", wm::tgamma_d),
    ("tgammaf", wm::tgamma_f),
    ("atan2", wm::atan2_d),
    ("atan2f", wm::atan2_f),
    ("pow", wm::pow_d),
    ("powf", wm::pow_f),
    ("hypot", wm::hypot_d),
    ("hypotf", wm::hypot_f),
    ("fmod", wm::fmod_d),
    ("fmodf", wm::fmod_f),
    ("fmin", wm::fmin_d),
    ("fminf", wm::fmin_f),
    ("fmax", wm::fmax_d),
    ("fmaxf", wm::fmax_f),
    ("copysign", wm::copysign_d),
    ("copysignf", wm::copysign_f),
    ("fdim", wm::fdim_d),
    ("fdimf", wm::fdim_f),
    ("ldexp", wm::ldexp_d),
    ("scalbn", wm::ldexp_d),
    ("ldexpf", wm::ldexp_f),
    ("scalbnf", wm::ldexp_f),
    ("frexp", wm::frexp_d),
    ("modf", wm::modf_d),
    ("_isnan", wm::isnan_d),
    ("_finite", wm::finite_d),
    ("lround", wm::lround_d),
    ("lrint", wm::lrint_d),
    ("atof", wm::atof),
    ("_atof", wm::atof),
    ("strtod", wm::strtod),
    ("strtof", wm::strtof),
    ("shutdown", ws::shutdown),
    ("setsockopt", ws::setsockopt),
    ("getsockopt", ws::getsockopt),
    ("ioctlsocket", ws::ioctlsocket),
    ("htons", ws::htons),
    ("ntohs", ws::htons),
    ("htonl", ws::htonl),
    ("ntohl", ws::htonl),
    ("inet_addr", ws::inet_addr),
    ("gethostbyname", ws::gethostbyname),
    ("getaddrinfo", ws::getaddrinfo),
    ("freeaddrinfo", ws::freeaddrinfo),
    ("gethostname", ws::gethostname),
    ("inet_ntoa", ws::inet_ntoa),
    ("bind", ws::bind),
    ("listen", ws::listen),
    ("accept", ws::accept),
    ("sendto", ws::sendto),
    ("recvfrom", ws::recvfrom),
    ("select", ws::select),
    ("__WSAFDIsSet", ws::wsa_fd_isset),
    ("WSAPoll", ws::wsa_poll),
    ("getsockname", ws::getsockname),
    ("getpeername", ws::getpeername),
    ("InitializeSRWLock", wt::srw_init),
    ("AcquireSRWLockExclusive", wt::srw_acq_excl),
    ("TryAcquireSRWLockExclusive", wt::srw_try_excl),
    ("ReleaseSRWLockExclusive", wt::srw_rel_excl),
    ("AcquireSRWLockShared", wt::srw_acq_shared),
    ("TryAcquireSRWLockShared", wt::srw_try_shared),
    ("ReleaseSRWLockShared", wt::srw_rel_shared),
    ("InitializeConditionVariable", wt::srw_init),
    ("SleepConditionVariableCS", wt::cv_sleep_cs),
    ("SleepConditionVariableSRW", wt::cv_sleep_srw),
    ("WakeConditionVariable", wt::cv_wake),
    ("WakeAllConditionVariable", wt::cv_wake),
    ("InitializeCriticalSection", wt::cs_init),
    ("InitializeCriticalSectionAndSpinCount", wt::cs_init),
    ("EnterCriticalSection", wt::cs_enter),
    ("TryEnterCriticalSection", wt::cs_try_enter),
    ("LeaveCriticalSection", wt::cs_leave),
    ("DeleteCriticalSection", zero),
    ("CreateThread", wt::create_thread),
    ("_beginthreadex", wt::create_thread),
    ("_beginthread", wt::beginthread),
    ("ExitThread", wt::exit_thread),
    ("_endthreadex", wt::exit_thread),
    ("WaitForSingleObject", wt::wait_single),
    ("WaitForSingleObjectEx", wt::wait_single),
    ("WaitForMultipleObjects", wt::wait_multiple),
    ("CreateEventA", wt::create_event),
    ("SetEvent", wt::set_event),
    ("ResetEvent", wt::reset_event),
    ("CreateMutexA", wt::create_mutex),
    ("ReleaseMutex", wt::release_mutex),
    ("CreateSemaphoreA", wt::create_semaphore),
    ("ReleaseSemaphore", wt::release_semaphore),
    ("GetExitCodeThread", wt::get_exit_code_thread),
    ("SwitchToThread", wt::switch_to_thread),
    ("GetCurrentThread", wt::get_current_thread),
    ("InterlockedIncrement", wt::il_inc),
    ("InterlockedDecrement", wt::il_dec),
    ("InterlockedExchange", wt::il_xchg),
    ("InterlockedExchangeAdd", wt::il_xadd),
    ("InterlockedCompareExchange", wt::il_cmpxchg),
    ("InterlockedIncrement64", wt::il_inc64),
    ("InterlockedCompareExchange64", wt::il_cmpxchg64),
    ("TlsAlloc", tls_alloc),
    ("TlsFree", one),
    ("TlsGetValue", tls_get),
    ("TlsSetValue", tls_set),
    ("GetSystemTimeAsFileTime", get_system_time),
    ("QueryPerformanceCounter", query_perf_counter),
    ("QueryPerformanceFrequency", query_perf_freq),
    ("GetTickCount", get_tick_count),
    ("GetTickCount64", get_tick_count),
    ("Sleep", sleep),
    ("GetCurrentProcessId", get_pid),
    ("GetCurrentThreadId", get_tid),
    ("GetCurrentProcess", get_current_process),
    ("SetUnhandledExceptionFilter", zero),
    ("TerminateProcess", terminate_process),
    ("IsDBCSLeadByteEx", zero),
    ("MultiByteToWideChar", c::multi_byte_to_wide),
    ("WideCharToMultiByte", c::wide_to_multi_byte),
    ("VirtualProtect", one),
    ("VirtualQuery", zero),
    // ---- msvcrt ----
    ("__getmainargs", c::getmainargs),
    ("__set_app_type", zero),
    ("__setusermatherr", zero),
    ("___lc_codepage_func", zero),
    ("___mb_cur_max_func", one),
    ("__iob_func", c::iob_func),
    ("_amsg_exit", c::amsg_exit),
    ("_cexit", zero),
    ("_lock", zero),
    ("_unlock", zero),
    ("_onexit", c::onexit),
    ("atexit", c::atexit),
    ("signal", zero),
    ("getenv", zero),
    ("setvbuf", zero),
    ("_setmode", zero),
    ("_errno", c::errno_ptr),
    ("strerror", c::strerror),
    ("localeconv", c::localeconv),
    ("abort", c::abort),
    ("exit", c::exit),
    ("_exit", c::exit),
    ("malloc", c::malloc),
    ("calloc", c::calloc),
    ("realloc", c::realloc),
    ("free", c::free),
    ("_msize", c::msize),
    ("memcpy", c::memcpy),
    ("memmove", c::memcpy),
    ("memset", c::memset),
    ("memcmp", c::memcmp),
    ("strlen", c::strlen),
    ("strcpy", c::strcpy),
    ("strncpy", c::strncpy),
    ("strcat", c::strcat),
    ("strcmp", c::strcmp),
    ("strncmp", c::strncmp),
    ("strchr", c::strchr),
    ("strrchr", c::strrchr),
    ("strstr", c::strstr),
    ("wcslen", c::wcslen),
    ("toupper", c::toupper),
    ("tolower", c::tolower),
    ("atoi", c::atoi),
    ("abs", c::abs),
    ("time", c::time_),
    ("clock", c::clock_),
    ("rand", c::rand_),
    ("srand", c::srand_),
    ("fopen", c::fopen),
    ("fclose", c::fclose),
    ("fread", c::fread),
    ("fwrite", c::fwrite),
    ("fputc", c::fputc),
    ("putc", c::fputc),
    ("putchar", c::putchar),
    ("fputs", c::fputs),
    ("puts", c::puts),
    ("fgetc", c::fgetc),
    ("getc", c::fgetc),
    ("fgets", c::fgets),
    ("fseek", c::fseek),
    ("ftell", c::ftell),
    ("rewind", c::rewind),
    ("feof", c::feof),
    ("ferror", zero),
    ("fflush", c::fflush),
    ("remove", c::remove),
    ("printf", c::printf),
    ("fprintf", c::fprintf),
    ("vprintf", c::vprintf),
    ("vfprintf", c::vfprintf),
    ("sprintf", c::sprintf),
    ("snprintf", c::snprintf),
    ("_snprintf", c::snprintf),
    ("vsprintf", c::vsprintf),
    ("vsnprintf", c::vsnprintf),
    ("_vsnprintf", c::vsnprintf),
    ("CreateFileA", w32::create_file),
    ("ReadFile", w32::read_file),
    ("ReadConsoleA", w32::read_file),
    ("CloseHandle", close_any),
    ("GetFileSize", w32::get_file_size),
    ("SetFilePointer", w32::set_file_pointer),
    ("FlushFileBuffers", w32::flush_file_buffers),
    ("DeleteFileA", w32::delete_file),
    ("GetFileAttributesA", w32::get_file_attributes),
    ("GetFileType", w32::get_file_type),
    ("FindFirstFileA", w32::find_first_file),
    ("FindNextFileA", w32::find_next_file),
    ("FindClose", w32::find_close),
    ("GetModuleFileNameA", w32::get_module_file_name),
    ("GetCurrentDirectoryA", w32::get_current_directory),
    ("GetEnvironmentVariableA", w32::get_env_var),
    ("GetConsoleMode", w32::get_console_mode),
    ("SetConsoleMode", w32::one),
    ("SetConsoleCtrlHandler", w32::one),
    ("GetLocalTime", w32::get_local_time),
    ("GetSystemTime", w32::get_local_time),
    ("CreateDirectoryA", w32::create_directory),
    ("lstrlenA", c::strlen),
    ("lstrcpyA", c::strcpy),
    ("lstrcmpA", c::strcmp),
    ("isalpha", c::isalpha),
    ("isdigit", c::isdigit),
    ("isalnum", c::isalnum),
    ("isspace", c::isspace),
    ("isupper", c::isupper),
    ("islower", c::islower),
    ("ispunct", c::ispunct),
    ("isxdigit", c::isxdigit),
    ("isprint", c::isprint),
    ("iscntrl", c::iscntrl),
    ("strtol", c::strtol),
    ("strtoul", c::strtoul),
    ("strtoll", c::strtoll),
    ("_strtoi64", c::strtoll),
    ("strtoull", c::strtoull),
    ("_strtoui64", c::strtoull),
    ("atol", c::atol),
    ("atoll", c::atoll),
    ("_atoi64", c::atoll),
    ("sscanf", c::sscanf),
    ("scanf", c::scanf),
    ("getchar", c::getchar),
    ("ungetc", c::ungetc),
    ("strdup", c::strdup),
    ("_strdup", c::strdup),
    ("perror", c::perror),
    ("setlocale", c::setlocale),
    ("strcspn", c::strcspn),
    ("strspn", c::strspn),
    ("_stricmp", c::stricmp),
    ("stricmp", c::stricmp),
    ("_strnicmp", c::strnicmp),
    ("strnicmp", c::strnicmp),
    ("memchr", c::memchr),
    ("_fileno", c::fileno),
    ("fileno", c::fileno),
    ("system", c::minus1),
    ("_kbhit", zero),
];


/// Resolve `dll!name` to the address that goes into the import table: a syscall thunk (functions), a user-mode
/// code stub (`_initterm`...) or a data symbol (`_fmode`...). Only kernel32 and msvcrt are provided.
pub fn resolve(dll: &str, name: &str) -> Option<u64> {
    let d = dll.as_bytes();
    let d = if d.len() > 4 && d[d.len() - 4..].eq_ignore_ascii_case(b".dll") { &d[..d.len() - 4] } else { d };
    let low: alloc::string::String = alloc::string::String::from_utf8_lossy(d).to_ascii_lowercase();
    // one flat shim table serves every system DLL a program may import from (kernel32 and its forwarders, the C runtimes)
    let k32 = low == "bcrypt" || low == "kernel32" || low == "kernelbase" || low == "ntdll" || low == "advapi32" || low.starts_with("api-ms-win-core");
    let crt = low == "msvcrt" || low == "ucrtbase" || low == "vcruntime140" || low.starts_with("api-ms-win-crt");
    let wsock = low == "ws2_32" || low == "wsock32";
    if !k32 && !crt && !wsock {
        return None;
    }
    if crt {
        if let Some(a) = float_stub_addr(name) {
            return Some(a);
        }
        // user-mode code stubs take precedence (e.g. `exit` must run the atexit handlers in user mode)
        if let Some(a) = c::code_stub_addr(name) {
            return Some(a);
        }
    }
    if let Some(i) = SHIMS.iter().position(|(n, _)| *n == name) {
        return Some(thunk_addr(i));
    }
    if crt {
        return c::data_sym(name);
    }
    None
}

/// Shim index for a kernel32 function (kept for tests).
pub fn lookup(dll: &str, name: &str) -> Option<usize> {
    let d = dll.as_bytes();
    let d = if d.len() > 4 && d[d.len() - 4..].eq_ignore_ascii_case(b".dll") { &d[..d.len() - 4] } else { d };
    if !d.eq_ignore_ascii_case(b"kernel32") {
        return None;
    }
    SHIMS.iter().position(|(n, _)| *n == name)
}

/// Float functions: (name, kind). Kind 0: double/float arg in xmm0 -> result in xmm0; 1: xmm0+xmm1 -> xmm0; 2: xmm0 -> int
/// result; 3: integer args -> result in xmm0. Their stubs live in the fourth thunk page (32 bytes each).
pub const FLOAT_OFF: u64 = 12288;
pub static FLOAT_STUBS: &[(&str, u8)] = &[
    ("sin", 0),
    ("sinf", 0),
    ("cos", 0),
    ("cosf", 0),
    ("tan", 0),
    ("tanf", 0),
    ("asin", 0),
    ("asinf", 0),
    ("acos", 0),
    ("acosf", 0),
    ("atan", 0),
    ("atanf", 0),
    ("sinh", 0),
    ("sinhf", 0),
    ("cosh", 0),
    ("coshf", 0),
    ("tanh", 0),
    ("tanhf", 0),
    ("asinh", 0),
    ("asinhf", 0),
    ("acosh", 0),
    ("acoshf", 0),
    ("atanh", 0),
    ("atanhf", 0),
    ("exp", 0),
    ("expf", 0),
    ("exp2", 0),
    ("exp2f", 0),
    ("expm1", 0),
    ("expm1f", 0),
    ("log", 0),
    ("logf", 0),
    ("log2", 0),
    ("log2f", 0),
    ("log10", 0),
    ("log10f", 0),
    ("log1p", 0),
    ("log1pf", 0),
    ("sqrt", 0),
    ("sqrtf", 0),
    ("cbrt", 0),
    ("cbrtf", 0),
    ("fabs", 0),
    ("fabsf", 0),
    ("floor", 0),
    ("floorf", 0),
    ("ceil", 0),
    ("ceilf", 0),
    ("trunc", 0),
    ("truncf", 0),
    ("round", 0),
    ("roundf", 0),
    ("rint", 0),
    ("rintf", 0),
    ("erf", 0),
    ("erff", 0),
    ("erfc", 0),
    ("erfcf", 0),
    ("lgamma", 0),
    ("lgammaf", 0),
    ("tgamma", 0),
    ("tgammaf", 0),
    ("atan2", 1),
    ("atan2f", 1),
    ("pow", 1),
    ("powf", 1),
    ("hypot", 1),
    ("hypotf", 1),
    ("fmod", 1),
    ("fmodf", 1),
    ("fmin", 1),
    ("fminf", 1),
    ("fmax", 1),
    ("fmaxf", 1),
    ("copysign", 1),
    ("copysignf", 1),
    ("fdim", 1),
    ("fdimf", 1),
    ("ldexp", 0),
    ("scalbn", 0),
    ("ldexpf", 0),
    ("scalbnf", 0),
    ("frexp", 0),
    ("modf", 0),
    ("_isnan", 2),
    ("_finite", 2),
    ("lround", 2),
    ("lrint", 2),
    ("atof", 3),
    ("_atof", 3),
    ("strtod", 3),
    ("strtof", 3),
];

pub fn float_stub_addr(name: &str) -> Option<u64> {
    FLOAT_STUBS.iter().position(|(n, _)| *n == name).map(|k| NT_THUNK_BASE + FLOAT_OFF + 32 * k as u64)
}

/// Build the 32-byte trampoline for float stub `k` (calls shim `nr`).
fn float_stub(kind: u8, nr: u32) -> [u8; 32] {
    let mut b = alloc::vec::Vec::new();
    match kind {
        0 => b.extend_from_slice(&[0x66, 0x49, 0x0F, 0x7E, 0xC2]),                        // movq r10, xmm0
        1 => b.extend_from_slice(&[0x66, 0x49, 0x0F, 0x7E, 0xC2, 0x66, 0x48, 0x0F, 0x7E, 0xCA]), // movq r10, xmm0 ; movq rdx, xmm1
        2 => b.extend_from_slice(&[0x66, 0x49, 0x0F, 0x7E, 0xC2]),
        _ => b.extend_from_slice(&[0x49, 0x89, 0xCA]),                                    // mov r10, rcx
    }
    b.push(0xB8);
    b.extend_from_slice(&nr.to_le_bytes());
    b.extend_from_slice(&[0x0F, 0x05]); // syscall
    if kind != 2 {
        b.extend_from_slice(&[0x66, 0x48, 0x0F, 0x6E, 0xC0]); // movq xmm0, rax
    }
    b.push(0xC3);
    let mut s = [0xCCu8; 32];
    s[..b.len()].copy_from_slice(&b);
    s
}

/// Address of the stub for shim `idx` (stub 0 is the "process return" stub).
pub fn thunk_addr(idx: usize) -> u64 {
    NT_THUNK_BASE + 16 * (idx as u64 + 1)
}

fn stub(prefix: [u8; 3], nr: u32) -> [u8; 16] {
    let mut s = [0xCCu8; 16];
    s[..3].copy_from_slice(&prefix);
    s[3] = 0xB8; // mov eax, imm32
    s[4..8].copy_from_slice(&nr.to_le_bytes());
    s[8] = 0x0F; // syscall
    s[9] = 0x05;
    s[10] = 0xC3; // ret
    s
}

/// Map the thunk page and the TEB/PEB/strings pages, build the entry stack. Returns (rsp, teb).
pub fn setup_process(p: &Arc<Process>, plan: &Plan, args: &[&str]) -> Result<(u64, u64), ExecError> {
    let oom = |_| ExecError::OutOfMemory;
    p.map_region(NT_THUNK_BASE, 4, VmFlags::WRITE | VmFlags::USER).map_err(oom)?;
    let exit_idx = SHIMS.iter().position(|(n, _)| *n == "ExitProcess").unwrap_or(0);
    let mut page: Vec<u8> = Vec::new();
    // stub 0: process return: exit code is in RAX -> r10, then ExitProcess
    page.extend_from_slice(&stub([0x49, 0x89, 0xC2], exit_idx as u32 + 1)); // mov r10, rax
    for i in 0..SHIMS.len() {
        page.extend_from_slice(&stub([0x4C, 0x8B, 0xD1], i as u32 + 1)); // mov r10, rcx
    }
    if page.len() > c::CODE_OFF as usize {
        return Err(ExecError::Unsupported("too many shims"));
    }
    page.resize(c::CODE_OFF as usize, 0xCC);
    let exit_thunk = SHIMS.iter().position(|(n, _)| *n == "_exit").map(thunk_addr).unwrap_or(0);
    let thread_exit_thunk = SHIMS.iter().position(|(n, _)| *n == "ExitThread").map(thunk_addr).unwrap_or(0);
    for (_, code) in c::CODE_STUBS {
        let mut st = c::build_stub(code, exit_thunk, thread_exit_thunk);
        st.resize(c::CODE_STRIDE as usize, 0xCC);
        page.extend_from_slice(&st);
    }
    page.resize(FLOAT_OFF as usize, 0xCC);
    for (name, kind) in FLOAT_STUBS {
        let nr = SHIMS.iter().position(|(n, _)| n == name).map(|i| i as u32 + 1).unwrap_or(0);
        page.extend_from_slice(&float_stub(*kind, nr));
    }
    write_user(p, NT_THUNK_BASE, &page)?;
    {
        let mut g = p.space.lock();
        let sp = g.as_mut().ok_or(ExecError::OutOfMemory)?;
        for pg in 0..4u64 {
            sp.protect(VirtAddr::new(NT_THUNK_BASE + pg * PAGE_SIZE), VmFlags::USER | VmFlags::EXEC).map_err(|_| ExecError::OutOfMemory)?;
        }
    }

    p.map_region(NT_DATA_BASE, 4, VmFlags::WRITE | VmFlags::USER).map_err(oom)?;
    c::init_globals(p)?;
    let teb = NT_DATA_BASE;
    let peb = NT_DATA_BASE + PAGE_SIZE;
    let strings = NT_DATA_BASE + 2 * PAGE_SIZE;
    let stack_top = USER_STACK_TOP;
    let stack_limit = USER_STACK_TOP - crate::exec::EXEC_STACK_PAGES as u64 * PAGE_SIZE;
    let w64 = |off: u64, v: u64| write_user(p, off, &v.to_le_bytes());
    w64(teb + 0x08, stack_top)?; // NT_TIB.StackBase
    w64(teb + 0x10, stack_limit)?; // StackLimit
    w64(teb + 0x30, teb)?; // Self
    w64(teb + 0x40, p.pid)?; // ClientId.UniqueProcess
    w64(teb + 0x48, 1)?; // UniqueThread
    w64(teb + 0x60, peb)?; // ProcessEnvironmentBlock
    if let Some((start, end, zero, index_va)) = plan.tls {
        // static TLS: one block (template + zero fill) reached through TEB.ThreadLocalStoragePointer[tls_index]
        let len = (end - start) as usize;
        let total = len + zero as usize;
        let pages = ((total as u64 + PAGE_SIZE - 1) / PAGE_SIZE).max(1) as usize;
        let va = p.mmap_next.fetch_add((pages as u64 + 1) * PAGE_SIZE, core::sync::atomic::Ordering::SeqCst);
        p.map_region(va, pages, VmFlags::WRITE | VmFlags::USER).map_err(oom)?;
        let mut tmpl = alloc::vec![0u8; len];
        copy_from_user(p, &mut tmpl, start).map_err(|_| ExecError::BadRange)?;
        write_user(p, va, &tmpl)?;
        let arr = DATA_PAGE3 + 0xF00;
        w64(arr, va)?;
        w64(teb + 0x58, arr)?;
        write_user(p, index_va, &0u32.to_le_bytes())?;
    }
    p.foreign.lock().tls_tmpl = plan.tls;
    w64(peb + 0x10, plan.image_base)?; // ImageBaseAddress

    let mut cmd: Vec<u8> = Vec::new();
    for (i, a) in args.iter().enumerate() {
        if i > 0 {
            cmd.push(b' ');
        }
        cmd.extend_from_slice(a.as_bytes());
    }
    if cmd.len() > 2000 {
        cmd.truncate(2000);
    }
    cmd.push(0);
    write_user(p, strings, &cmd)?;
    // argv[] for __getmainargs: pointers at strings+2048, strings after them (at most 30 args)
    {
        let base = strings + 2048;
        let n = args.len().min(30);
        let mut ptrs: Vec<u8> = Vec::new();
        let mut data: Vec<u8> = Vec::new();
        let data_va = base + 8 * (n as u64 + 1);
        for a in args.iter().take(n) {
            if data.len() + a.len() + 1 > 1700 {
                break;
            }
            ptrs.extend_from_slice(&(data_va + data.len() as u64).to_le_bytes());
            data.extend_from_slice(a.as_bytes());
            data.push(0);
        }
        let argc = (ptrs.len() / 8) as u64;
        ptrs.extend_from_slice(&0u64.to_le_bytes());
        write_user(p, base, &ptrs)?;
        write_user(p, data_va, &data)?;
        let mut f = p.foreign.lock();
        f.argc = argc;
        f.argv_va = base;
    }
    p.foreign.lock().cmdline_va = strings;

    // Entry convention: rsp % 16 == 8 with a return address (-> stub 0) and 32 bytes of shadow space above it.
    let rsp = stack_top - 0x28;
    write_user(p, rsp, &NT_THUNK_BASE.to_le_bytes())?;
    Ok((rsp, teb))
}

pub fn syscall(f: &mut SyscallFrame) -> i64 {
    let p = task::current_process();
    let idx = (f.rax as usize).wrapping_sub(1);
    let args = [f.r10, f.rdx, f.r8, f.r9];
    p.foreign.lock().nt_rsp = f.rsp;
    match SHIMS.get(idx) {
        Some((_, func)) => func(&p, args) as i64,
        None => {
            if p.foreign.lock().first_warning(f.rax as u16) {
                log::warn!("nt: unknown shim number {} in pid {}", f.rax, p.pid);
            }
            0
        }
    }
}

pub fn set_err(p: &Arc<Process>, e: u32) {
    p.foreign.lock().last_error = e;
}

// ------------------------------------------------------------- shims -------

fn zero(_: &Arc<Process>, _: [u64; 4]) -> u64 {
    0
}
fn one(_: &Arc<Process>, _: [u64; 4]) -> u64 {
    1
}

pub(super) fn exit_process(p: &Arc<Process>, a: [u64; 4]) -> u64 {
    vfs::flush_all(p);
    task::sched::exit_process(a[0] as u32 as i64)
}

fn terminate_process(p: &Arc<Process>, a: [u64; 4]) -> u64 {
    if a[0] == u64::MAX {
        task::sched::exit_process(a[1] as u32 as i64);
    }
    set_err(p, ERROR_INVALID_HANDLE);
    0
}

fn get_std_handle(p: &Arc<Process>, a: [u64; 4]) -> u64 {
    match a[0] as u32 as i32 {
        -10 => STD_INPUT,
        -11 => STD_OUTPUT,
        -12 => STD_ERROR,
        _ => {
            set_err(p, ERROR_INVALID_HANDLE);
            INVALID_HANDLE
        }
    }
}

/// WriteFile / WriteConsoleA: (handle, buffer, count, *written, ...)
pub fn write_file(p: &Arc<Process>, a: [u64; 4]) -> u64 {
    if a[0] != STD_OUTPUT && a[0] != STD_ERROR {
        set_err(p, ERROR_INVALID_HANDLE);
        return 0;
    }
    let len = a[2] as u32 as usize;
    if len > 1 << 20 {
        set_err(p, ERROR_NOT_ENOUGH_MEMORY);
        return 0;
    }
    let mut done = 0usize;
    let mut chunk = [0u8; 512];
    while done < len {
        let n = core::cmp::min(len - done, chunk.len());
        if copy_from_user(p, &mut chunk[..n], a[1] + done as u64).is_err() {
            set_err(p, 998); // ERROR_NOACCESS
            return 0;
        }
        if console_write(p, "pe", &chunk[..n]).is_err() {
            set_err(p, ERROR_ACCESS_DENIED);
            return 0;
        }
        done += n;
    }
    if a[3] != 0 {
        let _ = copy_to_user(p, a[3], &(done as u32).to_le_bytes());
    }
    1
}

fn get_command_line(p: &Arc<Process>, _: [u64; 4]) -> u64 {
    p.foreign.lock().cmdline_va
}

fn get_module_handle(p: &Arc<Process>, a: [u64; 4]) -> u64 {
    if a[0] == 0 {
        p.foreign.lock().image_base
    } else {
        0
    }
}

/// VirtualAlloc(addr, size, type, protect): always RW, never executable (W^X policy).
fn virtual_alloc(p: &Arc<Process>, a: [u64; 4]) -> u64 {
    let (size, prot) = (a[1], a[3] as u32);
    if prot & 0xF0 != 0 {
        set_err(p, ERROR_NOT_SUPPORTED);
        return 0;
    }
    if size == 0 || size > 64 * 1024 * 1024 {
        set_err(p, ERROR_NOT_ENOUGH_MEMORY);
        return 0;
    }
    let pages = ((size + PAGE_SIZE - 1) / PAGE_SIZE) as usize;
    let va = p.mmap_next.fetch_add((pages as u64 + 1) * PAGE_SIZE, core::sync::atomic::Ordering::SeqCst);
    match p.map_region(va, pages, VmFlags::WRITE | VmFlags::USER) {
        Ok(()) => va,
        Err(_) => {
            set_err(p, ERROR_NOT_ENOUGH_MEMORY);
            0
        }
    }
}

fn virtual_free(p: &Arc<Process>, a: [u64; 4]) -> u64 {
    const MEM_RELEASE: u64 = 0x8000;
    if a[2] & MEM_RELEASE == 0 {
        return 1; // decommit: nothing to do
    }
    let found = {
        let m = p.mappings.lock();
        m.iter().find(|r| r.va == a[0] && r.owned).map(|r| r.pages)
    };
    match found {
        Some(pages) if super::unmap_region(p, a[0], pages) => 1,
        _ => {
            set_err(p, ERROR_INVALID_HANDLE);
            0
        }
    }
}

fn get_process_heap(_: &Arc<Process>, _: [u64; 4]) -> u64 {
    HEAP_HANDLE
}

/// Size class of a request: 16-byte steps up to 1 KiB, then powers of two (capacity of the block).
fn heap_class(size: u64) -> u64 {
    let need = (size.max(1) + 15) & !15;
    if need <= 1024 { need } else { need.next_power_of_two() }
}

/// Process heap over mapped arenas. Blocks carry a 16-byte header holding their capacity (size class); freed blocks go
/// to per-class free lists and are reused. Flag 8 (HEAP_ZERO_MEMORY) zeroes a recycled block.
pub fn heap_alloc(p: &Arc<Process>, a: [u64; 4]) -> u64 {
    let size = a[2];
    if size > 32 * 1024 * 1024 {
        set_err(p, ERROR_NOT_ENOUGH_MEMORY);
        return 0;
    }
    let cap = heap_class(size);
    // reuse a freed block of this class
    let reused = p.foreign.lock().heap_free.get_mut(&cap).and_then(|v| v.pop());
    if let Some(block) = reused {
        if a[1] & 8 != 0 {
            let zeros = alloc::vec![0u8; cap as usize];
            let _ = write_user(p, block, &zeros);
        }
        return block;
    }
    let need = 16 + cap;
    let (mut next, mut end) = {
        let f = p.foreign.lock();
        (f.heap_next, f.heap_end)
    };
    if next == 0 || next + need > end {
        let arena = core::cmp::max(1 << 20, (need + PAGE_SIZE - 1) & !(PAGE_SIZE - 1));
        let pages = (arena / PAGE_SIZE) as usize;
        let va = p.mmap_next.fetch_add((pages as u64 + 1) * PAGE_SIZE, core::sync::atomic::Ordering::SeqCst);
        if p.map_region(va, pages, VmFlags::WRITE | VmFlags::USER).is_err() {
            set_err(p, ERROR_NOT_ENOUGH_MEMORY);
            return 0;
        }
        next = va;
        end = va + arena;
    }
    let block = next + 16;
    if write_user(p, next, &cap.to_le_bytes()).is_err() {
        set_err(p, ERROR_NOT_ENOUGH_MEMORY);
        return 0;
    }
    let mut f = p.foreign.lock();
    f.heap_next = next + need;
    f.heap_end = end;
    block
}

/// Capacity recorded in a block's header, if `ptr` looks like one of ours.
fn heap_block_cap(p: &Arc<Process>, ptr: u64) -> Option<u64> {
    if ptr < 16 || ptr % 16 != 0 {
        return None;
    }
    let mut hdr = [0u8; 8];
    copy_from_user(p, &mut hdr, ptr - 16).ok()?;
    let cap = u64::from_le_bytes(hdr);
    (cap >= 16 && cap <= 64 * 1024 * 1024 && cap == heap_class(cap)).then_some(cap)
}

/// free(ptr) / HeapFree: recycle the block. Foreign or doubly freed pointers are ignored.
pub fn heap_free(p: &Arc<Process>, ptr: u64) -> u64 {
    if ptr == 0 {
        return 1;
    }
    let Some(cap) = heap_block_cap(p, ptr) else { return 0 };
    let mut f = p.foreign.lock();
    let list = f.heap_free.entry(cap).or_default();
    if list.iter().rev().take(16).any(|b| *b == ptr) {
        return 0; // double free
    }
    list.push(ptr);
    1
}

pub fn heap_size(p: &Arc<Process>, a: [u64; 4]) -> u64 {
    heap_block_cap(p, a[2]).unwrap_or(u64::MAX)
}

pub fn heap_free_shim(p: &Arc<Process>, a: [u64; 4]) -> u64 {
    heap_free(p, a[2])
}

pub fn heap_realloc(p: &Arc<Process>, a: [u64; 4]) -> u64 {
    // args: heap, flags, ptr, size (4th arg arrives in r9)
    let (ptr, size) = (a[2], a[3]);
    if ptr == 0 {
        return heap_alloc(p, [a[0], a[1], size, 0]);
    }
    let old_cap = heap_block_cap(p, ptr);
    if let Some(c) = old_cap {
        if size <= c && size > c / 2 {
            return ptr; // fits in place
        }
    }
    let new = heap_alloc(p, [a[0], a[1], size, 0]);
    if new == 0 {
        return 0;
    }
    let old = old_cap.unwrap_or(size).min(size);
    let mut moved = 0u64;
    let mut buf = [0u8; 4096];
    while moved < old {
        let n = core::cmp::min(old - moved, 4096) as usize;
        if copy_from_user(p, &mut buf[..n], ptr + moved).is_err() || write_user(p, new + moved, &buf[..n]).is_err() {
            break;
        }
        moved += n as u64;
    }
    heap_free(p, ptr);
    new
}

fn get_last_error(p: &Arc<Process>, _: [u64; 4]) -> u64 {
    p.foreign.lock().last_error as u64
}

fn set_last_error(p: &Arc<Process>, a: [u64; 4]) -> u64 {
    set_err(p, a[0] as u32);
    0
}

fn tls_slots<'a>(f: &'a mut super::ForeignState, tid: u64) -> &'a mut [u64; 64] {
    if let Some(i) = f.tls_threads.iter().position(|(t, _)| *t == tid) {
        return &mut f.tls_threads[i].1;
    }
    f.tls_threads.push((tid, [0; 64]));
    let n = f.tls_threads.len() - 1;
    &mut f.tls_threads[n].1
}

fn tls_alloc(p: &Arc<Process>, _: [u64; 4]) -> u64 {
    let mut f = p.foreign.lock();
    for i in 0..64 {
        if f.tls_used & (1 << i) == 0 {
            f.tls_used |= 1 << i;
            for (_, v) in f.tls_threads.iter_mut() {
                v[i] = 0;
            }
            return i as u64;
        }
    }
    0xFFFF_FFFF // TLS_OUT_OF_INDEXES
}

fn tls_get(p: &Arc<Process>, a: [u64; 4]) -> u64 {
    let i = a[0] as usize;
    if i < 64 {
        let tid = task::current_ids().1;
        tls_slots(&mut p.foreign.lock(), tid)[i]
    } else {
        0
    }
}

fn tls_set(p: &Arc<Process>, a: [u64; 4]) -> u64 {
    let i = a[0] as usize;
    if i < 64 {
        let tid = task::current_ids().1;
        tls_slots(&mut p.foreign.lock(), tid)[i] = a[1];
        1
    } else {
        0
    }
}

fn get_system_time(p: &Arc<Process>, a: [u64; 4]) -> u64 {
    // FILETIME: 100 ns units since 1601; anchor at a fixed epoch + uptime.
    let ft = (time::unix_ms() + 11_644_473_600_000) * 10_000; // FILETIME: 100 ns since 1601
    let _ = copy_to_user(p, a[0], &ft.to_le_bytes());
    0
}

fn query_perf_counter(p: &Arc<Process>, a: [u64; 4]) -> u64 {
    let v = time::uptime_ms() * 10_000; // 10 MHz counter
    if copy_to_user(p, a[0], &v.to_le_bytes()).is_err() {
        return 0;
    }
    1
}

fn query_perf_freq(p: &Arc<Process>, a: [u64; 4]) -> u64 {
    if copy_to_user(p, a[0], &10_000_000u64.to_le_bytes()).is_err() {
        return 0;
    }
    1
}

fn get_tick_count(_: &Arc<Process>, _: [u64; 4]) -> u64 {
    time::uptime_ms()
}

fn sleep(_: &Arc<Process>, a: [u64; 4]) -> u64 {
    task::sleep_ms((a[0] as u32 as u64).min(60_000));
    0
}

fn get_pid(p: &Arc<Process>, _: [u64; 4]) -> u64 {
    p.pid
}

fn get_tid(_: &Arc<Process>, _: [u64; 4]) -> u64 {
    task::current_ids().1
}

fn get_current_process(_: &Arc<Process>, _: [u64; 4]) -> u64 {
    u64::MAX
}

fn close_any(p: &Arc<Process>, a: [u64; 4]) -> u64 {
    if let Some(r) = wt::close_obj(p, a[0]) {
        return r;
    }
    w32::close_handle(p, a)
}

/// GetSystemTimePreciseAsFileTime = GetSystemTimeAsFileTime
fn w32_system_time_alias(p: &Arc<Process>, a: [u64; 4]) -> u64 {
    match SHIMS.iter().find(|(n, _)| *n == "GetSystemTimeAsFileTime") {
        Some((_, f)) => f(p, a),
        None => 0,
    }
}
