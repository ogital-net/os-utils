#![doc = include_str!("../README.md")]
// README and other crate-level docs use `fn main` for blocks that would otherwise
// produce bare-expression lint warnings; allow it explicitly.
#![allow(clippy::needless_doctest_main)]

use std::{
    borrow::Cow,
    ffi::{CStr, CString, OsStr},
    fmt::Write as _,
    io::{IoSlice, IoSliceMut},
    mem::MaybeUninit,
    os::{fd::AsRawFd, unix::ffi::OsStrExt},
    path::{Path, PathBuf},
    time::Duration,
};

// borrowed from rust std lib internals
#[cfg(any(
    target_os = "dragonfly",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_vendor = "apple",
    target_os = "cygwin",
))]
const fn max_iov() -> usize {
    libc::IOV_MAX as usize
}

#[cfg(any(
    target_os = "android",
    target_os = "emscripten",
    target_os = "linux",
    target_os = "nto",
))]
const fn max_iov() -> usize {
    libc::UIO_MAXIOV as usize
}

#[cfg(not(any(
    target_os = "android",
    target_os = "dragonfly",
    target_os = "emscripten",
    target_os = "espidf",
    target_os = "freebsd",
    target_os = "linux",
    target_os = "netbsd",
    target_os = "nuttx",
    target_os = "nto",
    target_os = "openbsd",
    target_os = "horizon",
    target_os = "vita",
    target_vendor = "apple",
    target_os = "cygwin",
)))]
const fn max_iov() -> usize {
    16 // The minimum value required by POSIX.
}

/// Represents system identification information, wrapping the `libc::utsname` structure.
/// This struct provides a safe interface to access system information such as operating system name,
/// host name, kernel version, etc.
pub struct UtsName {
    inner: libc::utsname,
}

impl UtsName {
    /// Retrieves system identification information by calling the system's `uname` function.
    ///
    /// # Returns
    /// - `Ok(UtsName)` containing the system information if successful
    /// - `Err(std::io::Error)` if the system call fails
    ///
    /// # Example
    /// ```
    /// let info = os_utils::UtsName::new().unwrap();
    /// println!("System: {}", info.sysname());
    /// println!("Node: {}", info.nodename());
    /// println!("Release: {}", info.release());
    /// println!("Version: {}", info.version());
    /// println!("Machine: {}", info.machine());
    /// ```
    pub fn new() -> std::io::Result<Self> {
        let (res, utsname) = unsafe {
            // SAFETY: utsname is properly initialized by the system call if it returns 0.
            // We initialize the struct with MaybeUninit and only call assume_init after the system call.
            let mut utsname = MaybeUninit::<libc::utsname>::uninit();
            let res = libc::uname(utsname.as_mut_ptr());
            (res, utsname.assume_init())
        };

        if res == 0 {
            return Ok(UtsName { inner: utsname });
        }
        Err(std::io::Error::last_os_error())
    }

    /// Returns the operating system name (e.g., "Linux", "Darwin").
    ///
    /// Returns a borrowed `Cow::Borrowed(&str)` when the value is valid UTF-8, or an
    /// owned `Cow::Owned(String)` with non-UTF-8 bytes replaced by `U+FFFD`. The value
    /// returned by the kernel is preserved losslessly when it is UTF-8 and is otherwise
    /// recoverable instead of panicking.
    #[must_use]
    pub fn sysname(&self) -> Cow<'_, str> {
        // SAFETY: The sysname field in libc::utsname is a null-terminated C string
        // initialized by the uname system call.
        unsafe { CStr::from_ptr(self.inner.sysname.as_ptr()).to_string_lossy() }
    }

    /// Returns the network node hostname.
    ///
    /// Returns a borrowed `Cow::Borrowed(&str)` when the value is valid UTF-8, or an
    /// owned `Cow::Owned(String)` with non-UTF-8 bytes replaced by `U+FFFD`. The value
    /// returned by the kernel is preserved losslessly when it is UTF-8 and is otherwise
    /// recoverable instead of panicking.
    #[must_use]
    pub fn nodename(&self) -> Cow<'_, str> {
        // SAFETY: The nodename field in libc::utsname is a null-terminated C string
        // initialized by the uname system call.
        unsafe { CStr::from_ptr(self.inner.nodename.as_ptr()).to_string_lossy() }
    }

    /// Returns the operating system release level.
    ///
    /// Returns a borrowed `Cow::Borrowed(&str)` when the value is valid UTF-8, or an
    /// owned `Cow::Owned(String)` with non-UTF-8 bytes replaced by `U+FFFD`. The value
    /// returned by the kernel is preserved losslessly when it is UTF-8 and is otherwise
    /// recoverable instead of panicking.
    #[must_use]
    pub fn release(&self) -> Cow<'_, str> {
        // SAFETY: The release field in libc::utsname is a null-terminated C string
        // initialized by the uname system call.
        unsafe { CStr::from_ptr(self.inner.release.as_ptr()).to_string_lossy() }
    }

    /// Returns the operating system version.
    ///
    /// Returns a borrowed `Cow::Borrowed(&str)` when the value is valid UTF-8, or an
    /// owned `Cow::Owned(String)` with non-UTF-8 bytes replaced by `U+FFFD`. The value
    /// returned by the kernel is preserved losslessly when it is UTF-8 and is otherwise
    /// recoverable instead of panicking.
    #[must_use]
    pub fn version(&self) -> Cow<'_, str> {
        // SAFETY: The version field in libc::utsname is a null-terminated C string
        // initialized by the uname system call.
        unsafe { CStr::from_ptr(self.inner.version.as_ptr()).to_string_lossy() }
    }

    /// Returns the machine hardware name.
    ///
    /// Returns a borrowed `Cow::Borrowed(&str)` when the value is valid UTF-8, or an
    /// owned `Cow::Owned(String)` with non-UTF-8 bytes replaced by `U+FFFD`. The value
    /// returned by the kernel is preserved losslessly when it is UTF-8 and is otherwise
    /// recoverable instead of panicking.
    #[must_use]
    pub fn machine(&self) -> Cow<'_, str> {
        // SAFETY: The machine field in libc::utsname is a null-terminated C string
        // initialized by the uname system call.
        unsafe { CStr::from_ptr(self.inner.machine.as_ptr()).to_string_lossy() }
    }

    /// Returns the Network Information System (NIS) domain name.
    ///
    /// This method is only available on Linux systems.
    ///
    /// Returns a borrowed `Cow::Borrowed(&str)` when the value is valid UTF-8, or an
    /// owned `Cow::Owned(String)` with non-UTF-8 bytes replaced by `U+FFFD`. The value
    /// returned by the kernel is preserved losslessly when it is UTF-8 and is otherwise
    /// recoverable instead of panicking.
    #[cfg(target_os = "linux")]
    #[must_use]
    pub fn domainname(&self) -> Cow<'_, str> {
        // SAFETY: The domainname field in libc::utsname is a null-terminated C string
        // initialized by the uname system call.
        unsafe { CStr::from_ptr(self.inner.domainname.as_ptr()).to_string_lossy() }
    }
}

/// Returns system information as a single space-separated string.
///
/// The output intentionally mirrors the format of `uname -snrvmo`, not `uname -a`:
/// some Linux distributions ship a patched `uname` whose `-a` output is
/// non-standard, so the exact field set and order of `uname -a` is not portable.
/// Use [`UtsName`] directly when the individual fields are needed.
///
/// # Returns
/// * `Ok(String)` containing the formatted system information
/// * `Err(std::io::Error)` if retrieving system information failed
///
/// # Example
/// ```
/// let info = os_utils::uname().unwrap();
/// println!("{}", info);
/// // Linux:   "Linux hostname 5.15.0-1 #1 SMP ... x86_64 GNU/Linux"
/// // macOS:   "Darwin hostname 23.6.0 Darwin Kernel Version 23.6.0:... x86_64"
/// ```
pub fn uname() -> std::io::Result<String> {
    let info = UtsName::new()?;

    let mut buf = String::with_capacity(128);
    write!(
        buf,
        "{} {} {} {} {}",
        info.sysname(),
        info.nodename(),
        info.release(),
        info.version(),
        info.machine()
    )
    .expect("write failed");

    #[cfg(target_os = "linux")]
    {
        // Linux uname -a format includes "GNU/Linux" at the end
        const HOST_OPERATING_SYSTEM: &str = "GNU/Linux";
        write!(buf, " {HOST_OPERATING_SYSTEM}").expect("write failed");
    }

    Ok(buf)
}

/// Represents the scheduling policy for a thread.
///
/// - `Other`: Standard round-robin time-sharing scheduling policy (SCHED_OTHER)
/// - `FIFO`: First-in-first-out real-time scheduling policy (SCHED_FIFO)
/// - `RoundRobin`: Round-robin real-time scheduling policy (SCHED_RR)
pub enum SchedPolicy {
    /// Standard scheduling policy for normal processes
    Other,
    /// First-in-first-out real-time scheduling policy
    FIFO,
    /// Round-robin real-time scheduling policy
    RoundRobin,
}

/// Converts the `SchedPolicy` enum to the corresponding `libc` constant.
impl From<SchedPolicy> for libc::c_int {
    fn from(policy: SchedPolicy) -> Self {
        match policy {
            SchedPolicy::Other => libc::SCHED_OTHER,
            SchedPolicy::FIFO => libc::SCHED_FIFO,
            SchedPolicy::RoundRobin => libc::SCHED_RR,
        }
    }
}

/// Sets the scheduling policy and priority for the current thread.
///
/// # Arguments
/// * `policy` - The scheduling policy to set
/// * `sched_priority` - The scheduling priority (must be within valid range for the policy)
///
/// # Returns
/// * `Ok(())` if successful
/// * `Err(std::io::Error)` if setting the scheduler failed (e.g., insufficient privileges)
///
/// # Notes
/// Setting real-time scheduling policies (FIFO, RoundRobin) typically requires root privileges.
///
/// # Example
/// ```no_run
/// use os_utils::{SchedPolicy, thread_setscheduler};
/// // Real-time policies require root privileges
/// thread_setscheduler(SchedPolicy::RoundRobin, 1).unwrap();
/// // Standard scheduling works without elevated privileges
/// thread_setscheduler(SchedPolicy::Other, 0).unwrap();
/// ```
pub fn thread_setscheduler(policy: SchedPolicy, sched_priority: i32) -> std::io::Result<()> {
    // SAFETY: MaybeUninit::zeroed() initializes all bytes to zero, which is a valid
    // initialization for libc::sched_param.
    let mut params = unsafe { MaybeUninit::<libc::sched_param>::zeroed().assume_init() };
    params.sched_priority = sched_priority;
    // SAFETY: pthread_setschedparam is a valid POSIX function that operates on the current thread.
    // The parameters are valid: pthread_self() returns the current thread, policy is converted from
    // our enum, and params is properly initialized.
    let res = unsafe { libc::pthread_setschedparam(libc::pthread_self(), policy.into(), &params) };
    if res == 0 {
        return Ok(());
    }
    Err(std::io::Error::last_os_error())
}

/// Sets the scheduling priority (nice value) for the current process.
///
/// # Arguments
/// * `prio` - Priority value (nice value) to set. Higher values mean lower priority.
///   The range is typically from -20 (highest priority) to 19 (lowest priority).
///
/// # Returns
/// * `Ok(())` if successful
/// * `Err(std::io::Error)` if setting the priority failed (e.g., insufficient privileges)
///
/// # Notes
/// Setting a negative nice value (higher priority) typically requires root privileges.
///
/// # Example
/// ```
/// // Lowering priority (higher nice value) does not require elevated privileges
/// os_utils::process_setpriority(10).unwrap();
/// ```
pub fn process_setpriority(prio: i32) -> std::io::Result<()> {
    // SAFETY: setpriority is a valid POSIX function. The arguments are safe:
    // PRIO_PROCESS is a valid constant, getpid() returns the current process ID,
    // and prio is a valid i32 that will be converted appropriately.
    let res = unsafe { libc::setpriority(libc::PRIO_PROCESS, libc::getpid() as libc::id_t, prio) };
    if res == 0 {
        return Ok(());
    }
    Err(std::io::Error::last_os_error())
}

/// Returns the hostname of the system.
///
/// This is a convenience wrapper around `UtsName::new()?.nodename()`. The
/// hostname is owned (an allocation) because `UtsName` is consumed for the
/// duration of the call and the result outlives it; use
/// [`UtsName::new`] directly if you need to avoid the allocation or read
/// other fields from the same uname snapshot.
///
/// # Returns
/// * `Ok(String)` containing the hostname if successful
/// * `Err(std::io::Error)` if retrieving the hostname failed
///
/// # Example
/// ```
/// let hostname = os_utils::gethostname().unwrap();
/// println!("Hostname: {}", hostname);
/// ```
pub fn gethostname() -> std::io::Result<String> {
    Ok(UtsName::new()?.nodename().into_owned())
}

#[link(name = "c")]
unsafe extern "C" {
    fn uptime_sys_c() -> u64;
    fn uptime_proc_c(id: i32) -> u64;
    fn rss_self_c() -> usize;
}

/// Returns the system uptime (time since boot).
///
/// # Returns
/// A `Duration` representing how long the system has been running.
///
/// # Example
/// ```
/// let uptime = os_utils::uptime_sys();
/// println!("System uptime: {:?}", uptime);
/// ```
pub fn uptime_sys() -> Duration {
    unsafe { Duration::from_nanos(uptime_sys_c()) }
}

/// Returns the uptime of a specific process.
///
/// # Arguments
/// * `id` - Process ID to get the uptime for. Must fit in an `i32` (i.e. <= 2^31 - 1),
///   matching the OS-level `pid_t` width on supported platforms. Larger values
///   return an `InvalidInput` error rather than silently wrapping to a negative
///   PID that would be rejected by the kernel.
///
/// # Returns
/// A `Duration` representing how long the process has been running.
///
/// # Example
/// ```
/// let uptime = os_utils::uptime_proc(std::process::id());
/// println!("Process uptime: {:?}", uptime);
/// ```
pub fn uptime_proc(id: u32) -> Duration {
    let pid = i32::try_from(id).expect("pid exceeds i32::MAX");
    unsafe { Duration::from_nanos(uptime_proc_c(pid)) }
}

/// Returns the uptime of the container (for containerized environments).
///
/// This is equivalent to getting the uptime of process ID 1 (init process).
///
/// # Returns
/// A `Duration` representing how long the container has been running.
///
/// # Example
/// ```
/// let uptime = os_utils::uptime_container();
/// println!("Container uptime: {:?}", uptime);
/// ```
pub fn uptime_container() -> Duration {
    uptime_proc(1)
}

/// Returns the resident set size (RSS) of the current process.
///
/// The resident set size is the portion of a process's memory that is held in main memory (RAM).
/// Returns `0` on systems where RSS cannot be read (for example, kernels without
/// `/proc/self/statm`, or macOS sandbox profiles that deny `task_info`); use
/// [`rss_self_opt`] to distinguish that case from a real zero-byte measurement.
///
/// # Platform-specific
/// - **macOS/Darwin**: Uses `task_info` with `TASK_BASIC_INFO` to get memory information.
/// - **Linux**: Reads from `/proc/self/statm` and converts pages to bytes.
///
/// # Example
/// ```
/// let rss = os_utils::rss_self();
/// println!("RSS: {} bytes", rss);
/// ```
pub fn rss_self() -> usize {
    rss_self_opt().unwrap_or(0)
}

/// Returns the resident set size (RSS) of the current process, or `None` if it
/// could not be measured.
///
/// See [`rss_self`] for details. This variant is preferred when the caller
/// needs to distinguish a real zero-byte measurement from a failure to read
/// the underlying kernel interface (for example, to log an error rather than
/// silently report zero memory usage).
///
/// # Example
/// ```
/// if let Some(rss) = os_utils::rss_self_opt() {
///     println!("RSS: {} bytes", rss);
/// } else {
///     println!("RSS unavailable on this platform");
/// }
/// ```
pub fn rss_self_opt() -> Option<usize> {
    // rss_self_c returns usize::MAX to signal "could not measure". A running
    // process always has at least one resident page, so the success path is
    // at least _SC_PAGESIZE bytes -- never 0 and never near usize::MAX.
    let rss = unsafe { rss_self_c() };
    if rss == usize::MAX {
        None
    } else {
        Some(rss)
    }
}

/// Generates cryptographically secure random bytes using the Linux `getrandom` system call.
///
/// # Arguments
/// * `dst` - Slice to fill with random bytes
///
/// # Returns
/// * `Ok(())` if the random bytes were successfully generated
/// * `Err(std::io::Error)` if generation failed or couldn't generate enough bytes
///
/// # Platform-specific
/// This implementation is only available on Linux systems.
///
/// # Example
/// ```
/// use os_utils::{rand_bytes, rand_u32, rand_u64};
/// let mut buffer = vec![0u8; 32];
/// rand_bytes(&mut buffer).unwrap();
/// println!("Random u32: {}", rand_u32().unwrap());
/// println!("Random u64: {}", rand_u64().unwrap());
/// ```
#[cfg(target_os = "linux")]
pub fn rand_bytes(dst: &mut [u8]) -> std::io::Result<()> {
    let need = dst.len();
    if need == 0 {
        return Ok(());
    }

    let mut filled = 0;
    while filled < need {
        let res = unsafe {
            // SAFETY: `dst[filled..]` is a valid, properly-aligned slice of length
            // `need - filled` for the duration of the call.
            libc::getrandom(
                dst[filled..].as_mut_ptr() as *mut libc::c_void,
                need - filled,
                0,
            )
        };
        if res < 0 {
            let err = std::io::Error::last_os_error();
            // getrandom returns EINTR if interrupted by a signal before any bytes
            // were written, and EAGAIN very early in boot before the entropy pool
            // is initialized. Both are transient; retry.
            if err.raw_os_error() == Some(libc::EINTR) || err.raw_os_error() == Some(libc::EAGAIN) {
                continue;
            }
            return Err(err);
        }
        filled += res as usize;
        // getrandom can also return fewer bytes than requested without setting
        // errno; the loop covers that case naturally on the next iteration.
    }
    Ok(())
}

/// Generates cryptographically secure random bytes using macOS's Common Crypto framework.
///
/// # Arguments
/// * `dst` - Slice to fill with random bytes
///
/// # Returns
/// * `Ok(())` if the random bytes were successfully generated
/// * `Err(std::io::Error)` if generation failed
///
/// # Platform-specific
/// This implementation is only available on macOS systems.
///
/// # Example
/// ```
/// use os_utils::{rand_bytes, rand_u32, rand_u64};
/// let mut buffer = vec![0u8; 32];
/// rand_bytes(&mut buffer).unwrap();
/// println!("Random u32: {}", rand_u32().unwrap());
/// println!("Random u64: {}", rand_u64().unwrap());
/// ```
#[cfg(target_os = "macos")]
pub fn rand_bytes(dst: &mut [u8]) -> std::io::Result<()> {
    let need = dst.len();
    if need == 0 {
        return Ok(());
    }

    // SAFETY: CCRandomGenerateBytes is a valid macOS function. The buffer pointer is valid
    // and properly aligned, and the length matches the slice size.
    if unsafe { libc::CCRandomGenerateBytes(dst.as_mut_ptr() as *mut libc::c_void, need) } != 0 {
        Err(std::io::Error::other(format!(
            "Unable to generate {need} random bytes"
        )))
    } else {
        Ok(())
    }
}

/// Generates a cryptographically secure random 32-bit unsigned integer.
///
/// # Returns
/// `Ok(u32)` containing 4 random bytes from the system's secure random number generator,
/// or an `io::Error` if the underlying RNG call fails (e.g., `ENOSYS` on a kernel
/// without `getrandom`).
///
/// # Example
/// ```
/// let random_num = os_utils::rand_u32()?;
/// println!("Random u32: {}", random_num);
/// # Ok::<(), std::io::Error>(())
/// ```
pub fn rand_u32() -> std::io::Result<u32> {
    let mut buf = [0u8; 4];
    rand_bytes(&mut buf)?;
    Ok(u32::from_ne_bytes(buf))
}

/// Generates a cryptographically secure random 64-bit unsigned integer.
///
/// # Returns
/// `Ok(u64)` containing 8 random bytes from the system's secure random number generator,
/// or an `io::Error` if the underlying RNG call fails (e.g., `ENOSYS` on a kernel
/// without `getrandom`).
///
/// # Example
/// ```
/// let random_num = os_utils::rand_u64()?;
/// println!("Random u64: {}", random_num);
/// # Ok::<(), std::io::Error>(())
/// ```
pub fn rand_u64() -> std::io::Result<u64> {
    let mut buf = [0u8; 8];
    rand_bytes(&mut buf)?;
    Ok(u64::from_ne_bytes(buf))
}

/// Returns the system load averages for the past 1, 5, and 15 minutes.
///
/// Uses macOS's native `getloadavg` function.
///
/// # Returns
/// * `Ok([f64; 3])` containing the 1, 5, and 15 minute load averages if successful
/// * `Err(std::io::Error)` if retrieving the load averages failed
///
/// # Platform-specific
/// This implementation is only available on macOS systems.
///
/// # Example
/// ```
/// let [one, five, fifteen] = os_utils::getloadavg().unwrap();
/// println!("Load averages: {:.2} {:.2} {:.2}", one, five, fifteen);
/// ```
#[cfg(target_os = "macos")]
pub fn getloadavg() -> std::io::Result<[f64; 3]> {
    let mut loadavg = [0f64, 0f64, 0f64];
    // SAFETY: getloadavg is a valid macOS function. The array pointer is valid and
    // properly aligned, and the length is correct (3 elements).
    let res = unsafe { libc::getloadavg(loadavg.as_mut_ptr(), loadavg.len() as libc::c_int) };
    if res != loadavg.len() as i32 {
        return Err(std::io::Error::other("Unable to retrieve load average."));
    }
    Ok(loadavg)
}

/// Returns the system load averages for the past 1, 5, and 15 minutes.
///
/// Uses Linux's `sysinfo` system call to retrieve load averages.
///
/// # Returns
/// * `Ok([f64; 3])` containing the 1, 5, and 15 minute load averages if successful
/// * `Err(std::io::Error)` if retrieving the load averages failed
///
/// # Platform-specific
/// This implementation is only available on Linux systems.
///
/// # Example
/// ```
/// let [one, five, fifteen] = os_utils::getloadavg().unwrap();
/// println!("Load averages: {:.2} {:.2} {:.2}", one, five, fifteen);
/// ```
#[cfg(target_os = "linux")]
pub fn getloadavg() -> std::io::Result<[f64; 3]> {
    let mut loadavg = [0f64, 0f64, 0f64];

    let si = unsafe {
        // SAFETY: sysinfo is a valid Linux system call. We initialize the structure with
        // MaybeUninit and only call assume_init after confirming the system call succeeded.
        let mut si = MaybeUninit::<libc::sysinfo>::uninit();
        if libc::sysinfo(si.as_mut_ptr()) != 0 {
            return Err(std::io::Error::last_os_error());
        };
        si.assume_init()
    };

    // `sysinfo()` reports `loads[i]` as a fixed-point number: the actual load average
    // is `loads[i] / (1 << SI_LOAD_SHIFT)`. SI_LOAD_SHIFT is 16 on every Linux ABI we
    // support, but using `1u64 << SI_LOAD_SHIFT` keeps the math correct if that ever
    // changes. We use u64 to avoid shifting into the sign bit on a 32-bit `c_ulong`.
    let scale = (1u64 << libc::SI_LOAD_SHIFT) as f64;
    for (slot, raw) in loadavg.iter_mut().zip(si.loads.iter()) {
        *slot = *raw as f64 / scale;
    }

    Ok(loadavg)
}

/// Space and inode usage for a filesystem.
///
/// The `free` values include resources reserved for privileged users, while
/// the `available` values report what unprivileged users can allocate.
/// Returned by [`disk_free`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DiskUsage {
    total_bytes: u64,
    used_bytes: u64,
    free_bytes: u64,
    available_bytes: u64,
    total_inodes: u64,
    free_inodes: u64,
    available_inodes: u64,
}

impl DiskUsage {
    /// Returns the total filesystem capacity in bytes.
    #[must_use]
    pub const fn total_bytes(&self) -> u64 {
        self.total_bytes
    }

    /// Returns the number of free bytes, including space reserved for
    /// privileged users.
    #[must_use]
    pub const fn free_bytes(&self) -> u64 {
        self.free_bytes
    }

    /// Returns the number of bytes available to unprivileged users.
    #[must_use]
    pub const fn available_bytes(&self) -> u64 {
        self.available_bytes
    }

    /// Returns the number of bytes in use.
    ///
    /// On macOS this uses the volume's `ATTR_VOL_SPACEUSED` value, matching
    /// `df` for filesystems such as APFS whose volumes share container space.
    /// Other platforms derive this as `total_bytes - free_bytes`.
    #[must_use]
    pub const fn used_bytes(&self) -> u64 {
        self.used_bytes
    }

    /// Returns the total number of inodes in the filesystem.
    #[must_use]
    pub const fn total_inodes(&self) -> u64 {
        self.total_inodes
    }

    /// Returns the number of free inodes, including those reserved for
    /// privileged users.
    #[must_use]
    pub const fn free_inodes(&self) -> u64 {
        self.free_inodes
    }

    /// Returns the number of inodes available to unprivileged users.
    #[must_use]
    pub const fn available_inodes(&self) -> u64 {
        self.available_inodes
    }

    /// Returns the number of inodes in use (`total_inodes - free_inodes`).
    #[must_use]
    pub const fn used_inodes(&self) -> u64 {
        self.total_inodes.saturating_sub(self.free_inodes)
    }
}

#[cfg(target_os = "macos")]
fn macos_used_bytes(path: &CStr) -> Option<u64> {
    #[repr(C, packed(4))]
    struct VolumeSpaceUsed {
        size: u32,
        space_used: u64,
    }

    let mut attributes = libc::attrlist {
        bitmapcount: libc::ATTR_BIT_MAP_COUNT,
        reserved: 0,
        commonattr: 0,
        volattr: libc::ATTR_VOL_INFO | libc::ATTR_VOL_SPACEUSED,
        dirattr: 0,
        fileattr: 0,
        forkattr: 0,
    };
    let mut result = VolumeSpaceUsed {
        size: 0,
        space_used: 0,
    };

    let status = unsafe {
        // SAFETY: `path` is NUL-terminated, and both pointers refer to valid,
        // writable values whose sizes match the Darwin `getattrlist` ABI.
        libc::getattrlist(
            path.as_ptr(),
            (&mut attributes as *mut libc::attrlist).cast(),
            (&mut result as *mut VolumeSpaceUsed).cast(),
            std::mem::size_of::<VolumeSpaceUsed>(),
            0,
        )
    };
    if status != 0 || result.size as usize != std::mem::size_of::<VolumeSpaceUsed>() {
        return None;
    }

    Some(unsafe {
        // SAFETY: `getattrlist` populated the complete packed result buffer.
        std::ptr::addr_of!(result.space_used).read_unaligned()
    })
}

/// Returns disk free information for a given path.
///
/// # Arguments
/// * `path` - The filesystem path to query.
///
/// # Errors
/// Returns [`std::io::Error`] if the underlying `statvfs` call fails, a byte
/// count overflows `u64`, or the path contains an interior NUL byte.
///
/// On macOS, used space is read from `ATTR_VOL_SPACEUSED` to match `df` on
/// APFS volumes. If that attribute is unavailable, it falls back to the
/// portable `total - free` calculation used on other platforms.
///
/// # Example
/// ```
/// let usage = os_utils::disk_free("/").unwrap();
/// println!(
///     "Disk free: {} / {} bytes ({:.1}% used)",
///     usage.available_bytes(),
///     usage.total_bytes(),
///     (usage.used_bytes() as f64
///         / (usage.used_bytes() as f64 + usage.available_bytes() as f64))
///         * 100.0,
/// );
/// ```
pub fn disk_free<P: AsRef<Path>>(path: P) -> std::io::Result<DiskUsage> {
    let path_cstr = CString::new(path.as_ref().as_os_str().as_encoded_bytes())
        .map_err(|_| std::io::Error::other("Path contains null byte"))?;

    let stat = unsafe {
        // SAFETY: statvfs is a valid POSIX system call. We initialize the structure with
        // MaybeUninit and only call assume_init after confirming the system call succeeded.
        let mut stat = MaybeUninit::<libc::statvfs>::uninit();
        if libc::statvfs(path_cstr.as_ptr(), stat.as_mut_ptr()) != 0 {
            return Err(std::io::Error::last_os_error());
        }
        stat.assume_init()
    };

    let total_blocks = stat.f_blocks as u64;
    let free_blocks = stat.f_bfree as u64;
    let available_blocks = stat.f_bavail as u64;
    let block_size = stat.f_frsize as u64;
    let total_inodes = stat.f_files as u64;
    let free_inodes = stat.f_ffree as u64;
    let available_inodes = stat.f_favail as u64;
    let blocks_to_bytes = |blocks: u64| {
        blocks.checked_mul(block_size).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "filesystem capacity exceeds u64",
            )
        })
    };
    let total_bytes = blocks_to_bytes(total_blocks)?;
    let free_bytes = blocks_to_bytes(free_blocks)?;
    let portable_used_bytes = total_bytes.saturating_sub(free_bytes);
    #[cfg(target_os = "macos")]
    let used_bytes = macos_used_bytes(&path_cstr).unwrap_or(portable_used_bytes);
    #[cfg(not(target_os = "macos"))]
    let used_bytes = portable_used_bytes;

    Ok(DiskUsage {
        total_bytes,
        used_bytes,
        free_bytes,
        available_bytes: blocks_to_bytes(available_blocks)?,
        total_inodes,
        free_inodes,
        available_inodes,
    })
}

/// # Example
/// ```
/// use os_utils::TtyInfo;
/// let stdin = os_utils::Stdin::new();
/// if stdin.isatty() {
///     println!("Terminal: {}", stdin.ttyname().unwrap().display());
/// } else {
///     println!("stdin is not a TTY");
/// }
/// ```
pub trait TtyInfo {
    /// Returns whether stdin is connected to a terminal.
    ///
    /// # Returns
    /// `true` if stdin is a terminal, `false` otherwise.
    fn isatty(&self) -> bool;

    /// Returns the name of the terminal device connected to stdin.
    ///
    /// # Returns
    /// * `Ok(String)` containing the terminal device name (e.g., "/dev/ttys001")
    /// * `Err(std::io::Error)` if stdin is not connected to a terminal or an error occurs
    fn ttyname(&self) -> std::io::Result<PathBuf>;
}

impl<T: AsRawFd> TtyInfo for T {
    fn isatty(&self) -> bool {
        unsafe {
            // SAFETY: isatty is always safe to call with any file descriptor.
            // It returns 1 if the fd refers to a terminal, 0 otherwise.
            libc::isatty(self.as_raw_fd()) == 1
        }
    }

    fn ttyname(&self) -> std::io::Result<PathBuf> {
        // Start with a small buffer and grow on ERANGE
        let mut buf = vec![0u8; 256];
        loop {
            let result = unsafe {
                // SAFETY: `buf` is a valid heap allocation of `buf.len()` bytes;
                // `ttyname_r` writes at most that many bytes including the NUL.
                libc::ttyname_r(
                    self.as_raw_fd(),
                    buf.as_mut_ptr() as *mut libc::c_char,
                    buf.len(),
                )
            };
            match result {
                0 => {
                    let name = unsafe {
                        // SAFETY: `ttyname_r` returned 0 and writes a NUL-terminated
                        // string into the buffer on success.
                        CStr::from_ptr(buf.as_ptr() as *const libc::c_char)
                    }
                    .to_bytes();
                    return Ok(PathBuf::from(OsStr::from_bytes(name)));
                }
                libc::ERANGE => {
                    // Buffer too small; double and retry. Cap at 64 KiB to avoid
                    // runaway allocation if the kernel is misbehaving.
                    if buf.len() >= 65536 {
                        return Err(std::io::Error::from_raw_os_error(libc::ERANGE));
                    }
                    buf.resize(buf.len() * 2, 0);
                }
                other => return Err(std::io::Error::from_raw_os_error(other)),
            }
        }
    }
}

/// Represents standard input (file descriptor 0).
///
/// This struct provides a low-level interface to stdin using direct libc syscalls.
pub struct Stdin;

impl Stdin {
    /// Creates a new StdIn instance.
    pub fn new() -> Self {
        Stdin
    }
}

impl AsRawFd for Stdin {
    fn as_raw_fd(&self) -> std::os::unix::prelude::RawFd {
        libc::STDIN_FILENO
    }
}

impl std::io::Read for Stdin {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        loop {
            let result = unsafe {
                // SAFETY: `buf` is a valid, properly-aligned slice for the call.
                libc::read(
                    libc::STDIN_FILENO,
                    buf.as_mut_ptr() as *mut libc::c_void,
                    buf.len(),
                )
            };
            if result < 0 {
                let err = std::io::Error::last_os_error();
                if err.raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                return Err(err);
            }
            return Ok(result as usize);
        }
    }

    fn read_vectored(&mut self, bufs: &mut [IoSliceMut<'_>]) -> std::io::Result<usize> {
        let result = unsafe {
            libc::readv(
                libc::STDIN_FILENO,
                bufs.as_ptr().cast::<libc::iovec>(),
                std::cmp::min(bufs.len(), max_iov()) as libc::c_int,
            )
        };
        if result < 0 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(result as usize)
        }
    }
}

impl Default for Stdin {
    fn default() -> Self {
        Self::new()
    }
}

/// Represents standard output (file descriptor 1).
///
/// This struct provides a low-level interface to stdout using direct libc syscalls.
pub struct Stdout;

impl Stdout {
    /// Creates a new StdOut instance.
    ///
    /// # Example
    /// ```
    /// use std::io::Write;
    /// let mut out = os_utils::Stdout::new();
    /// out.write_all(b"hello from libc write\n").unwrap();
    /// ```
    pub fn new() -> Self {
        Stdout
    }
}

impl AsRawFd for Stdout {
    fn as_raw_fd(&self) -> std::os::unix::prelude::RawFd {
        libc::STDOUT_FILENO
    }
}

impl std::io::Write for Stdout {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let mut written = 0;
        while written < buf.len() {
            let result = unsafe {
                // SAFETY: `buf[written..]` is a valid, properly-aligned slice for the
                // duration of the call.
                libc::write(
                    libc::STDOUT_FILENO,
                    buf[written..].as_ptr().cast::<libc::c_void>(),
                    buf.len() - written,
                )
            };
            if result < 0 {
                let err = std::io::Error::last_os_error();
                if err.raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                return Err(err);
            }
            written += result as usize;
        }
        Ok(written)
    }

    fn write_vectored(&mut self, bufs: &[IoSlice<'_>]) -> std::io::Result<usize> {
        let result = unsafe {
            libc::writev(
                libc::STDOUT_FILENO,
                bufs.as_ptr() as *const libc::iovec,
                std::cmp::min(bufs.len(), max_iov()) as libc::c_int,
            )
        };
        if result < 0 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(result as usize)
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        // Unbuffered: writes go straight to fd 1, so there's nothing to flush.
        // This is a no-op that satisfies the `Write` trait contract.
        Ok(())
    }
}

impl Default for Stdout {
    fn default() -> Self {
        Self::new()
    }
}

/// Represents standard error (file descriptor 2).
///
/// This struct provides a low-level interface to stderr using direct libc syscalls.
pub struct Stderr;

impl Stderr {
    /// Creates a new StdErr instance.
    pub fn new() -> Self {
        Stderr
    }
}

impl AsRawFd for Stderr {
    fn as_raw_fd(&self) -> std::os::unix::prelude::RawFd {
        libc::STDERR_FILENO
    }
}

impl std::io::Write for Stderr {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let mut written = 0;
        while written < buf.len() {
            let result = unsafe {
                // SAFETY: `buf[written..]` is a valid, properly-aligned slice for the
                // duration of the call.
                libc::write(
                    libc::STDERR_FILENO,
                    buf[written..].as_ptr().cast::<libc::c_void>(),
                    buf.len() - written,
                )
            };
            if result < 0 {
                let err = std::io::Error::last_os_error();
                if err.raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                return Err(err);
            }
            written += result as usize;
        }
        Ok(written)
    }

    fn write_vectored(&mut self, bufs: &[IoSlice<'_>]) -> std::io::Result<usize> {
        let result = unsafe {
            libc::writev(
                libc::STDERR_FILENO,
                bufs.as_ptr() as *const libc::iovec,
                std::cmp::min(bufs.len(), max_iov()) as libc::c_int,
            )
        };
        if result < 0 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(result as usize)
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        // Unbuffered: writes go straight to fd 2, so there's nothing to flush.
        // This is a no-op that satisfies the `Write` trait contract.
        Ok(())
    }
}

impl Default for Stderr {
    fn default() -> Self {
        Self::new()
    }
}

/// A cryptographically secure random number generator that uses the operating system's
/// random number generation facilities.
///
/// `OsRng` is a zero-sized type that implements [`rand_core::TryRng`] and [`rand_core::TryCryptoRng`],
/// providing a bridge to use OS-level random number generation with the `rand_core` trait ecosystem.
///
/// # Platform-specific implementations
///
/// - **Linux**: Uses the `getrandom` system call
/// - **macOS**: Uses the `CCRandomGenerateBytes` function from Common Crypto
///
/// Both implementations provide cryptographically secure random numbers suitable for
/// security-sensitive applications.
///
/// # Feature flag
///
/// This type is only available when the `rand` feature is enabled.
///
/// # Errors
///
/// `TryRng::Error` is `std::io::Error`, so an underlying OS failure (such as
/// `getrandom` returning `ENOSYS` on a pre-3.17 Linux kernel) is surfaced
/// through the trait's `Result` return type rather than panicking.
///
/// # Examples
///
/// ```ignore
/// use os_utils::OsRng;
/// use rand_core::TryRng;
///
/// let mut rng = OsRng;
///
/// // Generate a random u32
/// let random_u32 = rng.try_next_u32().unwrap();
///
/// // Generate a random u64
/// let random_u64 = rng.try_next_u64().unwrap();
///
/// // Fill a buffer with random bytes
/// let mut buffer = [0u8; 32];
/// rng.try_fill_bytes(&mut buffer).unwrap();
/// ```
#[cfg(feature = "rand")]
#[derive(Debug, Clone, Copy, Default)]
pub struct OsRng;

#[cfg(feature = "rand")]
impl rand_core::TryRng for OsRng {
    type Error = std::io::Error;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        rand_u32()
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        rand_u64()
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        rand_bytes(dst)
    }
}

#[cfg(feature = "rand")]
impl rand_core::TryCryptoRng for OsRng {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_uname_success() {
        let uname = UtsName::new().expect("Failed to get system information");

        // Test that none of the fields are empty and are valid UTF-8
        assert!(!uname.sysname().is_empty());
        assert!(!uname.nodename().is_empty());
        assert!(!uname.release().is_empty());
        assert!(!uname.version().is_empty());
        assert!(!uname.machine().is_empty());
        #[cfg(target_os = "linux")]
        assert!(!uname.domainname().is_empty());
    }

    #[test]
    fn test_uname() {
        use std::process::Command;

        // Get output from our Rust function
        let rust_output = uname().expect("Failed to get uname output");

        // Execute system's uname command
        let system_output = Command::new("uname")
            .args(["-s", "-n", "-r", "-v", "-m", "-o"])
            .output()
            .expect("Failed to execute uname");

        let system_output_str = String::from_utf8_lossy(&system_output.stdout)
            .trim()
            .to_string();

        // Verify our function output matches system command output
        assert_eq!(
            rust_output, system_output_str,
            "Rust uname() output does not match system uname output.\nRust:   '{rust_output}'\nSystem: '{system_output_str}'"
        );

        println!("uname output verified: {rust_output}");
    }

    #[test]
    fn test_sched_policy_conversion() {
        assert_eq!(libc::c_int::from(SchedPolicy::Other), libc::SCHED_OTHER);
        assert_eq!(libc::c_int::from(SchedPolicy::FIFO), libc::SCHED_FIFO);
        assert_eq!(libc::c_int::from(SchedPolicy::RoundRobin), libc::SCHED_RR);
    }

    #[test]
    fn test_thread_setscheduler() {
        // Test with SCHED_OTHER which should work without elevated privileges
        let result = thread_setscheduler(SchedPolicy::Other, 0);
        assert!(result.is_ok(), "Setting SCHED_OTHER policy should succeed");

        // FIFO and RR typically require root privileges, so we'll test that they
        // either succeed or fail with EPERM
        let result = thread_setscheduler(SchedPolicy::FIFO, 1);
        match result {
            Ok(_) => (),
            Err(e) => assert_eq!(e.raw_os_error(), Some(libc::EPERM)),
        }
    }

    #[test]
    fn test_process_setpriority() {
        // Try to set priority to 0 (normal)
        let result = process_setpriority(0);
        assert!(result.is_ok(), "Setting normal priority should succeed");

        // Try to set a lower priority (higher nice value)
        let result = process_setpriority(10);
        assert!(result.is_ok(), "Setting lower priority should succeed");

        // Try to set a higher priority (requires privileges)
        let result = process_setpriority(-10);
        if let Err(err) = result {
            // On some systems it might be EPERM (1) or EACCES (13)
            let code = err.raw_os_error().expect("Should have OS error code");
            assert!(
                code == libc::EPERM || code == libc::EACCES,
                "Expected EPERM or EACCES, got error code: {code}"
            );
        }
    }

    #[test]
    fn test_gethostname() {
        let hostname = gethostname().expect("Failed to get hostname");
        assert!(!hostname.is_empty(), "Hostname should not be empty");

        // The hostname should match what we get from UtsName directly
        let uname = UtsName::new().expect("Failed to get system information");
        assert_eq!(hostname, uname.nodename());
    }

    #[test]
    fn test_uptime_sys() {
        assert_ne!(uptime_sys(), Duration::ZERO);
    }

    /// Cross-check `uptime_sys()` against an independent kernel source of
    /// boot time: `/proc/stat`'s `btime` field on Linux and
    /// `sysctl -n kern.boottime` on macOS. Both are epoch-relative seconds,
    /// so `time.time() - boot` matches `uptime_sys()` within tolerance.
    #[test]
    fn test_uptime_sys_matches_boot_time() {
        use std::time::{SystemTime, UNIX_EPOCH};

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock is before the Unix epoch")
            .as_secs_f64();

        let boot_secs: f64 = read_boot_time_secs().expect("could not determine boot time");

        let expected = now - boot_secs;
        let ours = uptime_sys().as_secs_f64();

        // The shell-side sample and the FFI call are not taken at the same
        // instant, and `sysctl kern.boottime` reports whole seconds.
        const TOLERANCE: f64 = 60.0;
        assert!(
            (ours - expected).abs() < TOLERANCE,
            "uptime_sys() = {ours:.3} s diverges from boot-time reference = {expected:.3} s \
             (delta = {:.3} s, tolerance = {TOLERANCE} s)",
            (ours - expected).abs(),
        );
        // Bound: anything beyond a human lifespan indicates a unit mix-up.
        const MAX_PLAUSIBLE: f64 = 100.0 * 365.25 * 24.0 * 3600.0;
        assert!(
            ours < MAX_PLAUSIBLE,
            "uptime_sys() = {ours:.3} s exceeds {MAX_PLAUSIBLE:.0} s",
        );
    }

    #[test]
    fn test_uptime_proc() {
        // Sleep so the test process has measurable uptime. Without this, very fast
        // test runners can spawn the process in the same kernel tick that
        // /proc/uptime is sampled, returning `Duration::ZERO`.
        std::thread::sleep(std::time::Duration::from_millis(10));
        assert_ne!(uptime_proc(std::process::id()), Duration::ZERO);
    }

    /// Cross-check `uptime_proc(self)` against `ps -o etime=`. `ps` reads the
    /// same kernel data (`KERN_PROC_PID` on macOS, `/proc/<pid>/stat` field
    /// 22 on Linux), so the two values match within a second of jitter.
    /// `etime` format is `[[DD-]HH:]MM:SS`.
    #[test]
    fn test_uptime_proc_matches_ps() {
        use std::process::Command;

        // One second of uptime so `etime` is at least `00:01` and integer
        // rounding can't trip the parser.
        std::thread::sleep(std::time::Duration::from_millis(1100));

        let pid = std::process::id();
        let output = Command::new("ps")
            .args(["-o", "etime=", "-p", &pid.to_string()])
            .output()
            .expect("failed to spawn ps");
        let etime = String::from_utf8_lossy(&output.stdout).trim().to_string();
        let ps_secs = match parse_ps_etime(&etime) {
            Some(s) => s,
            None => {
                eprintln!("skipping: could not parse ps etime = {etime:?}");
                return;
            }
        };

        let ours = uptime_proc(pid).as_secs_f64();
        const TOLERANCE: f64 = 2.0;
        assert!(
            (ours - ps_secs).abs() < TOLERANCE,
            "uptime_proc(self) = {ours:.3} s diverges from `ps -o etime=` = {ps_secs:.3} s \
             (delta = {:.3} s, tolerance = {TOLERANCE} s)",
            (ours - ps_secs).abs(),
        );
    }

    /// Cross-check `rss_self()` against `ps -o rss=`. `ps` reports RSS in
    /// KiB on both Linux and macOS; we multiply by 1024 to normalize.
    #[test]
    fn test_rss_self_matches_ps() {
        use std::process::Command;

        let pid = std::process::id();
        let output = Command::new("ps")
            .args(["-o", "rss=", "-p", &pid.to_string()])
            .output()
            .expect("failed to spawn ps");
        let rss_str = String::from_utf8_lossy(&output.stdout).trim().to_string();
        let rss_raw: u64 = match rss_str.parse() {
            Ok(n) => n,
            Err(_) => {
                eprintln!("skipping: could not parse ps rss = {rss_str:?}");
                return;
            }
        };
        let ps_bytes = rss_raw * 1024;
        let ours = rss_self();
        let ps_bytes_usize = usize::try_from(ps_bytes).expect("ps rss exceeds usize");

        // RSS fluctuates by a few pages between the two samples.
        const TOLERANCE_BYTES: usize = 1024 * 1024;
        let diff = ours.abs_diff(ps_bytes_usize);
        assert!(
            diff < TOLERANCE_BYTES,
            "rss_self() = {ours} B diverges from `ps -o rss=` = {ps_bytes} B \
             (delta = {diff} B, tolerance = {TOLERANCE_BYTES} B)",
        );
    }

    /// Cross-check `uptime_proc` against an in-process Rust reimplementation that
    /// reads the same `/proc/<pid>/stat` field 22 and `/proc/uptime` independently.
    /// Tolerates a few ms of jitter between the two samples.
    #[cfg(target_os = "linux")]
    #[test]
    fn test_uptime_proc_matches_proc() {
        use std::fs;

        fn parse_self_uptime_ns() -> Option<u128> {
            let pid = std::process::id();
            let stat = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
            let rparen = stat.rfind(')')?;
            let mut field = 2u32;
            let mut idx = rparen + 1;
            let bytes = stat.as_bytes();
            while field < 22 && idx < bytes.len() {
                if bytes[idx] == b' ' {
                    field += 1;
                    if field == 22 {
                        idx += 1;
                        break;
                    }
                }
                idx += 1;
            }
            if field != 22 {
                return None;
            }
            let rest = stat[idx..].trim_start();
            let end = rest.find(|c: char| c.is_whitespace()).unwrap_or(rest.len());
            let start_ticks: f64 = rest[..end].parse().ok()?;
            let clk_tck = unsafe { libc::sysconf(libc::_SC_CLK_TCK) } as f64;
            let uptime_secs: f64 = fs::read_to_string("/proc/uptime")
                .ok()?
                .split_whitespace()
                .next()?
                .parse()
                .ok()?;
            Some(((uptime_secs - start_ticks / clk_tck) * 1e9) as u128)
        }

        let ours = uptime_proc(std::process::id()).as_nanos();
        let reference = parse_self_uptime_ns().expect("failed to read /proc reference");
        let diff = (ours as i128 - reference as i128).unsigned_abs();
        const TOLERANCE_NS: u128 = 50_000_000; // 50 ms
        assert!(
            diff < TOLERANCE_NS,
            "uptime_proc(self) diverges from /proc reference: ours={ours} ns, reference={reference} ns, diff={diff} ns (tolerance {TOLERANCE_NS} ns)",
        );
    }

    #[test]
    fn test_rand_bytes() {
        // Empty slice is a no-op success.
        let mut empty = [];
        assert!(rand_bytes(&mut empty).is_ok());

        // Sample at several sizes. Each call succeeds, is not all zero, and
        // differs from the previous sample.
        for &size in &[4usize, 32, 4096] {
            let mut prev = vec![0u8; size];
            rand_bytes(&mut prev).expect("rand_bytes should succeed");
            assert!(
                prev.iter().any(|&b| b != 0),
                "rand_bytes({size}) returned all zeros",
            );
            let mut cur = vec![0u8; size];
            rand_bytes(&mut cur).expect("rand_bytes should succeed");
            assert_ne!(
                prev, cur,
                "two consecutive rand_bytes({size}) calls returned identical buffers",
            );
        }
    }

    #[test]
    fn test_getloadavg() {
        let avg = getloadavg().unwrap();
        assert!(avg[0] > 0.0);
        assert!(avg[1] > 0.0);
        assert!(avg[2] > 0.0);
    }

    /// Cross-check `getloadavg()` against `/proc/loadavg` on Linux. The
    /// kernel reports load averages as fixed-point integers scaled by
    /// `1 << SI_LOAD_SHIFT` (16); this test confirms the conversion factor.
    #[cfg(target_os = "linux")]
    #[test]
    fn test_getloadavg_matches_proc_loadavg() {
        use std::fs;

        // `/proc/loadavg` line 1 has the form: "1.00 0.50 0.25 1/123 4567"
        let raw = fs::read_to_string("/proc/loadavg").expect("failed to read /proc/loadavg");
        let mut fields = raw.split_whitespace();
        let proc_one: f64 = fields
            .next()
            .expect("missing 1-minute field")
            .parse()
            .expect("1-minute field is not numeric");
        let proc_five: f64 = fields
            .next()
            .expect("missing 5-minute field")
            .parse()
            .expect("5-minute field is not numeric");
        let proc_fifteen: f64 = fields
            .next()
            .expect("missing 15-minute field")
            .parse()
            .expect("15-minute field is not numeric");
        let proc_avg = [proc_one, proc_five, proc_fifteen];

        let our_avg = getloadavg().expect("getloadavg() failed");

        // The kernel updates both sources periodically, so the two samples
        // may be in slightly different reporting windows.
        const EPSILON: f64 = 0.01;
        for (i, (ours, theirs)) in our_avg.iter().zip(proc_avg.iter()).enumerate() {
            let label = match i {
                0 => "1-minute",
                1 => "5-minute",
                2 => "15-minute",
                _ => unreachable!(),
            };
            assert!(
                (ours - theirs).abs() < EPSILON,
                "{label} loadavg mismatch: ours={ours}, /proc/loadavg={theirs}, \
                 delta={} (tolerance {EPSILON})",
                (ours - theirs).abs(),
            );
        }
    }

    #[test]
    fn test_rss_self() {
        let rss = rss_self();
        assert!(rss > 0, "RSS should be greater than 0");
    }

    /// 1024 distinct samples -- collision probability ~5e-7 in a working RNG.
    #[test]
    fn test_rand_u32_unique_across_many_samples() {
        const N: usize = 1024;
        let mut seen = std::collections::HashSet::with_capacity(N);
        for _ in 0..N {
            let v = rand_u32().expect("rand_u32 should succeed");
            assert!(seen.insert(v), "rand_u32 returned a duplicate value {v}");
        }
        assert_eq!(seen.len(), N);
    }

    #[test]
    fn test_rand_u32() {
        let v1 = rand_u32().unwrap();
        let v2 = rand_u32().unwrap();
        assert_ne!(v1, v2);
    }

    /// 1024 distinct samples.
    #[test]
    fn test_rand_u64_unique_across_many_samples() {
        const N: usize = 1024;
        let mut seen = std::collections::HashSet::with_capacity(N);
        for _ in 0..N {
            let v = rand_u64().expect("rand_u64 should succeed");
            assert!(seen.insert(v), "rand_u64 returned a duplicate value {v}");
        }
        assert_eq!(seen.len(), N);
    }

    #[test]
    fn test_rand_u64() {
        let v1 = rand_u64().unwrap();
        let v2 = rand_u64().unwrap();
        assert_ne!(v1, v2);
    }

    #[test]
    fn test_disk_free() {
        let usage = disk_free("/").expect("failed to get disk usage for /");
        assert!(
            usage.total_bytes() > 0,
            "total bytes should be greater than 0"
        );
        assert!(
            usage.available_bytes() <= usage.free_bytes(),
            "available bytes should be less than or equal to free bytes"
        );
        assert!(
            usage.free_bytes() <= usage.total_bytes(),
            "free bytes should be less than or equal to total bytes"
        );
        #[cfg(not(target_os = "macos"))]
        assert_eq!(usage.used_bytes() + usage.free_bytes(), usage.total_bytes());
        assert!(
            usage.available_inodes() <= usage.free_inodes(),
            "available inodes should be less than or equal to free inodes"
        );
        assert!(
            usage.free_inodes() <= usage.total_inodes(),
            "free inodes should be less than or equal to total inodes"
        );
        assert_eq!(
            usage.used_inodes() + usage.free_inodes(),
            usage.total_inodes()
        );

        // Test with current directory
        let result = disk_free(".");
        assert!(
            result.is_ok(),
            "Failed to get disk usage for current directory"
        );

        // Test with invalid path
        let result = disk_free("/nonexistent/path/that/does/not/exist");
        assert!(result.is_err(), "Should fail for non-existent path");
    }

    /// Cross-check `disk_free` against `df -B1`. Both call `statvfs(3)`,
    /// so values match within a small drift bounded by allocations between
    /// samples. Skipped silently if `df` is unavailable.
    #[cfg(target_os = "linux")]
    #[test]
    fn test_disk_free_matches_df() {
        use std::process::Command;

        // `df -B1` emits: Filesystem 1B-blocks Used Available Use% Mounted
        let df = Command::new("df")
            .args(["-B1", "/"])
            .output()
            .expect("failed to spawn df");
        let stdout = String::from_utf8_lossy(&df.stdout);
        let line = match stdout.lines().nth(1) {
            Some(l) => l,
            None => {
                eprintln!("skipping: df produced no data line");
                return;
            }
        };
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 4 {
            eprintln!("skipping: unexpected df output format: {line:?}");
            return;
        }
        let df_total: u64 = match fields[1].parse() {
            Ok(n) => n,
            Err(_) => {
                eprintln!("skipping: could not parse df total");
                return;
            }
        };
        let df_avail: u64 = match fields[3].parse() {
            Ok(n) => n,
            Err(_) => {
                eprintln!("skipping: could not parse df avail");
                return;
            }
        };

        let usage = disk_free("/").expect("disk_free(/) failed");
        let total = usage.total_bytes();
        let avail = usage.available_bytes();

        // Allow up to 1 MiB of drift to absorb allocations between the two samples.
        // On a quiet test machine the drift is usually a few hundred KiB.
        const TOLERANCE: u64 = 1024 * 1024;
        let total_diff = total.abs_diff(df_total);
        let avail_diff = avail.abs_diff(df_avail);
        assert!(
            total_diff < TOLERANCE && avail_diff < TOLERANCE,
            "disk_free diverges from df -B1:\n  ours total={total} df total={df_total} diff={total_diff}\n  \
             ours avail={avail} df avail={df_avail} diff={avail_diff}\n  \
             (tolerance {TOLERANCE})",
        );
    }

    /// Cross-check all values exposed by `disk_free` against macOS `df -k`.
    /// In particular, the Used column comes from `ATTR_VOL_SPACEUSED` rather
    /// than `f_blocks - f_bfree` on APFS.
    #[cfg(target_os = "macos")]
    #[test]
    fn test_disk_free_matches_df() {
        use std::process::Command;

        // `df -k` emits: Filesystem 1024-blocks Used Available Capacity
        // iused ifree %iused Mounted on
        let output = Command::new("df")
            .args(["-k", "/"])
            .output()
            .expect("failed to spawn df");
        assert!(output.status.success(), "df -k failed");
        let stdout = String::from_utf8_lossy(&output.stdout);
        let fields: Vec<&str> = stdout
            .lines()
            .nth(1)
            .expect("df produced no data line")
            .split_whitespace()
            .collect();
        assert!(fields.len() >= 7, "unexpected df output: {stdout:?}");

        let parse_kib = |field: &str| {
            field
                .parse::<u64>()
                .expect("df block count is not numeric")
                .checked_mul(1024)
                .expect("df byte count exceeds u64")
        };
        let df_total = parse_kib(fields[1]);
        let df_used = parse_kib(fields[2]);
        let df_available = parse_kib(fields[3]);
        let df_used_inodes = fields[5].parse::<u64>().expect("invalid df iused value");
        let df_free_inodes = fields[6].parse::<u64>().expect("invalid df ifree value");

        let usage = disk_free("/").expect("disk_free(/) failed");

        // The samples are taken in separate processes while filesystem usage
        // remains live. Allow modest drift, but not enough for the APFS
        // `total - free` fallback to pass accidentally.
        const BYTE_TOLERANCE: u64 = 16 * 1024 * 1024;
        assert!(usage.total_bytes().abs_diff(df_total) < BYTE_TOLERANCE);
        assert!(usage.used_bytes().abs_diff(df_used) < BYTE_TOLERANCE);
        assert!(usage.available_bytes().abs_diff(df_available) < BYTE_TOLERANCE);
        assert!(usage.used_inodes().abs_diff(df_used_inodes) < 1024);
        assert!(usage.free_inodes().abs_diff(df_free_inodes) < 1024);
    }

    /// Returns the system boot time in seconds since the Unix epoch, or
    /// `None` if it can't be read on this platform.
    fn read_boot_time_secs() -> Option<f64> {
        #[cfg(target_os = "linux")]
        {
            // /proc/stat contains `btime <unix_secs>`.
            let raw = std::fs::read_to_string("/proc/stat").ok()?;
            for line in raw.lines() {
                if let Some(rest) = line.strip_prefix("btime ") {
                    return rest.trim().parse().ok();
                }
            }
            None
        }
        #[cfg(target_os = "macos")]
        {
            // `sysctl -n kern.boottime` prints `{ sec = N, usec = N } ...`.
            let output = std::process::Command::new("sysctl")
                .args(["-n", "kern.boottime"])
                .output()
                .ok()?;
            let stdout = String::from_utf8_lossy(&output.stdout);
            let sec_start = stdout.find("sec = ")? + "sec = ".len();
            let after_sec = &stdout[sec_start..];
            let sec_end = after_sec
                .find(|c: char| !c.is_ascii_digit())
                .unwrap_or(after_sec.len());
            // usec is fractional and contributes at most 1 second; ignore.
            after_sec[..sec_end].parse().ok()
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        {
            None
        }
    }

    /// Parses the `[[DD-]HH:]MM:SS` format produced by `ps -o etime=`.
    fn parse_ps_etime(s: &str) -> Option<f64> {
        let mut parts: Vec<&str> = s.split(':').collect();
        if parts.len() < 2 || parts.len() > 3 {
            return None;
        }
        let seconds: f64 = parts.pop()?.parse().ok()?;
        let minutes: f64 = parts.pop()?.parse().ok()?;
        let (hours, days) = if let Some(rest) = parts.pop() {
            // Could be `HH` or `DD-HH`.
            if let Some((d, h)) = rest.split_once('-') {
                (h.parse().ok()?, d.parse().ok()?)
            } else {
                (rest.parse().ok()?, 0.0)
            }
        } else {
            (0.0, 0.0)
        };
        Some(days * 86400.0 + hours * 3600.0 + minutes * 60.0 + seconds)
    }
}
