use std::{
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
    /// # Panics
    /// Panics if the system name contains invalid UTF-8 characters.
    pub fn sysname(&self) -> &str {
        unsafe {
            // SAFETY: The sysname field in libc::utsname is guaranteed to contain a valid
            // null-terminated C string that was initialized by the uname system call.
            CStr::from_ptr(self.inner.sysname.as_ptr())
                .to_str()
                .unwrap()
        }
    }

    /// Returns the network node hostname.
    ///
    /// # Panics
    /// Panics if the hostname contains invalid UTF-8 characters.
    pub fn nodename(&self) -> &str {
        unsafe {
            // SAFETY: The nodename field in libc::utsname is guaranteed to contain a valid
            // null-terminated C string that was initialized by the uname system call.
            CStr::from_ptr(self.inner.nodename.as_ptr())
                .to_str()
                .unwrap()
        }
    }

    /// Returns the operating system release level.
    ///
    /// # Panics
    /// Panics if the release string contains invalid UTF-8 characters.
    pub fn release(&self) -> &str {
        unsafe {
            // SAFETY: The release field in libc::utsname is guaranteed to contain a valid
            // null-terminated C string that was initialized by the uname system call.
            CStr::from_ptr(self.inner.release.as_ptr())
                .to_str()
                .unwrap()
        }
    }

    /// Returns the operating system version.
    ///
    /// # Panics
    /// Panics if the version string contains invalid UTF-8 characters.
    pub fn version(&self) -> &str {
        unsafe {
            // SAFETY: The version field in libc::utsname is guaranteed to contain a valid
            // null-terminated C string that was initialized by the uname system call.
            CStr::from_ptr(self.inner.version.as_ptr())
                .to_str()
                .unwrap()
        }
    }

    /// Returns the machine hardware name.
    ///
    /// # Panics
    /// Panics if the machine name contains invalid UTF-8 characters.
    pub fn machine(&self) -> &str {
        unsafe {
            // SAFETY: The machine field in libc::utsname is guaranteed to contain a valid
            // null-terminated C string that was initialized by the uname system call.
            CStr::from_ptr(self.inner.machine.as_ptr())
                .to_str()
                .unwrap()
        }
    }

    /// Returns the Network Information System (NIS) domain name.
    ///
    /// This method is only available on Linux systems.
    ///
    /// # Panics
    /// Panics if the domain name contains invalid UTF-8 characters.
    #[cfg(target_os = "linux")]
    pub fn domainname(&self) -> &str {
        unsafe {
            // SAFETY: The domainname field in libc::utsname is guaranteed to contain a valid
            // null-terminated C string that was initialized by the uname system call.
            CStr::from_ptr(self.inner.domainname.as_ptr())
                .to_str()
                .unwrap()
        }
    }
}

/// Returns system information in the same format as the `uname -a` command.
///
/// The format matches platform-specific output:
/// - **macOS**: `sysname nodename release version machine`
/// - **Linux**: `sysname nodename release version machine processor platform os`
///
/// # Returns
/// * `Ok(String)` containing the formatted system information
/// * `Err(std::io::Error)` if retrieving system information failed
///
/// # Example
/// ```
/// let info = os_utils::uname().unwrap();
/// println!("{}", info);
/// // macOS: "Darwin hostname 23.6.0 Darwin Kernel Version 23.6.0:... x86_64"
/// // Linux: "Linux hostname 5.15.0-1 #1 SMP ... x86_64 x86_64 x86_64 GNU/Linux"
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
/// This is a convenience wrapper around `UtsName::uname()?.nodename()`.
///
/// # Returns
/// * `Ok(String)` containing the hostname if successful
/// * `Err(std::io::Error)` if retrieving the hostname failed
pub fn gethostname() -> std::io::Result<String> {
    Ok(UtsName::new()?.nodename().to_string())
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
pub fn uptime_sys() -> Duration {
    unsafe { Duration::from_nanos(uptime_sys_c()) }
}

/// Returns the uptime of a specific process.
///
/// # Arguments
/// * `id` - Process ID to get the uptime for
///
/// # Returns
/// A `Duration` representing how long the process has been running.
pub fn uptime_proc(id: u32) -> Duration {
    unsafe { Duration::from_nanos(uptime_proc_c(id as i32)) }
}

/// Returns the uptime of the container (for containerized environments).
///
/// This is equivalent to getting the uptime of process ID 1 (init process).
///
/// # Returns
/// A `Duration` representing how long the container has been running.
pub fn uptime_container() -> Duration {
    uptime_proc(1)
}

/// Returns the resident set size (RSS) of the current process.
///
/// The resident set size is the portion of a process's memory that is held in main memory (RAM).
/// This is useful for monitoring memory usage of the running process.
///
/// # Returns
/// The resident set size in bytes.
///
/// # Platform-specific
/// - **macOS/Darwin**: Uses `task_info` with `TASK_BASIC_INFO` to get memory information.
/// - **Linux**: Reads from `/proc/self/statm` and converts pages to bytes.
pub fn rss_self() -> usize {
    unsafe { rss_self_c() }
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
#[cfg(target_os = "linux")]
pub fn rand_bytes(dst: &mut [u8]) -> std::io::Result<()> {
    let need = dst.len();
    if need == 0 {
        return Ok(());
    }

    unsafe {
        // SAFETY: getrandom is a valid system call. The buffer pointer is valid and properly aligned,
        // the length matches the slice size, and we check the return value to ensure safe usage.
        let res = libc::getrandom(dst.as_mut_ptr() as *mut libc::c_void, need, 0);
        if res < 0 {
            return Err(std::io::Error::last_os_error());
        } else if res != need as isize {
            return Err(std::io::Error::other(format!(
                "Unable to generate {need} random bytes"
            )));
        }
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
/// A `u32` containing 4 random bytes from the system's secure random number generator.
///
/// # Panics
/// Panics if random byte generation fails.
///
/// # Example
/// ```
/// let random_num = os_utils::rand_u32();
/// println!("Random u32: {}", random_num);
/// ```
pub fn rand_u32() -> u32 {
    let mut buf: [MaybeUninit<u8>; 4] = [MaybeUninit::uninit(); 4];
    rand_bytes(unsafe {
        // SAFETY: We're transmuting the uninitialized buffer to a mutable slice of u8.
        // Since rand_bytes will immediately initialize it, this is safe.
        std::mem::transmute::<&mut [std::mem::MaybeUninit<u8>], &mut [u8]>(&mut buf[..])
    })
    .unwrap();
    // SAFETY: The buffer has been fully initialized by rand_bytes above, so transmuting
    // the 4 initialized bytes to u32 is safe.
    unsafe { std::mem::transmute(buf) }
}

/// Generates a cryptographically secure random 64-bit unsigned integer.
///
/// # Returns
/// A `u64` containing 8 random bytes from the system's secure random number generator.
///
/// # Panics
/// Panics if random byte generation fails.
///
/// # Example
/// ```
/// let random_num = os_utils::rand_u64();
/// println!("Random u64: {}", random_num);
/// ```
pub fn rand_u64() -> u64 {
    let mut buf: [MaybeUninit<u8>; 8] = [MaybeUninit::uninit(); 8];
    rand_bytes(unsafe {
        // SAFETY: We're transmuting the uninitialized buffer to a mutable slice of u8.
        // Since rand_bytes will immediately initialize it, this is safe.
        std::mem::transmute::<&mut [std::mem::MaybeUninit<u8>], &mut [u8]>(&mut buf[..])
    })
    .unwrap();
    // SAFETY: The buffer has been fully initialized by rand_bytes above, so transmuting
    // the 8 initialized bytes to u64 is safe.
    unsafe { std::mem::transmute(buf) }
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

    #[allow(clippy::needless_range_loop)]
    for i in 0..3 {
        loadavg[i] = 1.0 / ((1 << libc::SI_LOAD_SHIFT) * si.loads[i]) as f64;
    }

    Ok(loadavg)
}

/// Returns disk free information for a given path.
///
/// # Arguments
/// * `path` - The filesystem path to query
///
/// # Returns
/// * `Ok((capacity_bytes, free_bytes))` - A tuple containing the total capacity and remaining space
/// * `Err(std::io::Error)` if the system call fails or path is invalid
///
/// # Example
/// ```
/// let (total, free) = os_utils::disk_free("/").unwrap();
/// println!("Disk free: {} / {} bytes ({:.1}% capacity)",
///          free, total, ((total - free) as f64 / total as f64) * 100.0);
/// ```
pub fn disk_free<P: AsRef<Path>>(path: P) -> std::io::Result<(u64, u64)> {
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
    let available_blocks = stat.f_bavail as u64;
    let block_size = stat.f_frsize as u64;

    Ok((total_blocks * block_size, available_blocks * block_size))
}

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
        const TTY_NAME_MAX: usize = 128;
        let mut buf = [0u8; TTY_NAME_MAX];
        let result = unsafe {
            // SAFETY: We're calling ttyname_r with a valid file descriptor (0)
            // and a properly allocated buffer with correct size.
            libc::ttyname_r(
                self.as_raw_fd(),
                buf.as_mut_ptr() as *mut libc::c_char,
                buf.len(),
            )
        };

        if result != 0 {
            return Err(std::io::Error::from_raw_os_error(result));
        }

        let name = unsafe {
            // SAFETY: ttyname_r guarantees a null-terminated string on success.
            CStr::from_ptr(buf.as_ptr() as *const libc::c_char)
        }
        .to_bytes();

        Ok(PathBuf::from(OsStr::from_bytes(name)))
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
        let result = unsafe {
            // SAFETY: We're calling libc::read with a valid file descriptor (0 for stdin)
            // and a properly allocated buffer with correct length.
            libc::read(
                libc::STDIN_FILENO,
                buf.as_mut_ptr() as *mut libc::c_void,
                buf.len(),
            )
        };

        if result < 0 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(result as usize)
        }
    }

    fn read_vectored(&mut self, bufs: &mut [IoSliceMut<'_>]) -> std::io::Result<usize> {
        let result = unsafe {
            libc::readv(
                libc::STDIN_FILENO,
                bufs.as_mut_ptr() as *mut libc::iovec as *const libc::iovec,
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
        let result = unsafe {
            // SAFETY: We're calling libc::write with a valid file descriptor (1 for stdout)
            // and a properly allocated buffer with correct length.
            libc::write(
                libc::STDOUT_FILENO,
                buf.as_ptr() as *const libc::c_void,
                buf.len(),
            )
        };

        if result < 0 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(result as usize)
        }
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
        // File descriptors don't buffer in the same way as stdio,
        // but we can ensure data is written to the OS.
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
        let result = unsafe {
            // SAFETY: We're calling libc::write with a valid file descriptor (2 for stderr)
            // and a properly allocated buffer with correct length.
            libc::write(
                libc::STDERR_FILENO,
                buf.as_ptr() as *const libc::c_void,
                buf.len(),
            )
        };

        if result < 0 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(result as usize)
        }
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
        // File descriptors don't buffer in the same way as stdio,
        // but we can ensure data is written to the OS.
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
/// The `TryRng` trait methods return `Result<T, Infallible>`, meaning they never fail.
/// Any underlying OS errors are handled by panicking in the [`rand_bytes`] function.
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
    type Error = core::convert::Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        Ok(rand_u32())
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        Ok(rand_u64())
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        rand_bytes(dst).expect("failed to generate random bytes");
        Ok(())
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

    #[test]
    fn test_uptime_proc() {
        assert_ne!(uptime_proc(std::process::id()), Duration::ZERO);
    }

    #[test]
    fn test_rand_bytes() {
        let mut buf1 = vec![0u8; 32];
        let mut buf2 = vec![0u8; 32];

        // Test successful generation
        assert!(rand_bytes(&mut buf1).is_ok());
        assert!(rand_bytes(&mut buf2).is_ok());

        // Test that two consecutive calls produce different bytes
        assert_ne!(buf1, buf2);
    }

    #[test]
    fn test_getloadavg() {
        let avg = getloadavg().unwrap();
        assert!(avg[0] > 0.0);
        assert!(avg[1] > 0.0);
        assert!(avg[2] > 0.0);
    }

    #[test]
    fn test_rss_self() {
        let rss = rss_self();
        assert!(rss > 0, "RSS should be greater than 0");
    }

    #[test]
    fn test_rand_u32() {
        // Test that two consecutive u32 values are different
        let v1 = rand_u32();
        let v2 = rand_u32();
        assert_ne!(v1, v2);
    }

    #[test]
    fn test_rand_u64() {
        // Test that two consecutive u64 values are different
        let v1 = rand_u64();
        let v2 = rand_u64();
        assert_ne!(v1, v2);
    }

    #[test]
    fn test_disk_free() {
        let result = disk_free("/");
        assert!(result.is_ok(), "Failed to get disk usage for /");

        let (total, free) = result.unwrap();
        assert!(free > 0, "Total bytes should be greater than 0");
        assert!(total > 0, "Used bytes should be greater than 0");
        assert!(
            free <= total,
            "Used bytes should be less than or equal to total bytes"
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
}
