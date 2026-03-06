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
/// ```ignore
/// let info = uname()?;
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

/// Generates a random string of specified length using a secure random number generator.
///
/// The generated string contains characters from the set:
/// `-`, `_`, `0-9`, `A-Z`, and `a-z`.
///
/// This function uses SIMD instructions for performance when available:
/// - SSSE3 on x86_64
/// - NEON on AArch64/ARM64
///
/// The implementation processes data in 16-byte chunks for optimal SIMD performance.
///
/// # Arguments
/// * `len` - The length of the random string to generate
///
/// # Returns
/// A String of the specified length containing random characters.
///
/// # Panics
/// Panics if random byte generation fails.
pub fn rand_string(len: usize) -> String {
    if len == 0 {
        return "".to_string();
    }

    // Use SIMD optimization if available - round up to 16-byte boundary
    #[cfg(target_arch = "x86_64")]
    {
        if is_x86_feature_detected!("ssse3") {
            // Round up to nearest 16-byte boundary for optimal SIMD processing
            let simd_len = (len + 15) & !15;
            let mut buf: Vec<u8> = Vec::with_capacity(simd_len);

            rand_bytes(unsafe {
                // SAFETY: We're transmuting the spare capacity of the vector to a mutable slice of u8.
                // spare_capacity_mut() returns uninitialized space, and we immediately fill it with
                // rand_bytes, which initializes it before we use it.
                std::mem::transmute::<&mut [std::mem::MaybeUninit<u8>], &mut [u8]>(
                    &mut buf.spare_capacity_mut()[..simd_len],
                )
            })
            .unwrap();
            // SAFETY: We just initialized `simd_len` bytes in the buffer via rand_bytes call above.
            unsafe { buf.set_len(simd_len) };

            // Process all bytes with SIMD (no scalar fallback needed)
            unsafe { rand_string_simd_ssse3(&mut buf) };

            // Truncate to requested length
            buf.truncate(len);

            return unsafe { String::from_utf8_unchecked(buf) };
        }
    }

    // Use NEON optimization on ARM if available
    #[cfg(target_arch = "aarch64")]
    {
        if std::arch::is_aarch64_feature_detected!("neon") {
            // Round up to nearest 16-byte boundary for optimal SIMD processing
            let simd_len = (len + 15) & !15;
            let mut buf: Vec<u8> = Vec::with_capacity(simd_len);

            rand_bytes(unsafe {
                // SAFETY: We're transmuting the spare capacity of the vector to a mutable slice of u8.
                // spare_capacity_mut() returns uninitialized space, and we immediately fill it with
                // rand_bytes, which initializes it before we use it.
                std::mem::transmute::<&mut [std::mem::MaybeUninit<u8>], &mut [u8]>(
                    &mut buf.spare_capacity_mut()[..simd_len],
                )
            })
            .unwrap();
            // SAFETY: We just initialized `simd_len` bytes in the buffer via rand_bytes call above.
            unsafe { buf.set_len(simd_len) };

            // Process all bytes with NEON SIMD (no scalar fallback needed)
            unsafe { rand_string_simd_neon(&mut buf) };

            // Truncate to requested length
            buf.truncate(len);

            return unsafe { String::from_utf8_unchecked(buf) };
        }
    }

    // Fallback to scalar implementation for other architectures or when SIMD is unavailable
    let mut buf: Vec<u8> = Vec::with_capacity(len);
    rand_bytes(unsafe {
        // SAFETY: We're transmuting the spare capacity of the vector to a mutable slice of u8.
        // spare_capacity_mut() returns uninitialized space, and we immediately fill it with
        // rand_bytes, which initializes it before we use it.
        std::mem::transmute::<&mut [std::mem::MaybeUninit<u8>], &mut [u8]>(buf.spare_capacity_mut())
    })
    .unwrap();
    // SAFETY: We just initialized `len` bytes in the buffer via rand_bytes call above.
    unsafe { buf.set_len(len) };

    rand_string_scalar(&mut buf);
    // SAFETY: the charset provided is valid UTF-8
    unsafe { String::from_utf8_unchecked(buf) }
}

/// Scalar implementation of charset lookup for random string generation.
#[inline]
fn rand_string_scalar(buf: &mut [u8]) {
    const CHARS: [u8; 64] = [
        b'A', b'B', b'C', b'D', b'E', b'F', b'G', b'H', b'I', b'J', b'K', b'L', b'M', b'N', b'O',
        b'P', b'Q', b'R', b'S', b'T', b'U', b'V', b'W', b'X', b'Y', b'Z', b'a', b'b', b'c', b'd',
        b'e', b'f', b'g', b'h', b'i', b'j', b'k', b'l', b'm', b'n', b'o', b'p', b'q', b'r', b's',
        b't', b'u', b'v', b'w', b'x', b'y', b'z', b'0', b'1', b'2', b'3', b'4', b'5', b'6', b'7',
        b'8', b'9', b'-', b'_',
    ];

    for b in buf.iter_mut() {
        *b = CHARS[(*b >> 2) as usize];
    }
}

/// SIMD implementation using SSSE3 instructions for charset lookup.
/// Processes 16 bytes at a time using shuffle instructions.
///
/// # Safety
/// The buffer length must be a multiple of 16 bytes.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "ssse3")]
#[inline]
unsafe fn rand_string_simd_ssse3(buf: &mut [u8]) {
    // SAFETY: This entire function is marked unsafe and requires SSSE3.
    // All SIMD operations are safe when the target feature is enabled.
    unsafe {
        #[cfg(target_arch = "x86_64")]
        use std::arch::x86_64::*;

        // Our charset: A-Z (indices 0-25), a-z (26-51), 0-9 (52-61), - (62), _ (63)
        // We need to map 6-bit values (0-63) to these characters

        // Split the 64-character table into 4 lookup tables of 16 characters each
        // LUT 0: indices 0-15 => A-P
        let lut0 = _mm_setr_epi8(
            b'A' as i8, b'B' as i8, b'C' as i8, b'D' as i8, b'E' as i8, b'F' as i8, b'G' as i8,
            b'H' as i8, b'I' as i8, b'J' as i8, b'K' as i8, b'L' as i8, b'M' as i8, b'N' as i8,
            b'O' as i8, b'P' as i8,
        );

        // LUT 1: indices 16-31 => Q-Z, a-e
        let lut1 = _mm_setr_epi8(
            b'Q' as i8, b'R' as i8, b'S' as i8, b'T' as i8, b'U' as i8, b'V' as i8, b'W' as i8,
            b'X' as i8, b'Y' as i8, b'Z' as i8, b'a' as i8, b'b' as i8, b'c' as i8, b'd' as i8,
            b'e' as i8, b'f' as i8,
        );

        // LUT 2: indices 32-47 => g-v
        let lut2 = _mm_setr_epi8(
            b'g' as i8, b'h' as i8, b'i' as i8, b'j' as i8, b'k' as i8, b'l' as i8, b'm' as i8,
            b'n' as i8, b'o' as i8, b'p' as i8, b'q' as i8, b'r' as i8, b's' as i8, b't' as i8,
            b'u' as i8, b'v' as i8,
        );

        // LUT 3: indices 48-63 => w-z, 0-9, -, _
        let lut3 = _mm_setr_epi8(
            b'w' as i8, b'x' as i8, b'y' as i8, b'z' as i8, b'0' as i8, b'1' as i8, b'2' as i8,
            b'3' as i8, b'4' as i8, b'5' as i8, b'6' as i8, b'7' as i8, b'8' as i8, b'9' as i8,
            b'-' as i8, b'_' as i8,
        );

        let len = buf.len();
        let mut i = 0;

        debug_assert!(
            buf.as_ptr().addr() & 15 == 0,
            "pointer must be 16 byte aligned"
        );

        // Process all bytes in 16-byte chunks (buffer length is guaranteed to be a multiple of 16)
        while i < len {
            // Load 16 random bytes
            let input = _mm_load_si128(buf.as_ptr().add(i) as *const __m128i);

            // Extract 6 bits per byte (shift right by 2), giving us values 0-63
            let indices = _mm_srli_epi16(input, 2);
            let indices = _mm_and_si128(indices, _mm_set1_epi8(0x3f));

            // Extract the high 2 bits (bits 4-5) to determine which LUT to use
            // and the low 4 bits (bits 0-3) to index within the LUT
            let hi_bits = _mm_srli_epi16(indices, 4);
            let hi_bits = _mm_and_si128(hi_bits, _mm_set1_epi8(0x03));
            let lo_bits = _mm_and_si128(indices, _mm_set1_epi8(0x0f));

            // Perform lookups in all 4 tables
            let result0 = _mm_shuffle_epi8(lut0, lo_bits);
            let result1 = _mm_shuffle_epi8(lut1, lo_bits);
            let result2 = _mm_shuffle_epi8(lut2, lo_bits);
            let result3 = _mm_shuffle_epi8(lut3, lo_bits);

            // Create masks for each LUT based on hi_bits value
            let mask0 = _mm_cmpeq_epi8(hi_bits, _mm_setzero_si128());
            let mask1 = _mm_cmpeq_epi8(hi_bits, _mm_set1_epi8(1));
            let mask2 = _mm_cmpeq_epi8(hi_bits, _mm_set1_epi8(2));
            let mask3 = _mm_cmpeq_epi8(hi_bits, _mm_set1_epi8(3));

            // Blend results based on masks
            let mut result = _mm_and_si128(mask0, result0);
            result = _mm_or_si128(result, _mm_and_si128(mask1, result1));
            result = _mm_or_si128(result, _mm_and_si128(mask2, result2));
            result = _mm_or_si128(result, _mm_and_si128(mask3, result3));

            // Store result
            _mm_storeu_si128(buf.as_mut_ptr().add(i) as *mut __m128i, result);

            i += 16;
        }
    }
}

/// SIMD implementation using ARM NEON instructions for charset lookup.
/// Processes 16 bytes at a time using table lookup instructions.
///
/// # Safety
/// The buffer length must be a multiple of 16 bytes.
#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "neon")]
#[inline]
unsafe fn rand_string_simd_neon(buf: &mut [u8]) {
    // SAFETY: This entire function is marked unsafe and requires NEON.
    // All SIMD operations are safe when the target feature is enabled.
    unsafe {
        #[cfg(target_arch = "aarch64")]
        use std::arch::aarch64::*;

        // Our charset: A-Z (indices 0-25), a-z (26-51), 0-9 (52-61), - (62), _ (63)
        // We need to map 6-bit values (0-63) to these characters

        // Split the 64-character table into 4 lookup tables of 16 characters each
        // LUT 0: indices 0-15 => A-P
        let lut0 = [
            b'A', b'B', b'C', b'D', b'E', b'F', b'G', b'H', b'I', b'J', b'K', b'L', b'M', b'N',
            b'O', b'P',
        ];

        // LUT 1: indices 16-31 => Q-Z, a-e
        let lut1 = [
            b'Q', b'R', b'S', b'T', b'U', b'V', b'W', b'X', b'Y', b'Z', b'a', b'b', b'c', b'd',
            b'e', b'f',
        ];

        // LUT 2: indices 32-47 => g-v
        let lut2 = [
            b'g', b'h', b'i', b'j', b'k', b'l', b'm', b'n', b'o', b'p', b'q', b'r', b's', b't',
            b'u', b'v',
        ];

        // LUT 3: indices 48-63 => w-z, 0-9, -, _
        let lut3 = [
            b'w', b'x', b'y', b'z', b'0', b'1', b'2', b'3', b'4', b'5', b'6', b'7', b'8', b'9',
            b'-', b'_',
        ];

        let lut0_vec = vld1q_u8(lut0.as_ptr());
        let lut1_vec = vld1q_u8(lut1.as_ptr());
        let lut2_vec = vld1q_u8(lut2.as_ptr());
        let lut3_vec = vld1q_u8(lut3.as_ptr());

        let len = buf.len();
        let mut i = 0;

        // Process all bytes in 16-byte chunks (buffer length is guaranteed to be a multiple of 16)
        while i < len {
            // Load 16 random bytes
            let input = vld1q_u8(buf.as_ptr().add(i));

            // Extract 6 bits per byte (shift right by 2), giving us values 0-63
            let indices = vshrq_n_u8(input, 2);
            let indices = vandq_u8(indices, vdupq_n_u8(0x3f));

            // Extract the high 2 bits (bits 4-5) to determine which LUT to use
            // and the low 4 bits (bits 0-3) to index within the LUT
            let hi_bits = vshrq_n_u8(indices, 4);
            let hi_bits = vandq_u8(hi_bits, vdupq_n_u8(0x03));
            let lo_bits = vandq_u8(indices, vdupq_n_u8(0x0f));

            // Perform lookups in all 4 tables using NEON table lookup
            let result0 = vqtbl1q_u8(lut0_vec, lo_bits);
            let result1 = vqtbl1q_u8(lut1_vec, lo_bits);
            let result2 = vqtbl1q_u8(lut2_vec, lo_bits);
            let result3 = vqtbl1q_u8(lut3_vec, lo_bits);

            // Create masks for each LUT based on hi_bits value
            let zero_vec = vdupq_n_u8(0);
            let mask0 = vceqq_u8(hi_bits, zero_vec);
            let mask1 = vceqq_u8(hi_bits, vdupq_n_u8(1));
            let mask2 = vceqq_u8(hi_bits, vdupq_n_u8(2));
            let mask3 = vceqq_u8(hi_bits, vdupq_n_u8(3));

            // Blend results based on masks using bitwise select
            // vbslq_u8(mask, a, b) returns: (mask & a) | (!mask & b)
            let mut result = vbslq_u8(mask0, result0, zero_vec);
            result = vorrq_u8(result, vandq_u8(mask1, result1));
            result = vorrq_u8(result, vandq_u8(mask2, result2));
            result = vorrq_u8(result, vandq_u8(mask3, result3));

            // Store result
            vst1q_u8(buf.as_mut_ptr().add(i), result);

            i += 16;
        }
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
/// ```ignore
/// let random_num = rand_u32();
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
/// ```ignore
/// let random_num = rand_u64();
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
/// ```ignore
/// let (total, free) = disk_free("/").unwrap();
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
    fn test_rand_string() {
        // Test empty string
        assert_eq!(rand_string(0).len(), 0);

        // Test string of specific length
        let s = rand_string(16);
        assert_eq!(s.len(), 16);

        // Test that two strings are different
        let s1 = rand_string(32);
        let s2 = rand_string(32);
        assert_ne!(s1, s2);

        // Test string contents are from valid charset
        const VALID_CHARS: &[u8] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        for c in s1.bytes() {
            assert!(VALID_CHARS.contains(&c));
        }
    }

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn test_rand_string_simd_consistency() {
        // Test that SIMD and scalar implementations produce the same output
        // for the same input random bytes

        const TEST_SIZES: &[usize] = &[16, 32, 48, 64, 80, 128, 256];

        for &size in TEST_SIZES {
            // Generate random bytes (size is always a multiple of 16)
            let mut random_bytes = vec![0u8; size];
            rand_bytes(&mut random_bytes).unwrap();

            // Process with scalar
            let mut scalar_result = random_bytes.clone();
            rand_string_scalar(&mut scalar_result);

            // Process with SIMD (if available)
            let mut simd_result = random_bytes.clone();
            if is_x86_feature_detected!("ssse3") {
                unsafe { rand_string_simd_ssse3(&mut simd_result) };
            }

            // Compare results
            if is_x86_feature_detected!("ssse3") {
                assert_eq!(
                    scalar_result, simd_result,
                    "SIMD and scalar results differ for size {size}"
                );
            }

            // Verify all bytes are valid charset characters
            const VALID_CHARS: &[u8] =
                b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
            for &byte in &scalar_result {
                assert!(
                    VALID_CHARS.contains(&byte),
                    "Invalid character: {}",
                    byte as char
                );
            }
        }
    }

    #[test]
    #[cfg(target_arch = "aarch64")]
    fn test_rand_string_simd_neon_consistency() {
        // Test that SIMD and scalar implementations produce the same output
        // for the same input random bytes

        const TEST_SIZES: &[usize] = &[16, 32, 48, 64, 80, 128, 256];

        for &size in TEST_SIZES {
            // Generate random bytes (size is always a multiple of 16)
            let mut random_bytes = vec![0u8; size];
            rand_bytes(&mut random_bytes).unwrap();

            // Process with scalar
            let mut scalar_result = random_bytes.clone();
            rand_string_scalar(&mut scalar_result);

            // Process with SIMD (if available)
            let mut simd_result = random_bytes.clone();
            if std::arch::is_aarch64_feature_detected!("neon") {
                unsafe { rand_string_simd_neon(&mut simd_result) };
            }

            // Compare results
            if std::arch::is_aarch64_feature_detected!("neon") {
                assert_eq!(
                    scalar_result, simd_result,
                    "SIMD and scalar results differ for size {}",
                    size
                );
            }

            // Verify all bytes are valid charset characters
            const VALID_CHARS: &[u8] =
                b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
            for &byte in &scalar_result {
                assert!(
                    VALID_CHARS.contains(&byte),
                    "Invalid character: {}",
                    byte as char
                );
            }
        }
    }

    #[test]
    fn test_rand_string_lengths() {
        // Test that rand_string works correctly for various lengths including
        // those that aren't multiples of 16
        const TEST_LENGTHS: &[usize] =
            &[1, 7, 15, 16, 17, 31, 32, 33, 63, 64, 65, 100, 127, 128, 250];

        for &len in TEST_LENGTHS {
            let s = rand_string(len);
            assert_eq!(s.len(), len, "String length should match requested length");

            // Verify all characters are from valid charset
            const VALID_CHARS: &[u8] =
                b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
            for c in s.bytes() {
                assert!(VALID_CHARS.contains(&c), "Invalid character: {}", c as char);
            }
        }
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
