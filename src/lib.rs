use std::{ffi::CStr, mem::MaybeUninit, time::Duration};

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
    pub fn uname() -> std::io::Result<Self> {
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
    Ok(UtsName::uname()?.nodename().to_string())
}

#[link(name = "c")]
unsafe extern "C" {
    fn uptime_sys_c() -> u64;
    fn uptime_proc_c(id: i32) -> u64;
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

    const CHARS: [u8; 64] = [
        b'A', b'B', b'C', b'D', b'E', b'F', b'G', b'H', b'I', b'J', b'K', b'L', b'M', b'N', b'O',
        b'P', b'Q', b'R', b'S', b'T', b'U', b'V', b'W', b'X', b'Y', b'Z', b'a', b'b', b'c', b'd',
        b'e', b'f', b'g', b'h', b'i', b'j', b'k', b'l', b'm', b'n', b'o', b'p', b'q', b'r', b's',
        b't', b'u', b'v', b'w', b'x', b'y', b'z', b'0', b'1', b'2', b'3', b'4', b'5', b'6', b'7',
        b'8', b'9', b'-', b'_',
    ];

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

    for b in buf.iter_mut() {
        *b = CHARS[(*b >> 2) as usize];
    }
    // SAFETY: the charset provided is valid UTF-8
    unsafe { String::from_utf8_unchecked(buf) }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_uname_success() {
        let uname = UtsName::uname().expect("Failed to get system information");

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
        let uname = UtsName::uname().expect("Failed to get system information");
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
    fn test_getloadavg() {
        let avg = getloadavg().unwrap();
        assert!(avg[0] > 0.0);
        assert!(avg[1] > 0.0);
        assert!(avg[2] > 0.0);
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
}
