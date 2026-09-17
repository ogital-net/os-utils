# os-utils

A Rust library providing safe wrappers around common operating system utilities and system calls. This library offers cross-platform support for system information retrieval, process management, random number generation, and system statistics.

## Features

- System information retrieval (`uname`, `gethostname`)
- Process and thread scheduling management
- System, process, and container uptime queries
- Disk free space queries
- Resident set size (RSS) monitoring
- Secure random number generation
- System load average monitoring
- Low-level `Stdin`, `Stdout`, `Stderr` wrappers with TTY support
- Cross-platform support for Linux and macOS

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
os-utils = "0.1.0"
```

To enable the `rand_core` integration, enable the `rand` feature:

```toml
[dependencies]
os-utils = { version = "0.1.0", features = ["rand"] }
```

## Examples

### Getting System Information

```rust
use os_utils::UtsName;

fn main() -> std::io::Result<()> {
    let info = UtsName::new()?;

    println!("System: {}", info.sysname());
    println!("Node: {}", info.nodename());
    println!("Release: {}", info.release());
    println!("Version: {}", info.version());
    println!("Machine: {}", info.machine());

    // Linux-specific
    #[cfg(target_os = "linux")]
    println!("Domain: {}", info.domainname());

    Ok(())
}
```

### Get uname -a Output

```rust
use os_utils::uname;

fn main() -> std::io::Result<()> {
    let info = uname()?;
    println!("{}", info);
    // macOS: "Darwin hostname 23.6.0 Darwin Kernel Version... x86_64"
    // Linux: "Linux hostname 5.15.0-1 #1 SMP... x86_64 x86_64 x86_64 GNU/Linux"
    Ok(())
}
```

### Hostname

```rust
use os_utils::gethostname;

fn main() -> std::io::Result<()> {
    println!("Hostname: {}", gethostname()?);
    Ok(())
}
```

### Thread and Process Scheduling

```rust,no_run
use os_utils::{SchedPolicy, thread_setscheduler, process_setpriority};

fn main() -> std::io::Result<()> {
    // Set thread to use round-robin scheduling with priority 1
    thread_setscheduler(SchedPolicy::RoundRobin, 1)?;

    // Or use standard scheduling
    thread_setscheduler(SchedPolicy::Other, 0)?;

    // Lower the current process's priority (nice value)
    process_setpriority(10)?;

    Ok(())
}
```

### System Load Average

```rust
use os_utils::getloadavg;

fn main() -> std::io::Result<()> {
    let [one, five, fifteen] = getloadavg()?;
    println!("Load averages: {:.2} {:.2} {:.2}", one, five, fifteen);
    Ok(())
}
```

### Generate Random Data

```rust
use os_utils::{rand_bytes, rand_u32, rand_u64};

fn main() -> std::io::Result<()> {
    // Generate random bytes
    let mut buffer = vec![0u8; 32];
    rand_bytes(&mut buffer)?;

    // Generate random integers
    println!("Random u32: {}", rand_u32()?);
    println!("Random u64: {}", rand_u64()?);

    Ok(())
}
```

### System and Process Uptime

```rust
use os_utils::{uptime_sys, uptime_proc, uptime_container};

fn main() {
    println!("System uptime: {:?}", uptime_sys());
    println!("Process uptime: {:?}", uptime_proc(std::process::id()));
    println!("Container uptime: {:?}", uptime_container());
}
```

### Disk Free Space

```rust
use os_utils::disk_free;

fn main() -> std::io::Result<()> {
    let usage = disk_free("/")?;
    println!("Disk free: {} / {} bytes ({:.1}% used)",
             usage.available_bytes(),
             usage.total_bytes(),
             (usage.used_bytes() as f64
                 / (usage.used_bytes() as f64 + usage.available_bytes() as f64)) * 100.0);
    println!("Inodes available: {} / {}",
             usage.available_inodes(), usage.total_inodes());
    Ok(())
}
```

`free_bytes()` includes space reserved for privileged users, while
`available_bytes()` reports the space an unprivileged user can allocate.
On macOS, `used_bytes()` uses `ATTR_VOL_SPACEUSED` so APFS usage matches `df`;
other platforms derive it from total and free space.

### Resident Set Size

```rust
use os_utils::rss_self;

fn main() {
    println!("RSS: {} bytes", rss_self());
}
```

### TTY Detection

```rust
use os_utils::{Stdin, TtyInfo};

fn main() -> std::io::Result<()> {
    let stdin = Stdin::new();
    if stdin.isatty() {
        println!("Running in terminal: {}", stdin.ttyname()?.display());
    } else {
        println!("stdin is not a TTY");
    }
    Ok(())
}
```

### Low-level stdio

`Stdin`, `Stdout`, and `Stderr` implement `std::io::Read`/`Write` and `TtyInfo` directly via libc syscalls.

```rust
use std::io::Write;
use os_utils::Stdout;

fn main() -> std::io::Result<()> {
    let mut out = Stdout::new();
    out.write_all(b"hello from libc write\n")?;
    Ok(())
}
```

### OsRng (rand feature)

`OsRng` implements `rand_core::TryRng` and `rand_core::TryCryptoRng`, bridging OS random generation to the `rand_core` ecosystem.

```rust,ignore
use rand_core::TryRng;

let mut rng = OsRng;
let random_u32 = rng.try_next_u32().unwrap();
let random_u64 = rng.try_next_u64().unwrap();

let mut buffer = [0u8; 32];
rng.try_fill_bytes(&mut buffer).unwrap();
```

## Platform Support

This library currently supports:
- Linux
- macOS

Some features are platform-specific:
- `domainname()` is only available on Linux
- Random number generation uses different system calls on each platform
  - Linux: `getrandom`
  - macOS: Common Crypto (`CCRandomGenerateBytes`)

## Safety

This library provides safe wrappers around unsafe system calls. However, some operations might require elevated privileges:
- Setting real-time scheduling policies (`FIFO`, `RoundRobin`) typically requires root privileges
- Setting negative nice values (higher priorities) via `process_setpriority` requires root privileges

## License

This project is licensed under a BSD-2 Clause License.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.