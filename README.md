# os-utils

A Rust library providing safe wrappers around common operating system utilities and system calls. This library offers cross-platform support for system information retrieval, process management, random number generation, and system statistics.

## Features

- System information retrieval (uname, hostname)
- Process and thread scheduling management
- System and process uptime queries
- Secure random number generation
- System load average monitoring
- Cross-platform support for Linux and macOS

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
os-utils = "0.1.0"
```

## Examples

### Getting System Information

```rust
use os_utils::UtsName;

fn main() -> std::io::Result<()> {
    let info = UtsName::uname()?;
    
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

### Thread Scheduling

```rust
use os_utils::{SchedPolicy, thread_setscheduler};

fn main() -> std::io::Result<()> {
    // Set thread to use round-robin scheduling with priority 1
    thread_setscheduler(SchedPolicy::RoundRobin, 1)?;
    
    // Or use standard scheduling
    thread_setscheduler(SchedPolicy::Other, 0)?;
    
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
use os_utils::{rand_bytes, rand_string};

fn main() -> std::io::Result<()> {
    // Generate random bytes
    let mut buffer = vec![0u8; 32];
    rand_bytes(&mut buffer)?;
    
    // Generate random string
    let random_string = rand_string(16);
    println!("Random string: {}", random_string);
    
    Ok(())
}
```

### System Uptime

```rust
use os_utils::{uptime_sys, uptime_proc};
use std::time::Duration;

fn main() {
    let system_uptime: Duration = uptime_sys();
    println!("System uptime: {:?}", system_uptime);
    
    let current_process_uptime = uptime_proc(std::process::id());
    println!("Process uptime: {:?}", current_process_uptime);
}
```

## Platform Support

This library currently supports:
- Linux
- macOS

Some features are platform-specific:
- `domainname()` is only available on Linux
- Random number generation uses different system calls on each platform
  - Linux: `getrandom`
  - macOS: Common Crypto framework

### SIMD Optimizations

The `rand_string` function includes SIMD optimizations for improved performance:
- **x86_64**: Uses SSSE3 instructions (`_mm_shuffle_epi8`) when available
- **AArch64/ARM64**: Uses NEON instructions (`vqtbl1q_u8`) when available
- **Other platforms**: Falls back to scalar implementation

The SIMD implementation provides 2-3x speedup for charset lookups on strings ≥32 bytes. See [SIMD_OPTIMIZATION.md](SIMD_OPTIMIZATION.md) for detailed performance analysis.

## Safety

This library provides safe wrappers around unsafe system calls. However, some operations might require elevated privileges:
- Setting real-time scheduling policies (FIFO, RoundRobin) typically requires root privileges
- Setting negative nice values (higher priorities) requires root privileges

## License

This project is licensed under a BSD-2 Clause License.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.