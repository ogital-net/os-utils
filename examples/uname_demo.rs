use os_utils::{UtsName, uname};

fn main() -> std::io::Result<()> {
    println!("=== System Information Demo ===\n");

    // Get formatted uname -a style output
    println!("uname -a format:");
    let uname_output = uname()?;
    println!("{}\n", uname_output);

    // Get individual fields
    println!("Individual fields:");
    let info = UtsName::uname()?;
    println!("  System name: {}", info.sysname());
    println!("  Node name:   {}", info.nodename());
    println!("  Release:     {}", info.release());
    println!("  Version:     {}", info.version());
    println!("  Machine:     {}", info.machine());

    #[cfg(target_os = "linux")]
    println!("  Domain:      {}", info.domainname());

    Ok(())
}
