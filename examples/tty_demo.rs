use os_utils::{Stderr, Stdin, Stdout, TtyInfo as _};

fn main() {
    let stdin = Stdin::new();
    let stdout = Stdout::new();
    let stderr = Stderr::new();

    println!("=== Terminal Information ===\n");

    // Check stdin
    print!("stdin  (fd 0): ");
    if stdin.isatty() {
        match stdin.ttyname() {
            Ok(name) => println!("Connected to terminal: {}", name.display()),
            Err(e) => println!("Error getting tty name: {e}"),
        }
    } else {
        println!("Not a terminal (redirected or piped)");
    }

    // Check stdout
    print!("stdout (fd 1): ");
    if stdout.isatty() {
        match stdout.ttyname() {
            Ok(name) => println!("Connected to terminal: {}", name.display()),
            Err(e) => println!("Error getting tty name: {e}"),
        }
    } else {
        println!("Not a terminal (redirected or piped)");
    }

    // Check stderr
    print!("stderr (fd 2): ");
    if stderr.isatty() {
        match stderr.ttyname() {
            Ok(name) => println!("Connected to terminal: {}", name.display()),
            Err(e) => println!("Error getting tty name: {e}"),
        }
    } else {
        println!("Not a terminal (redirected or piped)");
    }

    println!("\n=== Try redirecting to see different results ===");
    println!("Examples:");
    println!("  cargo run --example tty_demo");
    println!("  cargo run --example tty_demo > /dev/null");
    println!("  cargo run --example tty_demo 2> /dev/null");
    println!("  echo 'test' | cargo run --example tty_demo");
}
