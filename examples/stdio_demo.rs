use os_utils::{Stderr, Stdin, Stdout};
use std::io::{Read, Write};

fn main() {
    // Create instances of the standard streams
    let mut stdin = Stdin::new();
    let mut stdout = Stdout::new();
    let mut stderr = Stderr::new();

    // Write to stdout
    let msg = b"Enter some text: ";
    stdout.write_all(msg).expect("Failed to write to stdout");
    stdout.flush().expect("Failed to flush stdout");

    // Read from stdin
    let mut buffer = [0u8; 128];
    match stdin.read(&mut buffer) {
        Ok(n) => {
            // Write to stdout
            stdout
                .write_all(b"You entered: ")
                .expect("Failed to write to stdout");
            stdout
                .write_all(&buffer[..n])
                .expect("Failed to write to stdout");
            stdout.flush().expect("Failed to flush stdout");

            // Write to stderr
            stderr
                .write_all(b"[Debug] Read ")
                .expect("Failed to write to stderr");
            let count_str = format!("{n}");
            stderr
                .write_all(count_str.as_bytes())
                .expect("Failed to write to stderr");
            stderr
                .write_all(b" bytes from stdin\n")
                .expect("Failed to write to stderr");
            stderr.flush().expect("Failed to flush stderr");
        }
        Err(e) => {
            stderr
                .write_all(b"Error reading from stdin: ")
                .expect("Failed to write to stderr");
            let err_msg = format!("{e}\n");
            stderr
                .write_all(err_msg.as_bytes())
                .expect("Failed to write to stderr");
            stderr.flush().expect("Failed to flush stderr");
        }
    }
}
