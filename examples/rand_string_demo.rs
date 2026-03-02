use os_utils::rand_string;

fn main() {
    println!("Random String Generator with SIMD Optimization\n");
    println!("Generating random URL-safe strings...\n");

    // Generate strings of various lengths
    let lengths = [8, 16, 32, 64, 128];

    for &len in &lengths {
        let s = rand_string(len);
        println!("Length {:3}: {}", len, s);

        // Verify charset
        let valid_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        for ch in s.chars() {
            assert!(valid_chars.contains(ch), "Invalid character: {}", ch);
        }
    }

    println!("\n✓ All strings generated successfully with valid characters!");

    // Show that SIMD is being used (on x86_64 with SSSE3)
    #[cfg(target_arch = "x86_64")]
    {
        if is_x86_feature_detected!("ssse3") {
            println!("✓ SIMD (SSSE3) optimization is active");
        } else {
            println!("ℹ SIMD not available, using scalar fallback");
        }
    }
}
