use std::hint::black_box;
use std::time::Instant;

fn main() {
    #[cfg(target_arch = "x86_64")]
    {
        if !is_x86_feature_detected!("ssse3") {
            println!("SSSE3 not detected, SIMD benchmark not available");
            return;
        }

        println!("Comparing Scalar vs SIMD (SSSE3) Random String Generation\n");
        run_benchmark();
    }

    #[cfg(target_arch = "aarch64")]
    {
        if !std::arch::is_aarch64_feature_detected!("neon") {
            println!("NEON not detected, SIMD benchmark not available");
            return;
        }

        println!("Comparing Scalar vs SIMD (NEON) Random String Generation\n");
        run_benchmark();
    }

    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        println!("This benchmark requires x86_64 (SSSE3) or aarch64 (NEON) architecture");
        return;
    }
}

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
fn run_benchmark() {
    println!(
        "{:<10} | {:>15} | {:>15} | {:>10}",
        "Size", "Scalar (ns)", "SIMD (ns)", "Speedup"
    );
    println!("{:-<10}-+-{:-<15}-+-{:-<15}-+-{:-<10}", "", "", "", "");

    let sizes = [16, 32, 64, 128, 256, 512, 1024, 2048, 4096];
    let iterations = 1000000;

    for &size in &sizes {
        // Benchmark scalar implementation
        let mut scalar_buf = vec![0u8; size];
        os_utils::rand_bytes(&mut scalar_buf).unwrap();
        let scalar_input = scalar_buf.clone();

        let start = Instant::now();
        for _ in 0..iterations {
            scalar_buf.copy_from_slice(&scalar_input);
            benchmark_scalar(&mut scalar_buf);
            black_box(&scalar_buf);
        }
        let scalar_time = start.elapsed();
        let scalar_ns = scalar_time.as_nanos() / iterations;

        // Benchmark SIMD implementation (requires 16-byte aligned size)
        let simd_size = (size + 15) & !15;
        let mut simd_buf = vec![0u8; simd_size];
        os_utils::rand_bytes(&mut simd_buf).unwrap();
        let simd_input = simd_buf.clone();

        let start = Instant::now();
        for _ in 0..iterations {
            simd_buf.copy_from_slice(&simd_input);
            unsafe { benchmark_simd(&mut simd_buf) };
            black_box(&simd_buf);
        }
        let simd_time = start.elapsed();
        let simd_ns = simd_time.as_nanos() / iterations;

        let speedup = scalar_ns as f64 / simd_ns as f64;

        println!(
            "{:<10} | {:>15} | {:>15} | {:>9.2}x",
            format!("{} bytes", size),
            scalar_ns,
            simd_ns,
            speedup
        );
    }

    println!("\nNote: SIMD processes rounded-up 16-byte aligned buffers");
}

// Scalar implementation - works on all architectures
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
fn benchmark_scalar(buf: &mut [u8]) {
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

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "ssse3")]
unsafe fn benchmark_simd(buf: &mut [u8]) {
    unsafe {
        use std::arch::x86_64::*;

        let lut0 = _mm_setr_epi8(
            b'A' as i8, b'B' as i8, b'C' as i8, b'D' as i8, b'E' as i8, b'F' as i8, b'G' as i8,
            b'H' as i8, b'I' as i8, b'J' as i8, b'K' as i8, b'L' as i8, b'M' as i8, b'N' as i8,
            b'O' as i8, b'P' as i8,
        );

        let lut1 = _mm_setr_epi8(
            b'Q' as i8, b'R' as i8, b'S' as i8, b'T' as i8, b'U' as i8, b'V' as i8, b'W' as i8,
            b'X' as i8, b'Y' as i8, b'Z' as i8, b'a' as i8, b'b' as i8, b'c' as i8, b'd' as i8,
            b'e' as i8, b'f' as i8,
        );

        let lut2 = _mm_setr_epi8(
            b'g' as i8, b'h' as i8, b'i' as i8, b'j' as i8, b'k' as i8, b'l' as i8, b'm' as i8,
            b'n' as i8, b'o' as i8, b'p' as i8, b'q' as i8, b'r' as i8, b's' as i8, b't' as i8,
            b'u' as i8, b'v' as i8,
        );

        let lut3 = _mm_setr_epi8(
            b'w' as i8, b'x' as i8, b'y' as i8, b'z' as i8, b'0' as i8, b'1' as i8, b'2' as i8,
            b'3' as i8, b'4' as i8, b'5' as i8, b'6' as i8, b'7' as i8, b'8' as i8, b'9' as i8,
            b'-' as i8, b'_' as i8,
        );

        let len = buf.len();
        let mut i = 0;

        while i < len {
            let input = _mm_loadu_si128(buf.as_ptr().add(i) as *const __m128i);

            let indices = _mm_srli_epi16(input, 2);
            let indices = _mm_and_si128(indices, _mm_set1_epi8(0x3f));

            let hi_bits = _mm_srli_epi16(indices, 4);
            let hi_bits = _mm_and_si128(hi_bits, _mm_set1_epi8(0x03));
            let lo_bits = _mm_and_si128(indices, _mm_set1_epi8(0x0f));

            let result0 = _mm_shuffle_epi8(lut0, lo_bits);
            let result1 = _mm_shuffle_epi8(lut1, lo_bits);
            let result2 = _mm_shuffle_epi8(lut2, lo_bits);
            let result3 = _mm_shuffle_epi8(lut3, lo_bits);

            let mask0 = _mm_cmpeq_epi8(hi_bits, _mm_setzero_si128());
            let mask1 = _mm_cmpeq_epi8(hi_bits, _mm_set1_epi8(1));
            let mask2 = _mm_cmpeq_epi8(hi_bits, _mm_set1_epi8(2));
            let mask3 = _mm_cmpeq_epi8(hi_bits, _mm_set1_epi8(3));

            let mut result = _mm_and_si128(mask0, result0);
            result = _mm_or_si128(result, _mm_and_si128(mask1, result1));
            result = _mm_or_si128(result, _mm_and_si128(mask2, result2));
            result = _mm_or_si128(result, _mm_and_si128(mask3, result3));

            _mm_storeu_si128(buf.as_mut_ptr().add(i) as *mut __m128i, result);

            i += 16;
        }
    }
}

// ARM NEON SIMD implementation
#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "neon")]
unsafe fn benchmark_simd(buf: &mut [u8]) {
    unsafe {
        use std::arch::aarch64::*;

        let lut0 = [
            b'A', b'B', b'C', b'D', b'E', b'F', b'G', b'H', b'I', b'J', b'K', b'L', b'M', b'N',
            b'O', b'P',
        ];

        let lut1 = [
            b'Q', b'R', b'S', b'T', b'U', b'V', b'W', b'X', b'Y', b'Z', b'a', b'b', b'c', b'd',
            b'e', b'f',
        ];

        let lut2 = [
            b'g', b'h', b'i', b'j', b'k', b'l', b'm', b'n', b'o', b'p', b'q', b'r', b's', b't',
            b'u', b'v',
        ];

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

        while i < len {
            let input = vld1q_u8(buf.as_ptr().add(i));

            let indices = vshrq_n_u8(input, 2);
            let indices = vandq_u8(indices, vdupq_n_u8(0x3f));

            let hi_bits = vshrq_n_u8(indices, 4);
            let hi_bits = vandq_u8(hi_bits, vdupq_n_u8(0x03));
            let lo_bits = vandq_u8(indices, vdupq_n_u8(0x0f));

            let result0 = vqtbl1q_u8(lut0_vec, lo_bits);
            let result1 = vqtbl1q_u8(lut1_vec, lo_bits);
            let result2 = vqtbl1q_u8(lut2_vec, lo_bits);
            let result3 = vqtbl1q_u8(lut3_vec, lo_bits);

            let zero_vec = vdupq_n_u8(0);
            let mask0 = vceqq_u8(hi_bits, zero_vec);
            let mask1 = vceqq_u8(hi_bits, vdupq_n_u8(1));
            let mask2 = vceqq_u8(hi_bits, vdupq_n_u8(2));
            let mask3 = vceqq_u8(hi_bits, vdupq_n_u8(3));

            let mut result = vbslq_u8(mask0, result0, zero_vec);
            result = vorrq_u8(result, vandq_u8(mask1, result1));
            result = vorrq_u8(result, vandq_u8(mask2, result2));
            result = vorrq_u8(result, vandq_u8(mask3, result3));

            vst1q_u8(buf.as_mut_ptr().add(i), result);

            i += 16;
        }
    }
}
