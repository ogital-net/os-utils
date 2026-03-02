use std::hint::black_box;
use std::time::Instant;

fn main() {
    println!("Benchmarking rand_string performance with SIMD optimization\n");

    let sizes = [16, 32, 64, 128, 256, 512, 1024, 4096];
    let iterations = 1000000;

    for &size in &sizes {
        let start = Instant::now();

        for _ in 0..iterations {
            let s = os_utils::rand_string(size);
            black_box(s);
        }

        let duration = start.elapsed();
        let per_iter = duration.as_nanos() / iterations;
        let throughput = (size as f64 * iterations as f64) / duration.as_secs_f64() / 1_000_000.0;

        println!(
            "Size {:4} bytes: {:6} ns/iter ({:8.2} MB/s)",
            size, per_iter, throughput
        );
    }
}
