# SIMD Optimization for `rand_string`

This implementation uses SIMD instructions to accelerate the charset lookup in `rand_string`:
- **SSSE3** on x86_64 architectures
- **NEON** on AArch64/ARM64 architectures

## Implementation Details

The optimization processes 16 bytes at a time using SIMD table lookup instructions:
- `_mm_shuffle_epi8` (PSHUFB) on x86_64
- `vqtbl1q_u8` on ARM NEON

### Key Optimization: 16-Byte Chunk Processing

The implementation always operates on 16-byte aligned chunks:
1. For input length `n`, allocate `(n + 15) & ~15` bytes (round up to nearest 16-byte boundary)
2. Generate random bytes for the rounded-up length
3. Process ALL bytes with SIMD (no scalar fallback needed)
4. Truncate the result to the requested length

This approach eliminates conditional branching and scalar fallback code, resulting in cleaner and faster execution.

### Charset Mapping

The URL-safe charset (64 characters) is mapped as follows:
- Indices 0-25: A-Z (uppercase letters)
- Indices 26-51: a-z (lowercase letters)
- Indices 52-61: 0-9 (digits)
- Index 62: - (hyphen)
- Index 63: _ (underscore)

Since each random byte provides 8 bits of entropy, we extract 6 bits (by shifting right by 2) to get values in the range 0-63, which map directly to our charset.

### SIMD Approach

The implementation uses the same algorithm on both x86_64 and ARM NEON architectures:

The charset is split into 4 lookup tables (LUTs) of 16 characters each:

1. **LUT0** (indices 0-15): A-P
2. **LUT1** (indices 16-31): Q-Z, a-f
3. **LUT2** (indices 32-47): g-v
4. **LUT3** (indices 48-63): w-z, 0-9, -, _

For each batch of 16 bytes:
1. Extract 6 bits from each byte (shift right by 2)
2. Split the 6-bit value into:
   - High 2 bits: determine which LUT to use (0-3)
   - Low 4 bits: index within the selected LUT (0-15)
3. Perform lookups in all 4 tables using:
   - `_mm_shuffle_epi8` on x86_64 (SSSE3)
   - `vqtbl1q_u8` on ARM (NEON)
4. Use comparison masks to select the correct result from each LUT
5. Blend the results together

### Performance

The SIMD implementation provides significant performance improvements, especially for longer strings.

**End-to-end performance** (including random generation and allocation):

```
Size   16 bytes:    340 ns/iter (   46.97 MB/s)
Size   32 bytes:    367 ns/iter (   87.00 MB/s)
Size   64 bytes:    357 ns/iter (  178.91 MB/s)
Size  128 bytes:    394 ns/iter (  324.73 MB/s)
Size  256 bytes:    470 ns/iter (  544.06 MB/s)
Size  512 bytes:    637 ns/iter (  802.84 MB/s)
Size 1024 bytes:    925 ns/iter ( 1106.72 MB/s)
Size 4096 bytes:   2521 ns/iter ( 1624.60 MB/s)
```

**Charset lookup performance** (SIMD vs Scalar):

```
Size       |     Scalar (ns) |       SIMD (ns) |    Speedup
-----------+-----------------+-----------------+-----------
16 bytes   |               8 |              11 |      0.73x
32 bytes   |              16 |               7 |      2.29x
64 bytes   |              29 |              15 |      1.93x
128 bytes  |              59 |              19 |      3.11x
256 bytes  |              90 |              41 |      2.20x
512 bytes  |             170 |              87 |      1.95x
1024 bytes |             340 |             144 |      2.36x
2048 bytes |             708 |             268 |      2.64x
4096 bytes |            1498 |             563 |      2.66x
```

The SIMD implementation shows **2-3x speedup** for the charset lookup operation on strings ≥32 bytes. For very small strings (16 bytes), the scalar implementation is competitive due to lower overhead.

The elimination of scalar fallback provides consistent performance across all string lengths.

### Platform Support

- **x86_64 with SSSE3**: Uses optimized SIMD implementation with `_mm_shuffle_epi8`
- **AArch64/ARM64 with NEON**: Uses optimized SIMD implementation with `vqtbl1q_u8`
- **Other platforms**: Falls back to scalar implementation

**CPU Feature Availability:**
- SSSE3 (x86_64): Available on almost all modern x86_64 processors since 2006 (Intel Core 2 and later, AMD Bulldozer and later)
- NEON (ARM): Standard on all ARMv8-A processors (required by the architecture)

### References

This implementation is inspired by techniques in:
- https://github.com/WojciechMula/base64simd
- Base64 encoding/decoding SIMD optimizations

## Testing

The implementation includes comprehensive tests to verify:
1. Correctness of generated strings
2. Consistency between SIMD and scalar implementations
3. All characters are from the valid charset
4. Correct length handling for non-16-byte-aligned requests

Run tests with:
```bash
cargo test test_rand_string
cargo test test_rand_string_simd_consistency
cargo test test_rand_string_lengths
```

Run benchmarks with:
```bash
# End-to-end rand_string performance
cargo bench --bench rand_string_bench

# Direct comparison of SIMD vs scalar charset lookup
cargo bench --bench simd_vs_scalar

# Run all benchmarks
cargo bench
```
