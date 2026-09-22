use krymux::compress::Decompressor;

fn main() -> anyhow::Result<()> {
    let wire = std::fs::read("C:/tmp/node-brotli-1mb.bin")?;
    let d = Decompressor::new("brotli");
    let _ = &d; // parity with the probe it replicates
                // direct instrumentation: replicate push internals with prints
    let mut out = Vec::new();
    let mut outbuf = [0u8; 65536];
    let mut avail_in = wire.len();
    let mut input_offset = 0usize;
    let mut total_out: usize = 0;
    let mut state = brotli::BrotliState::new(
        brotli::HeapAlloc::default(),
        brotli::HeapAlloc::default(),
        brotli::HeapAlloc::default(),
    );
    for i in 0..10 {
        let mut avail_out = outbuf.len();
        let mut output_offset = 0usize;
        let res = brotli::BrotliDecompressStream(
            &mut avail_in,
            &mut input_offset,
            &wire,
            &mut avail_out,
            &mut output_offset,
            &mut outbuf,
            &mut total_out,
            &mut state,
        );
        println!(
            "call {}: res={:?} in_left={} out_n={} total_out={}",
            i, res, avail_in, output_offset, total_out
        );
        out.extend_from_slice(&outbuf[..output_offset]);
        match res {
            brotli::BrotliResult::NeedsMoreOutput => continue,
            brotli::BrotliResult::NeedsMoreInput => {
                if avail_in > 0 {
                    continue;
                }
                break;
            }
            brotli::BrotliResult::ResultSuccess => {
                println!("SUCCESS at call {}", i);
                break;
            }
            brotli::BrotliResult::ResultFailure => {
                println!("FAILURE");
                break;
            }
        }
    }
    println!("out total: {}", out.len());
    Ok(())
}
