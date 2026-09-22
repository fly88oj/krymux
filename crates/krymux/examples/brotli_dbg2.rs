fn main() -> anyhow::Result<()> {
    let wire = std::fs::read("C:/tmp/node-brotli-1mb.bin")?;
    let mut outbuf = [0u8; 65536];
    let mut avail_in = wire.len();
    let mut input_offset = 0usize;
    let mut total_out: usize = 0;
    let mut state = brotli::BrotliState::new(
        brotli::HeapAlloc::default(),
        brotli::HeapAlloc::default(),
        brotli::HeapAlloc::default(),
    );
    // first call consumes everything, emits 65536
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
        "call0: {:?} in_left={} out={}",
        res, avail_in, output_offset
    );
    // now try to drain with EMPTY input repeatedly
    let empty: [u8; 0] = [];
    let mut total_drained = 0usize;
    for i in 0..40 {
        let mut avail_in2 = 0usize;
        let mut input_offset2 = 0usize;
        let mut avail_out2 = outbuf.len();
        let mut output_offset2 = 0usize;
        let res2 = brotli::BrotliDecompressStream(
            &mut avail_in2,
            &mut input_offset2,
            &empty,
            &mut avail_out2,
            &mut output_offset2,
            &mut outbuf,
            &mut total_out,
            &mut state,
        );
        total_drained += output_offset2;
        println!("drain {}: {:?} out={}", i, res2, output_offset2);
        match res2 {
            brotli::BrotliResult::NeedsMoreOutput => continue,
            _ => break,
        }
    }
    println!("drained total extra: {}", total_drained);
    Ok(())
}
