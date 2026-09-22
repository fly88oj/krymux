use krymux::compress::Decompressor;

fn main() -> anyhow::Result<()> {
    let wire = std::fs::read("C:/tmp/node-brotli-1mb.bin")?;
    println!("wire total {}", wire.len());
    let mut d = Decompressor::new("brotli");
    let mut plain = Vec::new();
    let mut frame_sizes = Vec::new();
    // replay with 64KB frames exactly as the mux delivers them
    let mut frames = Vec::new();
    let mut off = 0;
    while off < wire.len() {
        let take = (wire.len() - off).min(65536);
        frames.push(wire[off..off + take].to_vec());
        off += take;
    }
    for f in &frames {
        let out = d.push(f)?;
        frame_sizes.push(out.len());
        plain.extend_from_slice(&out);
    }
    println!(
        "decompressed {} (expect 1048576), per-frame out: {:?}",
        plain.len(),
        frame_sizes
    );
    Ok(())
}
