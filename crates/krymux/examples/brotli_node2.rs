use krymux::compress::Decompressor;

fn main() -> anyhow::Result<()> {
    let wire = std::fs::read("C:/tmp/node-brotli-1mb.bin")?;
    println!("wire total {}", wire.len());
    // A: one single push with everything
    let mut d = Decompressor::new("brotli");
    let out = d.push(&wire)?;
    println!("single push -> {}", out.len());
    // B: byte-by-byte (worst case splitting)
    let mut d2 = Decompressor::new("brotli");
    let mut total = 0usize;
    for b in &wire {
        total += d2.push(std::slice::from_ref(b))?.len();
    }
    println!("byte-by-byte -> {}", total);
    // C: 467/16-sized frames like Node emitted
    let mut d3 = Decompressor::new("brotli");
    let mut total3 = 0usize;
    let mut n = 0;
    for frame in wire.chunks(30) {
        total3 += d3.push(frame)?.len();
        n += 1;
    }
    println!("30B frames ({} calls) -> {}", n, total3);
    Ok(())
}
