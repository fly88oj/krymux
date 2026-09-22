use krymux::compress::{Compressor, Decompressor};

fn main() -> anyhow::Result<()> {
    let binding = "world! ".repeat(100);
    let chunks: Vec<String> = vec![
        "hello brotli ".into(),
        "from rust ".into(),
        "chunked flush ".into(),
        binding,
    ];
    let mut c = Compressor::new("brotli", 4);
    let mut wire: Vec<u8> = Vec::new();
    for ch in &chunks {
        let out = c.push(ch.as_bytes())?;
        println!(
            "rust compress chunk {} -> {} wire bytes",
            ch.len(),
            out.len()
        );
        wire.extend_from_slice(&out);
    }
    std::fs::write("C:/tmp/rust-brotli.bin", &wire)?;
    let node_wire = std::fs::read("C:/tmp/node-brotli.bin")?;
    let mut d = Decompressor::new("brotli");
    let mut plain = Vec::new();
    for w in node_wire.chunks(64) {
        let out = d.push(w)?;
        plain.extend_from_slice(&out);
    }
    println!(
        "rust decompress of node stream: {} wire -> {} plain bytes",
        node_wire.len(),
        plain.len()
    );
    let head = &plain[..plain.len().min(40)];
    println!("plain starts: {:?}", String::from_utf8_lossy(head));
    Ok(())
}
