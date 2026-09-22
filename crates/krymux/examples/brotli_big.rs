use krymux::compress::{Compressor, Decompressor};

fn main() -> anyhow::Result<()> {
    let mut payload = vec![0u8; 1024 * 1024];
    let half = 1024 * 1024 / 2;
    for (i, b) in payload.iter_mut().enumerate() {
        *b = if i < half { (i * 31 % 251) as u8 } else { b'x' };
    }
    let mut c = Compressor::new("brotli", 4);
    let mut wire: Vec<Vec<u8>> = Vec::new();
    for chunk in payload.chunks(64 * 1024) {
        wire.push(c.push(chunk)?);
    }
    let total_wire: usize = wire.iter().map(|w| w.len()).sum();
    println!("compress: logical {} wire {}", payload.len(), total_wire);

    let mut d = Decompressor::new("brotli");
    let mut plain = Vec::new();
    for frame in &wire {
        // feed in <=64KB wire frames, like the tunnel reader delivers them
        let out = d.push(frame)?;
        plain.extend_from_slice(&out);
    }
    println!("decompress: got {} expect {}", plain.len(), payload.len());
    if plain.len() != payload.len() {
        let n = plain.len().min(payload.len());
        println!("prefix equal: {}", plain[..n] == payload[..n]);
    }
    Ok(())
}
