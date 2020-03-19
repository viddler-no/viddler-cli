pub mod arena;

pub fn times(msg: &str, d: std::time::Duration) {
    println!(
        "{}: {}",
        msg,
        (d.as_secs() as f32) + (d.as_nanos() as f32) / (1_000_000_000 as f32)
    );
}
