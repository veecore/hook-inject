use std::time::Duration;

fn main() {
    let sleep_ms = std::env::args()
        .nth(1)
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(15_000);

    std::thread::sleep(Duration::from_millis(sleep_ms));
}
