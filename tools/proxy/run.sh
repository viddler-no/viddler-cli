#/bin/bash
cargo build && afplay /System/Library/Sounds/Submarine.aiff -v 10
RUST_BACKTRACE=1 cargo run -- --bind http://127.0.0.1:8080 --wordpress http://192.168.33.10 --cache_dir /Users/gudmund/code/proxy_cache --uploads_path /Users/gudmund/code/brygga/wp/wp-content/uploads
