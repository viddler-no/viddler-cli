#!/bin/bash
cargo build --release
cp ../target/release/proxy ../../server/prod/proxy-prod/proxy
