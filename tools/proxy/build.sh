#!/bin/bash
cargo build
cp ../target/debug/proxy ../../server/dev/proxy-dev/
# Could link (?), eventually there should be built docker images
