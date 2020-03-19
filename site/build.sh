#!/bin/bash

BUILD_DIR=../server/base/site/build

rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR"
cp -r \
    pages/ \
    public/ \
    "$BUILD_DIR/"

cp \
    package-lock.json \
    package.json \
    "$BUILD_DIR/"