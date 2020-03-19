#!/bin/bash

# Todo: rsync might be better choice

# Use extended globbing to exclude target, .git, .DS_Store
shopt -s extglob

VAGRANT_DIR=../vagrant/src-proxy

# Make sure directory exist and copy relevant files
# Want to keep it's target folder for the cache
mkdir -p "$VAGRANT_DIR"
cp -Rf ./!(target|.git|.DS_Store) "$VAGRANT_DIR/"

# Transfer over to script on vagrant
pushd ../vagrant
vagrant ssh -c 'source /vagrant/prod/proxy-prod/build.sh'
popd
