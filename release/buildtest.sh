#!/bin/sh

assetpath=$1
version=$2

rm -rf vtun-ng-$version
tar xzvf $assetpath/vtun-ng-$version.tar.gz || exit 1
cd vtun-ng-$version || exit 1
cargo build -r || exit 1
if [ ! -f target/release/vtunngd ]; then
  echo 'Did not build the binary'
  exit 1
fi
INSTALL_PREFIX=test-image INSTALL_OWNER=" " ./install.sh || exit 1
if [ ! -f image/usr/local/bin/vtunngd ]; then
  echo 'Did not install'
  exit 1
fi
cd ..
rm -rf vtun-ng-$version
rm -rf test-image
