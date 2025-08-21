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
echo "Testing install-script"
INSTALL_PREFIX=test-image INSTALL_OWNER=" " ./install.sh || exit 1
if [ ! -f test-image/usr/local/bin/vtunngd ]; then
  echo 'Did not install'
  exit 1
fi
rm -rf test-image
cargo test || exit 1
cd ..
echo "Cleaning up"
rm -rf vtun-ng-$version
echo "Success"