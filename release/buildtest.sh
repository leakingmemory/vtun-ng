#!/bin/sh

assetpath=$1
version=$2

rm -rf vtun-ng-$version
tar xzvf $assetpath/vtun-ng-$version.tar.gz || exit 1
pushd vtun-ng-$version || exit 1
./configure || exit 1
make || exit 1
if [ ! -f vtunngd ]; then
  echo 'Did not build the binary'
  exit 1
fi
popd
rm -rf vtun-ng-$version
