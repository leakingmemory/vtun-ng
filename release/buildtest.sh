#!/bin/sh

assetpath=$1
version=$2

rm -rf vtun-ng-$version
tar xzvf $assetpath/vtun-ng-$version.tar.gz || die
pushd vtun-ng-$version || die
./configure || die
make || die
if [ ! -f vtunngd ]; then
  echo 'Did not build the binary'
  die
fi
popd
rm -rf vtun-ng-$version
