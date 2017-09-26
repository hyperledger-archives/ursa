#!/bin/bash -xe

if [ "$1" = "--help" ] ; then
  echo "Usage: <version> <type> <number>"
  return
fi

version="$1"
type="$2"
number="$3"

[ -z $version ] && exit 1
[ -z $type ] && exit 2
[ -z $number ] && exit 3

dpkg-buildpackage -tc

rename -v "s/$version/$version-$number/" ../*.deb

./sovrin-packaging/upload_debs.py ../ $type