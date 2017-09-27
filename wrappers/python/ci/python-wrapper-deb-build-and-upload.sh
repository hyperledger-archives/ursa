#!/usr/bin/env bash

if [ "$1" = "--help" ] ; then
  echo "Usage: <type> <suffix>"
  return
fi

type="$1"
number="$2"

sed -i -E "s/version='([0-9,.]+).*/version='\\1-$number',/" setup.py

PACKAGE_NAME=$(grep -Po "(?<=name=').[^\']*" setup.py)
LICENSE=$(grep -Po "(?<=license=').[^\']*" setup.py)

mkdir debs

fpm --input-type "python" \
    --output-type "deb" \
    --verbose \
    --architecture "amd64" \
    --name python3-${PACKAGE_NAME} \
    --license ${LICENSE} \
    --python-package-name-prefix "python3" \
    --python-bin "/usr/bin/python3" \
    --exclude "*.pyc" \
    --exclude "*.pyo" \
    --maintainer "Hyperledger <hyperledger-indy@lists.hyperledger.org>" \
    --package "./debs" \
    .

./sovrin-packaging/upload_debs.py ./debs $type