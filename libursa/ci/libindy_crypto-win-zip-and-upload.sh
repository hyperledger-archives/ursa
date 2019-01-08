#!/bin/bash -xe

if [ "$1" = "--help" ] ; then
  echo "Usage: <version> <key> <type> <number> <prebuit_path>"
  return
fi

version="$1"
key="$2"
type="$3"
number="$4"

[ -z $version ] && exit 1
[ -z $key ] && exit 2
[ -z $type ] && exit 3
[ -z $number ] && exit 4
[ -z $prebuit_path ] && exit 5

mkdir libursa-zip
mkdir libursa-zip/lib
cp -r ./include ./libursa-zip
cp ./target/release/*.dll ./libursa-zip/lib/
cp $prebuit_path/lib/*.dll ./libursa-zip/lib/

cd libursa-zip && zip -r libindy_crypto_${version}.zip ./* && mv libindy_crypto_${version}.zip .. && cd ..

rm -rf libursa-zip

cat <<EOF | sftp -v -oStrictHostKeyChecking=no -i $key repo@192.168.11.115
mkdir /var/repository/repos/windows/libursa/$type/$version-$number
cd /var/repository/repos/windows/libursa/$type/$version-$number
put -r libursa_"$version".zip
ls -l /var/repository/repos/windows/libursa/$type/$version-$number
EOF
