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

mkdir libhl_crypto-zip
mkdir libhl_crypto-zip/lib
cp -r ./include ./libhl_crypto-zip
cp ./target/release/*.dll ./libhl_crypto-zip/lib/
cp $prebuit_path/lib/*.dll ./libhl_crypto-zip/lib/

cd libhl_crypto-zip && zip -r libindy_crypto_${version}.zip ./* && mv libindy_crypto_${version}.zip .. && cd ..

rm -rf libhl_crypto-zip

cat <<EOF | sftp -v -oStrictHostKeyChecking=no -i $key repo@192.168.11.115
mkdir /var/repository/repos/windows/libhl_crypto/$type/$version-$number
cd /var/repository/repos/windows/libhl_crypto/$type/$version-$number
put -r libhl_crypto_"$version".zip
ls -l /var/repository/repos/windows/libhl_crypto/$type/$version-$number
EOF
