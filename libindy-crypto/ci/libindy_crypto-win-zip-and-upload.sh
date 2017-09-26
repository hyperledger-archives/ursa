#!/bin/bash -xe

if [ "$1" = "--help" ] ; then
  echo "Usage: <version> <key> <type> <number>"
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

mkdir libindy_crypto-zip
mkdir libindy_crypto-zip/lib
cp -r ./include ./libindy_crypto-zip
cp ./target/release/*.dll ./libindy_crypto-zip/lib/
powershell.exe -nologo -noprofile -command "& { Add-Type -A 'System.IO.Compression.FileSystem'; [IO.Compression.ZipFile]::CreateFromDirectory('libindy_crypto-zip', 'libindy_crypto_$version.zip'); }"
rm -rf ./libindy-zip

cat <<EOF | sftp -v -oStrictHostKeyChecking=no -i $key repo@192.168.11.115
mkdir /var/repository/repos/windows/libindy_crypto/$type/$version-$number
cd /var/repository/repos/windows/libindy_crypto/$type/$version-$number
put -r libindy_crypto_"$version".zip
ls -l /var/repository/repos/windows/libindy_crypto/$type/$version-$number
EOF
