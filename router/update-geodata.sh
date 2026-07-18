#!/bin/sh
set -eu

# 修改为你的 GitHub 用户名和仓库名。
OWNER="CHANGE_ME"
REPO="passwall2-custom-rules"

BASE_URL="https://github.com/${OWNER}/${REPO}/releases/latest/download"
TMP_DIR="/tmp/passwall2-custom-geodata.$$"
ASSET_DIR="/usr/share/v2ray"

cleanup() {
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT INT TERM

mkdir -p "$TMP_DIR" "$ASSET_DIR"

for file in mianmian-geosite.dat mianmian-geoip.dat SHA256SUMS; do
  wget -q -O "$TMP_DIR/$file" "$BASE_URL/$file"
done

cd "$TMP_DIR"
grep '  mianmian-.*\.dat$' SHA256SUMS > CHECKSUMS
sha256sum -c CHECKSUMS

[ -s mianmian-geosite.dat ]
[ -s mianmian-geoip.dat ]

cp mianmian-geosite.dat "$ASSET_DIR/mianmian-geosite.dat.new"
cp mianmian-geoip.dat "$ASSET_DIR/mianmian-geoip.dat.new"
chmod 0644 "$ASSET_DIR/mianmian-geosite.dat.new" "$ASSET_DIR/mianmian-geoip.dat.new"

mv -f "$ASSET_DIR/mianmian-geosite.dat.new" "$ASSET_DIR/mianmian-geosite.dat"
mv -f "$ASSET_DIR/mianmian-geoip.dat.new" "$ASSET_DIR/mianmian-geoip.dat"

/etc/init.d/passwall2 restart
logger -t passwall2-geodata "custom geodata updated successfully"
