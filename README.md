# PassWall2 custom Xray geodata

This repository downloads the rule sources listed in `sources.json`, converts supported domain/IP rules into Xray geodata files, and publishes them as GitHub Release assets.

## Generated assets

- `mianmian-geosite.dat`
- `mianmian-geoip.dat`
- `SHA256SUMS`
- `build-report.txt`

## Manual build

```bash
python -m pip install protobuf
python scripts/build.py
```

## Stable release URLs

Replace `OWNER` and `REPO`:

```text
https://github.com/OWNER/REPO/releases/latest/download/mianmian-geosite.dat
https://github.com/OWNER/REPO/releases/latest/download/mianmian-geoip.dat
https://github.com/OWNER/REPO/releases/latest/download/SHA256SUMS
```

## Router updater

Edit `OWNER` and `REPO` in `router/update-geodata.sh`, then install it on OpenWrt.
