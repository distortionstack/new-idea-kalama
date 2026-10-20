set -eu
ES_VERSION='1.4.3'
ARCHIVE="elasticsearch-${ES_VERSION}.tar.gz"
ARCHIVE_URL="https://download.elastic.co/elasticsearch/elasticsearch/${ARCHIVE}"
ARCHIVE_SHA1='d26828bef335a164175f5af14a2a7fc44cb063f2'
WORKDIR='/tmp/kalama-es-1.4.3-remediation'
rm -rf "$WORKDIR"
mkdir -p "$WORKDIR"
for tool in sha1sum tar java; do
  command -v "$tool" >/dev/null 2>&1 || { echo "missing required tool: $tool" >&2; exit 20; }
done
if command -v wget >/dev/null 2>&1; then
  wget -O "$WORKDIR/$ARCHIVE" "$ARCHIVE_URL"
elif command -v curl >/dev/null 2>&1; then
  curl -fL -o "$WORKDIR/$ARCHIVE" "$ARCHIVE_URL"
else
  echo 'missing required downloader: wget or curl' >&2
  exit 20
fi
printf '%s  %s\n' "$ARCHIVE_SHA1" "$WORKDIR/$ARCHIVE" | sha1sum -c -
tar -xzf "$WORKDIR/$ARCHIVE" -C "$WORKDIR"
test -x "$WORKDIR/elasticsearch-${ES_VERSION}/bin/elasticsearch"
test -d /usr/share/elasticsearch
test -d /usr/share/elasticsearch/config
cp -a /usr/share/elasticsearch/config "$WORKDIR/config.before"
rm -rf /usr/share/elasticsearch
mkdir -p /usr/share
mv "$WORKDIR/elasticsearch-${ES_VERSION}" /usr/share/elasticsearch
rm -rf /usr/share/elasticsearch/config
cp -a "$WORKDIR/config.before" /usr/share/elasticsearch/config
chown -R root:root /usr/share/elasticsearch
rm -rf "$WORKDIR"
/usr/share/elasticsearch/bin/elasticsearch -v
