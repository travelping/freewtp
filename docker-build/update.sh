#!/bin/sh
lede=$(git ls-remote https://git.lede-project.org/source.git | grep 'refs/heads/master$' | cut -f1)
freewtp=$(git ls-remote https://github.com/travelping/freewtp | grep 'refs/heads/master$' | cut -f1)

echo "found upstream ref to lede master: $lede"
echo "found upstream ref to freewtp master: $freewtp"


sed -i "s/^ARG LEDE_REVISION=.*$/ARG LEDE_REVISION=$lede/" Dockerfile
sed -i "s/^ARG FREEWTP_REVISION=.*$/ARG FREEWTP_REVISION=$freewtp/" Dockerfile
