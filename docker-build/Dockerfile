FROM ubuntu:16.04
# we would love to use alpine as the build-image
# but unfortunately lede-build still fails with
# it when build some host-utils.

ARG LEDE_REVISION=e9c517772cee8af63b4ef173a28152645a4e1b05
ARG FREEWTP_REVISION=a4fed97ebafbfb07ded50e102be4a46fc9ac7cf3

RUN apt-get -y update && apt-get -y install \
	build-essential \
	python unzip gawk wget openssl git-core subversion \
	libssl-dev ncurses-dev

RUN mkdir /build
WORKDIR /build

RUN cd /build ; \
	git clone https://git.lede-project.org/source.git lede ; \
	cd lede ; git checkout -b docker_build $LEDE_REVISION

RUN cd /build ; \
	git clone https://github.com/travelping/freewtp ; \
	cd freewtp ; git checkout -b docker_build $FREEWTP_REVISION

RUN cp /build/lede/feeds.conf.default /build/lede/feeds.conf ; echo "src-link freewtp /build/freewtp/openwrt" >> /build/lede/feeds.conf
RUN cd /build/lede ; ./scripts/feeds update -a && ./scripts/feeds install -a && ./scripts/feeds list -r freewtp

RUN cp -v /build/freewtp/openwrt/mac80211_patches/922-mac80211_packet_tunnel-linux-4.8.patch /build/lede/package/kernel/mac80211/patches/
RUN cd /build/lede ; patch -p1 -i /build/freewtp/openwrt/mac80211_patches/package-config-option.patch

ADD ./dot-lede-config /build/lede/.config

RUN cd /build/lede ; make defconfig
RUN cd /build/lede ; make -j10 BUILD_LOG=1 FORCE_UNSAFE_CONFIGURE=1 ; rm -rf staging_dir build_dir

