
.PHONY: all help dependencies build config user clean

INSTALLDIR := $(shell pwd)/../build

export PKG_CONFIG_PATH=/usr/local/lib/pkgconfig:/usr/X11/lib/pkgconfig

help:
	@echo "Wireshark build targets"
	@echo "----------------------------------------------------------------"
	@echo "plugin   - build the wireshark plugin for CCNx"
	@echo "dependencies - install linux package dependencies"
	@echo "Gtk       - build generic wireshark with Gtk GUI and add the ccnxtlv plugin"
	@echo "clean     - delete previously built artifacts"
#	@echo "testdata  - create test data"
	@echo ""
	@echo "user      - enable user for raw device mode (used with ethernet interfaces)"
	@echo ""
	@echo "Wireshark depends on these modules.  "
	@echo "   brew install qt --with-developer"
	@echo "   brew install pkg-config gtk+3 xz cmake gettext glib libsmi \\"
	@echo "                libgpg-error gcrypt libgcrypt gnutls lua portaudio geoip"
	@echo "On Mac OS X, I'd recommend installing them with Home Brew (http://brew.sh)."
	@echo "Or, you can execute"
	@echo "   make depends"
	@echo "which will use the wireshark provided dependency build."
	@echo ""
	@echo "On ubuntu, use:"
	@echo "  aptitude install xz-utils libtool libsmi2-dev cmake libglib2.0-dev \\"
	@echo "     qt4-dev-tools qt4-bin-dbg gnutls-dev libgcrypt-dev bison flex \\"
	@echo "     liblua5.2-dev libpcap-dev"
	@echo ""
	@echo "NOTE: must have at least One Gigabyte of RAM to compile wireshark"

	


####
# Figure out the operating system

OS=$(shell uname)
OSOK=0

ifeq ($(OS),Linux)
OSOK=1
VERSION=1.12.5
SHARK=wireshark-$(VERSION)
OS_NAME="ubuntu-14_04"

GEOIP="--with-geoip=no"
QT="-with-qt=yes"
LUA="--with-lua=/usr"
SMI="--with-libsmi=/usr"
GCRYPT="--with-libgcrypt-prefix=/usr"
ARES="--with-c-ares=no"
endif

ifeq ($(OS),Darwin)
OSOK=1
VERSION=1.12.5
SHARK=wireshark-$(VERSION)
OS_NAME="macosx_10_10_5"

GEOIP="--with-geoip=no"
QT="-with-qt=yes"
LUA="--with-lua=/usr/local"
SMI="--with-libsmi=/usr/local"
GCRYPT=--with-gcrypt=no --with-gnutls=no
ARES="--with-c-ares=no"
endif

ifeq ($(OSOK),0)
$(error Could not find proper OS, please edit the Makefile: OS=$(OS))
endif

#
#####

$(SHARK).tar.bz2:
ifeq ($(OS),Linux)
	wget http://www.wireshark.org/download/src/all-versions/$@
endif
ifeq ($(OS),Darwin)
	curl -O https://www.wireshark.org/download/src/all-versions/$@
endif
ifeq ($(OSOK),0)
$(error Could not find proper OS, please edit the Makefile: OS=$(OS))
endif

$(SHARK)/Makefile.am: $(SHARK).tar.bz2
	tar -xjf $^

wireshark: $(SHARK)/Makefile.am
	ln -s $(SHARK) $@

wireshark/plugins/ccntlv: wireshark
	if [ ! -d "src" ]; then \
		rsync -a plugin_source/* $(SHARK)/plugins/ccnxtlv/; \
		ln -s $(SHARK)/plugins/ccnxtlv src; \
		cd $(SHARK); patch -p 1 < ../ccnxtlv-patch-$(VERSION); ./autogen.sh; \
	fi

plugin: wireshark/plugins/ccntlv
ifeq ($(OS),Linux)
	cd wireshark; \
		./configure --prefix=$(INSTALLDIR) $(QT) $(GEOIP) $(SMI) $(LUA) $(GCRYPT) $(ARES)
	$(MAKE) -j4 -C wireshark
endif
ifeq ($(OS),Darwin)
	export PKG_CONFIG_PATH=/usr/local/lib/pkgconfig:/usr/X11/lib/pkgconfig
	@echo --prefix=$(INSTALLDIR) $(QT) $(GEOIP) $(SMI) $(LUA) $(GCRYPT) $(ARES)
	cd wireshark && ./configure --prefix=$(INSTALLDIR) $(QT) $(GEOIP) $(SMI) $(LUA) $(GCRYPT) $(ARES)
	#cd wireshark && ./configure 
	#$(MAKE) -j4 -C wireshark
	cd wireshark && mkdir build && cd build && cmake ../ && $(MAKE)
endif
ifeq ($(OSOK),0)
$(error Could not find proper OS, please edit the Makefile: OS=$(OS))
endif
	cp wireshark/plugins/ccnxtlv/.libs/ccnxtlv.so ccnxtlv-$(VERSION)-$(OS_NAME).so

Gtk: wireshark
	cd wireshark && ./configure
	$(MAKE) -j4 -C wireshark
	sudo $(MAKE) -C wireshark install
	sudo ldconfig
#	test -f ccnxtlv-$(VERSION)-$(OS_NAME).so && mkdir -p ~/.wireshark/plugins && cp ccnxtlv-$(VERSION)-$(OS_NAME).so ~/.wireshark/plugins/

clean:
	rm -rf wireshark $(SHARK)
	rm -f src
	rm -f ccnxtlv-$(VERSION)-$(OS_NAME).so

dependencies: 
# This is not part of the dependency chain
ifeq ($(OS),Linux)
	@echo install wireshark related libraries
	sudo apt-get update -y
	sudo apt-get build-dep wireshark -y
	sudo apt-get install qt4-default -y
	# add to the LIB search path
	sudo sh -c "echo '/usr/local/lib' >> /etc/ld.so.conf"
endif
ifeq ($(OS),Darwin)
	Xcode-select --install
	ruby -e "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/install)"
	brew install c-ares cmake glib gnutls lua
	brew install libgcrypt gnutls lua portaudio geoip
	brew install pkg-config gtk+3 xz cmake gettext glib libsmi libgpg-error
	brew install qt5
	# adjust below for correct qt5 version number
	brew link --force qt5 && ln -fs /usr/local/Cellar/qt5/5.5.0/mkspecs /usr/local/mkspecs && ln -fs /usr/local/Cellar/qt5/5.5.0/plugins /usr/local/plugins
endif
ifeq ($(OSOK),0)
$(error Could not find proper OS, please edit the Makefile: OS=$(OS))
endif

user:
	@echo create wireshark group, allow raw network, and add current user
	sudo addgroup -system wireshark
	sudo touch /usr/local/bin/dumpcap
	sudo chown root:wireshark /usr/local/bin/dumpcap
	sudo chmod 750 /usr/local/bin/dumpcap
	sudo setcap cap_net_raw,cap_net_admin=eip /usr/local/bin/dumpcap
	sudo usermod -a -G wireshark `whoami`

#
### THIS IS NOT CURRENTLY SUPPORTED
#testdata:
#	mkdir -p testdata
#	cd testdata; ../../build/bin/write_packets; \
#		for f in *.txt; do \
#			../wireshark/text2pcap -T 9695,9695 $$f tcp_$${f/.txt/.pcap}; \
#		done; \
#		for f in *.txt; do \
#			../wireshark/text2pcap -e 0x0801 $$f ether_$${f/.txt/.pcap}; \
#		done; 
#
#####

