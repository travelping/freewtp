# SmartCAPWAP -- An Open Source CAPWAP WTP / AC
#
# Copyright (C) 2012-2013 Massimo Vellucci <vemax78@gmail.com>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program (see the file COPYING included with this
# distribution); if not, write to the Free Software Foundation, Inc.,
# 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

AC_PREREQ(2.60)

m4_include(version.m4)
AC_INIT([PRODUCT_NAME], [PRODUCT_VERSION], [PRODUCT_BUGREPORT], [PRODUCT_TARNAME])
AC_CONFIG_AUX_DIR([.])
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE

# cross-compile macros
AC_CANONICAL_BUILD
AC_CANONICAL_HOST

#
AC_COPYRIGHT("SmartCapwap by Massimo Vellucci <vemax78@gmail.com>")
AC_REVISION($Revision: 1.0 $)

#
AC_ARG_ENABLE(
	[dtls],
	[AS_HELP_STRING([--disable-dtls], [disable DTLS support @<:@default=yes@:>@])],
	,
	[enable_dtls="yes"]
)

AC_ARG_ENABLE(
	[debug],
	[AS_HELP_STRING([--disable-debug], [disable debug support @<:@default=yes@:>@])],
	,
	[enable_debug="yes"]
)

AC_ARG_ENABLE(
	[logging],
	[AS_HELP_STRING([--disable-logging], [disable logging support @<:@default=yes@:>@])],
	,
	[enable_logging="yes"]
)

AC_ARG_ENABLE(
	[ac],
	[AS_HELP_STRING([--disable-ac], [disable ac support @<:@default=yes@:>@])],
	,
	[enable_ac="yes"]
)

AC_ARG_ENABLE(
	[wtp],
	[AS_HELP_STRING([--disable-wtp], [disable wtp support @<:@default=yes@:>@])],
	,
	[enable_wtp="yes"]
)

AC_ARG_WITH(
	[ssl-library],
	[AS_HELP_STRING([--with-ssl-library=library], [build with the given crypto library, TYPE=openssl|cyassl @<:@default=openssl@:>@])],
	[
	        case "${withval}" in
	                openssl|cyassl) ;;
	                *) AC_MSG_ERROR([bad value ${withval} for --with-crypto-library]) ;;
	        esac
	],
	[with_ssl_library="openssl"]
)

AC_ARG_WITH(
	[mem-check],
	[AS_HELP_STRING([--with-mem-check=TYPE], [build with debug memory checking, TYPE=no|internal|valgrind @<:@default=internal@:>@])],
	[
		case "${withval}" in
			valgrind|internal|no) ;;
			*) AC_MSG_ERROR([bad value ${withval} for --mem-check]) ;;
		esac
	],
	[with_mem_check="internal"]
)

# WTP drivers wifi binding 
AC_ARG_ENABLE(
	[wifi-drivers-nl80211],
	[AS_HELP_STRING([--disable-wifi-drivers-nl80211], [disable WTP support for nl80211 wifi binding @<:@default=yes@:>@])],
	,
	[enable_wifi_drivers_nl80211="yes"]
)

# specify output header file
AM_CONFIG_HEADER(build/config.h)

#
old_CFLAGS="${CFLAGS}"
AC_PROG_CC([gcc])
CFLAGS="${old_CFLAGS}"

#
AM_CONDITIONAL([DEBUG_BUILD], [test "$enable_debug" = yes]) 
if test "${enable_debug}" = "yes"; then
	CFLAGS="${CFLAGS} -DDEBUG -Wall -Werror -g -O0"
else
	CFLAGS="${CFLAGS} -O2"
	AC_DEFINE([DISABLE_LOGGING_DEBUG], [1], [Disable logging debug])
fi

#
AC_PROG_INSTALL
AC_USE_SYSTEM_EXTENSIONS

AC_LANG(C)

AC_HEADER_STDC

# Check LIBCONFIG library
AC_CHECK_HEADER([libconfig.h], [], [AC_MSG_ERROR(You need the libconfig headers)])
AC_CHECK_LIB([config], [config_init], [CONFIG_LIBS="-lconfig"], [AC_MSG_ERROR(You need the libconfig library)])

# Check PTHREAD library
AC_CHECK_HEADER([pthread.h], [], [AC_MSG_ERROR(You need the pthread headers)])
AC_CHECK_LIB([pthread], [pthread_create], [PTHREAD_LIBS="-lpthread"], [AC_MSG_ERROR(You need the pthread library)])

# Check nl80211
has_libnl_ver=0
PKG_CHECK_MODULES(
	[LIBNL],
	[libnl-3.0 >= 3.0 libnl-genl-3.0 >= 3.0], 
	[AC_DEFINE([HAVE_LIBNL30], [1], [Use libnl-3.0 library])],
	[PKG_CHECK_MODULES(
		[LIBNL],
		[libnl-2.0 >= 2.0],
		[AC_DEFINE([HAVE_LIBNL20], [1], [Use libnl-2.0 library])],
		[PKG_CHECK_MODULES(
			[LIBNL],
			[libnl-1],
			[AC_DEFINE([HAVE_LIBNL10], [1], [Use libnl-1.0 library])],
			[AC_MSG_ERROR(You need the libnl and libnl-genl)]
		)]
	)]
)

if test "${enable_wifi_drivers_nl80211}" = "yes"; then
	AC_CHECK_HEADERS([netlink/genl/genl.h netlink/genl/family.h netlink/genl/ctrl.h], [], [AC_MSG_ERROR(You need the netlink header)])
	AC_CHECK_HEADER([linux/nl80211.h], [], [AC_MSG_ERROR(You need the nl80211 header)])
	AC_DEFINE([ENABLE_WIFI_DRIVERS_NL80211], [1], [Enable WTP support for nl80211 wifi binding])
fi
AM_CONDITIONAL([BUILD_WTP_WIFI_DRIVERS_NL80211], [test "${enable_wifi_drivers_nl80211}" = "yes"])

# Check SSL library
if test "${with_ssl_library}" = "openssl"; then
	PKG_CHECK_MODULES(
		[OPENSSL_CRYPTO],
		[libcrypto >= 1.0.0],
		[have_openssl_crypto="yes"],
		[AC_CHECK_LIB(
			[crypto],
			[RSA_new],
			[
				have_openssl_crypto="yes"
				OPENSSL_CRYPTO_LIBS="-lcrypto"
			]
		)]
	)
	
	PKG_CHECK_MODULES(
		[OPENSSL_SSL],
		[libssl >= 1.0.0],
		[have_openssl_ssl="yes"],
		[AC_CHECK_LIB(
			[ssl],
			[SSL_CTX_new],
			[
				have_openssl_ssl="yes"
				OPENSSL_SSL_LIBS="-lssl"
			]
		)]
	)
	
	if test "${have_openssl_ssl}" = "yes"; then
		saved_CFLAGS="${CFLAGS}"
		saved_LIBS="${LIBS}"
		CFLAGS="${CFLAGS} ${OPENSSL_SSL_CFLAGS}"
		LIBS="${LIBS} ${OPENSSL_SSL_LIBS}"
		have_openssl_engine="yes"
		AC_CHECK_FUNC([SSL_CTX_set_cookie_generate_cb], , [AC_MSG_ERROR([${with_ssl_library} SSL_CTX_set_cookie_generate_cb function is required but missing])])
		AC_CHECK_FUNC([SSL_CTX_set_cookie_verify_cb], , [AC_MSG_ERROR([${with_ssl_library} SSL_CTX_set_cookie_verify_cb function is required but missing])])
		CFLAGS="${saved_CFLAGS}"
		LIBS="${saved_LIBS}"
	fi
elif test "${with_ssl_library}" = "cyassl"; then
	AC_CHECK_HEADER([cyassl/ssl.h], [], [AC_MSG_ERROR(You need the cyassl headers)])
	AC_CHECK_HEADER([cyassl/openssl/ssl.h], [], [AC_MSG_ERROR(You need the cyassl opensslextra headers)])
	AC_CHECK_LIB([cyassl], [CyaSSL_Init], [], [AC_MSG_ERROR(You need the cyassl library)])
	have_cyassl_engine="yes"
	have_cyassl_ssl="yes"
fi

case "${with_ssl_library}" in
	openssl)
		have_crypto_engine="${have_openssl_engine}"
		have_crypto_crypto="${have_openssl_crypto}"
		have_crypto_ssl="${have_openssl_ssl}"
		SSL_CFLAGS="${OPENSSL_CRYPTO_CFLAGS} ${OPENSSL_SSL_CFLAGS}"
		SSL_LIBS="${OPENSSL_SSL_LIBS}"
		test "${have_crypto_engine}" = "yes" && AC_DEFINE([HAVE_OPENSSL_ENGINE], [1], [Use ssl library])
		;;
	cyassl)
		have_crypto_engine="${have_cyassl_engine}"
		have_crypto_crypto="${have_cyassl_ssl}"
		have_crypto_ssl="${have_cyassl_ssl}"
		SSL_CFLAGS=""
		SSL_LIBS="-lcyassl"
		test "${have_crypto_engine}" = "yes" && AC_DEFINE([HAVE_CYASSL_ENGINE], [1], [Use ssl library])
		;;
esac

if test "${enable_dtls}" = "yes"; then
	test "${have_crypto_engine}" != "yes" && AC_MSG_ERROR([${with_ssl_library} engine is required but missing])
	test "${have_crypto_ssl}" != "yes" && AC_MSG_ERROR([${with_ssl_library} ssl is required but missing])
	test "${have_crypto_crypto}" != "yes" && AC_MSG_ERROR([${with_ssl_library} crypto is required but missing])
	AC_DEFINE([ENABLE_DTLS], [1], [Enable DTLS])
fi

# Check UDPLite
AC_CHECK_HEADERS([netinet/udplite.h])

# Memory check
case "${with_mem_check}" in
	internal)
		LIBS="${LIBS} -rdynamic"
		AC_DEFINE([USE_INTERNAL_MEMCHECK], [1], [Use internal memory debugging])
		;;
	valgrind)
		AC_CHECK_HEADER(
			[valgrind/memcheck.h],
			[
				CFLAGS="${CFLAGS} -g -fno-inline"
				AC_DEFINE([USE_VALGRIND_MEMCHECK], [1], [Use valgrind memory debugging library])
			],
			[AC_MSG_ERROR([valgrind headers not found.])]
		)
		;;
esac

#
AM_CONDITIONAL([BUILD_AC], [test "${enable_ac}" = "yes"])
AM_CONDITIONAL([BUILD_WTP], [test "${enable_wtp}" = "yes"])

#
test "${enable_logging}" = "yes" && AC_DEFINE([ENABLE_LOGGING], [1], [Enable logging])

#
AM_CONDITIONAL([BUILD_DEBUG], [test "${enable_debug}" = "yes"])
AM_CONDITIONAL([DTLS_ENABLED], [test "${enable_dtls}" = "yes"])

#
AC_SUBST([SSL_CFLAGS])
AC_SUBST([SSL_LIBS])
AC_SUBST([CONFIG_LIBS])
AC_SUBST([PTHREAD_LIBS])

#
AC_CONFIG_FILES([
	Makefile
	build/Makefile
	build/ac/Makefile
	build/wtp/Makefile
])

AC_OUTPUT
