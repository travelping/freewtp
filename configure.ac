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

AC_PREREQ(2.63)

AC_INIT([SmartCAPWAP], [1.1.0], [https://github.com/travelping/smartcapwap], [smartcapwap])
AC_CONFIG_AUX_DIR([build])
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE([1.11 -Wall])
AC_USE_SYSTEM_EXTENSIONS

# cross-compile macros
AC_CANONICAL_BUILD
AC_CANONICAL_HOST

#
AC_COPYRIGHT("SmartCapwap by Massimo Vellucci <vemax78@gmail.com>")
AC_REVISION($Revision: 1.0 $)

#
AC_PROG_INSTALL
AC_LANG(C)
AC_HEADER_STDC

#
AC_ARG_ENABLE(
	[dtls],
	[AS_HELP_STRING([--disable-dtls], [disable DTLS support])],
	,
	[enable_dtls="yes"]
)

AC_ARG_ENABLE(
	[debug],
	[AS_HELP_STRING([--disable-debug], [disable debug support])],
	,
	[enable_debug="yes"]
)

AC_ARG_ENABLE(
	[logging],
	[AS_HELP_STRING([--disable-logging], [disable logging support])],
	,
	[enable_logging="yes"]
)

AC_ARG_ENABLE([ac],
	[AS_HELP_STRING([--enable-ac], [enable ac support])])

AC_ARG_ENABLE(
	[wtp],
	[AS_HELP_STRING([--disable-wtp], [disable wtp support])],
	,
	[enable_wtp="yes"]
)

AC_ARG_WITH(
	[mem-check],
	[AS_HELP_STRING([--with-mem-check=TYPE], [build with debug memory checking, TYPE=no|internal|valgrind])],
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
	[AS_HELP_STRING([--disable-wifi-drivers-nl80211], [disable WTP support for nl80211 wifi binding])],
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

	AC_CHECK_HEADERS([execinfo.h], [have_backtrace="yes"],[])
	if test "x${have_backtrace}" = "xyes"; then
		AC_DEFINE([USE_DEBUG_BACKTRACE], [1], [Use debug backtrace])
	fi
else
	CFLAGS="${CFLAGS} -O2"
	AC_DEFINE([DISABLE_LOGGING_DEBUG], [1], [Disable logging debug])
fi

# Check LIBCONFIG library
AC_CHECK_HEADER([libconfig.h], [], [AC_MSG_ERROR(You need the libconfig headers)])
AC_CHECK_LIB([config], [config_init], [CONFIG_LIBS="-lconfig"], [AC_MSG_ERROR(You need the libconfig library)])

# Check LIBCONFIG config_lookup_int() param type
LIBCONFIG_LOOKUP_INT_ARG=int
AC_MSG_CHECKING([what type of argument config_lookup_int() is expecting])

saved_CFLAGS="${CFLAGS}"
saved_LIBS="${LIBS}"
saved_LDFLAGS="${LDFLAGS}"

CFLAGS="$CFLAGS $LIBCONFIG_CFLAGS -Werror"
LIBS="$LIBS $CONFIG_LIBS"
LDFLAGS="$LDFLAGS $LIBCONFIG_LDFLAGS"

AC_COMPILE_IFELSE(
	[AC_LANG_PROGRAM(
		[
			#include <libconfig.h>
		],
		[
			int check;
			config_t config;
			(void)config_lookup_int(&config, "check", &check);
		]
	)],
	[
		AC_MSG_RESULT([int])
		LIBCONFIG_LOOKUP_INT_ARG=int
	],
	[AC_COMPILE_IFELSE(
		[AC_LANG_PROGRAM(
			[
				#include <libconfig.h>
			],
			[
				long check;
				config_t config;
				(void)config_lookup_int(&config, "check", &check);
			]
		)],
		[
			AC_MSG_RESULT([long])
			LIBCONFIG_LOOKUP_INT_ARG=long
		],
		[
			AC_MSG_RESULT([unknown])
			AC_MSG_ERROR([failed to determine config_lookup_int() argument type])
		]
	)]
)

CFLAGS="$saved_CFLAGS"
LIBS="$saved_LIBS"
LDFLAGS="$saved_LDFLAGS"

AC_DEFINE_UNQUOTED([LIBCONFIG_LOOKUP_INT_ARG], [$LIBCONFIG_LOOKUP_INT_ARG], [config_lookup_int() argument type])

# Check PTHREAD library
AC_CHECK_HEADER([pthread.h], [], [AC_MSG_ERROR(You need the pthread headers)])
AC_CHECK_LIB([pthread], [pthread_create], [PTHREAD_LIBS="-lpthread"], [AC_MSG_ERROR(You need the pthread library)])

# Check SSL library
PKG_CHECK_MODULES([WOLFSSL], [wolfssl >= 3.8.0], [have_wolfssl_ssl="yes"], [have_wolfssl_ssl="no"])

# Check JSON library
if test "${enable_ac}" = "yes"; then
	test "x${have_wolfssl_ssl}" != "xyes" && AC_MSG_ERROR(You need the wolfssl library)

	PKG_CHECK_MODULES(
		[LIBJSON],
		[json-c >= 0.11],
		[],
		[AC_MSG_ERROR(You need the libjson)]
	)

	# Check XML2 library
	PKG_CHECK_MODULES(
		[LIBXML2],
		[libxml-2.0 >= 2.6]
	)
fi

# Check Netlink library
PKG_CHECK_MODULES(
	[LIBNL3],
	[libnl-3.0 >= 3.1 libnl-genl-3.0 >= 3.1],
	[have_libnl3=yes],
	[PKG_CHECK_MODULES(
		[LIBNL],
		[libnl-1],
		[AC_DEFINE([HAVE_LIBNL_10], [1], [Use libnl-1.0 library])],
		[PKG_CHECK_MODULES(
			[LIBNL],
			[libnl-tiny],
			[AC_DEFINE([HAVE_LIBNL_TINY], [1], [Use libnl-tiny library])],
			[AC_MSG_ERROR(You need the libnl or libnl-tiny)]
		)]
	)]
)

if test "${have_libnl3}" = "yes"; then
	AC_DEFINE([HAVE_LIBNL_3], [1], [Use libnl-3.1+ library])
        CFLAGS="${CFLAGS}  ${LIBNL3_CFLAGS}"
        LIBS="${LIBS} ${LIBNL3_LIBS}"
fi

AC_CHECK_HEADERS([netlink/genl/genl.h netlink/genl/family.h netlink/genl/ctrl.h], [], [AC_MSG_ERROR(You need the netlink header)])
AC_CHECK_HEADER([linux/nl80211.h], [], [AC_MSG_ERROR(You need the nl80211 header)])

# Check nl80211
if test "${enable_wifi_drivers_nl80211}" = "yes"; then
	AC_DEFINE([ENABLE_WIFI_DRIVERS_NL80211], [1], [Enable WTP support for nl80211 wifi binding])
fi
AM_CONDITIONAL([BUILD_WTP_WIFI_DRIVERS_NL80211], [test "${enable_wifi_drivers_nl80211}" = "yes"])

if test "${enable_dtls}" = "yes"; then
	test "x${have_wolfssl_ssl}" != "xyes" && AC_MSG_ERROR(You need the wolfssl library)
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
