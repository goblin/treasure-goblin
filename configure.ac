AC_INIT([treasure-goblin], [0.1], [goblin@example.com])
AM_INIT_AUTOMAKE([foreign -Wall -Werror])
: ${CFLAGS="-O0 -ggdb -Wall -Wextra"}
: ${CXXFLAGS="-O0 -ggdb -Wall"} # libbitcoin and extra warnings are meh
AC_PROG_CC_STDC
AC_PROG_CXX
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([Makefile src/Makefile])

PKG_CHECK_MODULES([OPENSSL], [openssl])
PKG_CHECK_MODULES([SODIUM], [libsodium >= 1.0.9])
PKG_CHECK_MODULES([ARGON2], [libargon2])
PKG_CHECK_MODULES([LIBBITCOIN], [libbitcoin], [
	AC_DEFINE([HAVE_LIBBITCOIN], [1], [libbitcoin is present])
	echo using libbitcoin
	am_libbtc=true
], [
	echo
	echo Building without libbitcoin
	echo
	am_libbtc=false
])

AM_CONDITIONAL([M_HAVE_LIBBITCOIN], [test x$am_libbtc = xtrue ])

AC_SUBST(WORDLIST_LANG, [english])
AC_ARG_VAR(WORDLIST_LANG, [Wordlist language])

AC_OUTPUT
