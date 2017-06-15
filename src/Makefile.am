AUTOMAKE_OPTIONS = subdir-objects

wordlist.h: ../wordlists/$(WORDLIST_LANG).txt
	sed -e 's/^/"/' -e 's/$$/",/' ../wordlists/$(WORDLIST_LANG).txt > wordlist.h

BUILT_SOURCES = wordlist.h
CLEANFILES = wordlist.h

if M_HAVE_LIBBITCOIN
LIBBTC_EXTRA = bitcoin.h bitcoin.cc
else
LIBBTC_EXTRA = 
endif

bin_PROGRAMS = treasure_goblin
treasure_goblin_SOURCES = treasure_goblin.c \
						  ../linenoise/linenoise.c \
						  defaults.h colors.h wordlist.h \
						  $(LIBBTC_EXTRA)
treasure_goblin_LDFLAGS = $(OPENSSL_LIBS) $(SODIUM_LIBS) \
						  $(ARGON2_LIBS) $(LIBBITCOIN_LIBS)
treasure_goblin_CPPFLAGS = $(OPENSSL_CFLAGS) $(SODIUM_CFLAGS) \
						   $(ARGON2_CFLAGS) $(LIBBITCOIN_CFLAGS) \
						   -I../linenoise  -I..
