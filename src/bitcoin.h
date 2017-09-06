#ifndef BITCOIN_H
#define BITCOIN_H

#ifdef __cplusplus
#define EXTERNC extern "C"
#else
#define EXTERNC
#endif

typedef enum {
	BTC_XPUB,
	BTC_XPRV
} e_btc_xkeytype;

EXTERNC int bitcoin_get_xkey(const unsigned char *, unsigned, 
		char*, unsigned, e_btc_xkeytype);
EXTERNC int bitcoin_get_electrum_seed(const unsigned char *entropy, 
		unsigned entsize, char *rv, unsigned rvsize);
EXTERNC int bitcoin_get_electrum_1st(const unsigned char *entropy, 
		unsigned entsize, char *rv, unsigned rvsize);

#endif
