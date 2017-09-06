#include <string.h>
#include <vector>
#include <string>
#include <bitcoin/bitcoin.hpp>
#include <openssl/hmac.h>
#include <openssl/evp.h>

#include "bitcoin.h"

int bitcoin_get_xkey(const unsigned char *entropy, unsigned entsize, 
		char *rv, unsigned rvsize, e_btc_xkeytype keytype)
{
	// TODO FIXME: add mlock()ing if needed
	std::vector<uint8_t> entr(entropy, entropy + entsize);
	libbitcoin::wallet::hd_private wal(entr);

	std::string str;
	if(keytype == BTC_XPRV)
		str = wal.encoded();
	else if(keytype == BTC_XPUB)
		str = wal.to_public().encoded();
	else
		return 0;

	if(rvsize < str.size() + 1)
		return 0;

	strcpy(rv, str.c_str());
	return 1;
}

static int eseed_test(std::string seed)
{
	return HMAC(EVP_sha512(), "Seed version", 12, 
			(const unsigned char*)seed.c_str(), seed.size(), 
			NULL, NULL)[0] == 1;
}

static int bitcoin_get_electrum_seed_str(const unsigned char *entropy, 
		unsigned entsize, std::string &rv)
{
	std::vector<uint8_t> entr(entropy, entropy + entsize);
	auto plain_seed = libbitcoin::join(
			libbitcoin::wallet::create_mnemonic(entr)
		);
	std::string eseed = plain_seed;

	if(eseed_test(eseed)) {
		rv = eseed;
		return 1;
	} else {
		for(int i = 0; i < 2048; i++) {
			eseed = plain_seed + " " + libbitcoin::wallet::language::en[i];
			if(eseed_test(eseed)) {
				rv = eseed;
				return 1;
			}
		}
	}
		
	return 0;
}

int bitcoin_get_electrum_seed(const unsigned char *entropy, unsigned entsize,
		char *rv, unsigned rvsize)
{
	std::string eseed;
	if(!bitcoin_get_electrum_seed_str(entropy, entsize, eseed))
		return 0;

	if(rvsize < eseed.size() + 1)
		return 0;

	strcpy(rv, eseed.c_str());
	return 1;
}

// echo -n $EXPECTED_ESEED | pbkdf2 electrum | bx hd-new | bx hd-public -i 0 | bx hd-public -i 0 | bx hd-to-ec | bx ec-to-address
int bitcoin_get_electrum_1st(const unsigned char *entropy, unsigned entsize,
		char *rv, unsigned rvsize)
{
	std::string eseed;
	if(!bitcoin_get_electrum_seed_str(entropy, entsize, eseed))
		return 0;

	const int entrlen = 64;
	unsigned char entrbuf[entrlen];

	int pbkdf_res = PKCS5_PBKDF2_HMAC(eseed.c_str(), eseed.size(),
			(const unsigned char*)"electrum", 8, 
			2048, EVP_sha512(), entrlen, entrbuf);
	if(pbkdf_res != 1)
		return 0;

	std::vector<uint8_t> entr(entrbuf, entrbuf + entrlen);
	auto ec_point = libbitcoin::wallet::hd_private(entr). // hd-new
		derive_public(0). // hd-public -i 0
		derive_public(0). // hd-public -i 0
		point(); // hd-to-ec

	libbitcoin::wallet::ec_public publ(ec_point);
	auto addr = publ.to_payment_address().encoded();

	if(rvsize < addr.size() + 1)
		return 0;

	strcpy(rv, addr.c_str());

	return 1;
}
