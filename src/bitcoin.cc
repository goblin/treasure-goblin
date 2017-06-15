#include <string.h>
#include <vector>
#include <string>
#include <bitcoin/bitcoin.hpp>

#include "bitcoin.h"

int bitcoin_get_xkey(const unsigned char *entropy, unsigned entsize, 
		unsigned char *rv, unsigned rvsize, e_btc_xkeytype keytype)
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

	memcpy(rv, str.c_str(), str.size() + 1);
	return 1;
}
