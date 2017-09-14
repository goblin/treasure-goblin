#! /bin/bash

SALT="salt"
PASSWORD="password"
EXTRA_CMDS=""

# echo -n salt | b2sum -l 256
HASHED_SALT="3aa394787f34eb230efca0f1e966703d685515731780d34f729eeafa375721f1"

# PBKDF2, 2048 rounds
EXPECTED_PBKDF2="8c8b751010ad92f1f54151386a4eb5247ab343ce88de79983d5e3e995b7f5ae458cb9a0fb44d2d1e4b7feeeb966f17061174a55019f29e3ca59cc88d42ade53f"

# opslimit = 32k, memlimit = 16 MiB
# TODO: verify with external source! (remember these use the $HASHED_SALT)
EXPECTED_SCRYPT="824f41b868f8f1f7c0cd7fc526c02a00e478a309b06856011eacb0ee3afd04033c4b8ab349c2489f22813dfc0de9169c6bd0b0c3be7b36f4beb1cba73a89c98f"

# echo -n password | ./argon2 $(echo 3aa394787f34eb230efca0f1e966703d685515731780d34f729eeafa375721f1 | xxd -r -ps) -t 3 -m 12 -p 4 -l 64
# WARNING: ensure that when changing password, the resulting salt
#   doesn't contain the 0-byte as argon2 cli won't handle that
EXPECTED_ARGON2="11eacdfd0a758f940b891b630b1a95e4de20ffb5a5c1baaf06307d79b2e19cec40cb1bcf8155fff6e187a136ba366bba530af7627f3d683d6742abfe1d41ad84"

# this is XOR of the 3 above
EXPECTED_ALL3="1f2ef9557220ec923e05359e47940ac040eb1f729d77953625c2f30ed363c20b244b0b737cda9a778879722121b06a2029aee2f1d8b4c0f57c6fa8d465658134"

# python2
#   from pyblake2 import blake2b
#   h = blake2b(key='1f2ef9557220ec923e05359e47940ac040eb1f729d77953625c2f30ed363c20b244b0b737cda9a778879722121b06a2029aee2f1d8b4c0f57c6fa8d465658134'.decode('hex'))
#   h.update(b'verification')
#   h2 = blake2b()
#   h2.update(h.digest())
#   h2.hexdigest()
EXPECTED_VERIFICATION="090ec8ec00cb456d9d46189b4ae7bc339e2b456f4dc198c6a6cad21bac78a65b1cc3940bda90ec5f910a33b6f3bc61f81ce5953aa6d9a977982ae10cbfee487f"

# same as above but with 'testacc/0' instead of 'verification'
EXPECTED_TESTACC="20777b3fe17f76b30709590b9fce2613528ab81fee874e020b9df69c74ace669a510263c7351ccf03a9fbc20af90e3936e2b20a2a4576c0d16b485864bfa6b3d"

# echo 090ec8ec  | xxd -r -ps | xxd -b
# first 11 bits: 00001001 000 = 72  -> 73rd  word in dict is animal
# next  11 bits: 01110110 010 = 946 -> 947th word in dict is iron
# next   3 bits: 001 = 1 -> red
# next   3 bits: 110 = 6 -> cyan
# echo -e "\x1b[31;1manimal \x1b[36;1miron\x1b[0m" | xxd -ps
EXPECTED_WORDS="1b5b33313b316d616e696d616c201b5b33363b316d69726f6e1b5b306d0a"

# bx hd-new $EXPECTED_VERIFICATION
EXPECTED_XPRV="xprv9s21ZrQH143K4WDK8aersZzi2ToeUkwuNX2MaY9YnMeznzMjrd9PpBpng3qZi817pz5MbEBuiGTqLjAKuy9wunU6mpcRznSWdXpA2FfRQFB"

# bx hd-to-public $EXPECTED_XPRV
EXPECTED_XPUB="xpub661MyMwAqRbcGzHnEcBsEhwSaVe8tDfkjjwxNvZALhByfngtQATeMz9GXJ1jb7PqC2fzCMKmVJU3pjLsnqWCBj12xxheu9A2VHAoZFk9nSZ"

SLASHES="acct/0/wallet/0"

# bx hd-new / hd-to-public as with EXPECTED_X{PRV,PUB}
# but entropy comes from something like this code...

# (up to and including `h = blake2b(...)` as with EXPECTED_VERIFICATION, then:
#   h.update(b'acct')
#   acct = blake2b(data=h.digest()).digest()
#   zero1 = blake2b(data= blake2b(key=acct, data=b'0').digest()).digest()
#   wallet = blake2b(data= blake2b(key=zero1, data=b'wallet').digest()).digest()
#   zero2 = blake2b(data= blake2b(key=wallet, data=b'0').digest())
#   zero2.hexdigest()

# this gives: 797888d96ae093109dc591ed0596b812e4d95f37b56fb7e0e2cdf9faec962f0761970fdc1e81048490ce25b7ea146366c0713e343a03408484ce7ad9c7621458
EXPECTED_XPRV_SLASHES="xprv9s21ZrQH143K3LMYD1kikkrNE1JrvqR2RvRZg8mrDeUku6Q1BvrkBRPpeSKeN3vodbPTmFnzzfyyV8Vqd8w6QbkpaPCP4F3ajcNAj5hj71G"
EXPECTED_XPUB_SLASHES="xpub661MyMwAqRbcFpS1K3Hj7to6n39MLJ8so9MAUXBTmz1jmtj9jUAzjDiJVkE75371VYBWLtuGAAhf2pSuoRGMpfFJD6uicjap3Z44eKEuDox"

# echo $EXPECTED_TESTACC | head -c 32 | bx mnemonic-new | tr -d '\n' | electrumize-seed 
EXPECTED_ESEED="call rookie soup seed wash flower bring clinic argue wrist maze child cream"

# echo -n $EXPECTED_ESEED | pbkdf2 electrum | bx hd-new | bx hd-public -i 0 | bx hd-public -i 0 | bx hd-to-ec | bx ec-to-address
EXPECTED_E1ST="1FGcV1Y4ucA2pAhZzD1CshvAoERkQSG6C4"

# echo -n $EXPECTED_ESEED | pbkdf2 electrum | bx hd-new
EXPECTED_EXPRV="xprv9s21ZrQH143K2qHySge2WW3jV6c7qJLyZ5PgHmfWTnCEHtdCeirJ82JUqeG4EfkLMZTxg5sDk2nWTupwrGTSSgchEPVM2uK8X9rbN2VaPrq"

# echo $EXPECTED_EXPRV | bx hd-to-public
EXPECTED_EXPUB="xpub661MyMwAqRbcFKNSYiB2sdzU38ScEm4pvJKH6A5827jDAgxMCGAYfpcxguazpaJaoJyurXJLpCKXfQ48Lr3jjPDaUGEM1PhrYeJ1Zoub7Dn"

function run_tg() {
	CMDS="$RUN_TG_CMDS"
	if [ "x$CMDS" == "x" ]
	then
		CMDS="$SALT\n$PASSWORD\n$EXTRA_CMDS"
	fi
	echo -e "$CMDS" | 
		../src/treasure_goblin --debug $@
}

function gethead() {
	header="$1"
	shift
	run_tg $@ |
		grep "^$header:" |
		sed -e 's/^.*: //'
}

function get_master_entropy() {
	gethead "master entropy" $@
}

function get_verification_data() {
	gethead "verification data" $@
}

function get_verification_words() {
	gethead "Your verification words are" $@
}

# what, expected, computed
function test_equal() {
	if [ "$2" != "$3" ]
	then
		echo -e "$1 \x1b[31;1mmismatch!\x1b[0m"
		echo "  " exp: "$2"
		echo "  " got: "$3"
		echo -e "\x1b[0m"
		exit 1
	else
		echo -e "$1 \x1b[32;1mok\x1b[0m"
	fi
}

test_equal pbkdf2 "$EXPECTED_PBKDF2" \
	$(get_master_entropy --pbkdf2-iters=2048 --scrypt-opslimit=0 \
		--argon2-iters=0)

test_equal scrypt "$EXPECTED_SCRYPT" \
	$(get_master_entropy --pbkdf2-iters=0 --scrypt-opslimit=32768 \
		--scrypt-memlimit=16 --argon2-iters=0)

test_equal argon2 "$EXPECTED_ARGON2" \
	$(get_master_entropy --pbkdf2-iters=0 --scrypt-opslimit=0 \
		--argon2-iters=3 --argon2-parallel=4 --argon2-mem=4)

STD_ARGS="--pbkdf2-iters=2048 
		--scrypt-opslimit=32768 --scrypt-memlimit=16 
		--argon2-iters=3 --argon2-parallel=4 --argon2-mem=4"

test_equal all3 "$EXPECTED_ALL3" \
	$(get_master_entropy $STD_ARGS)

test_equal verification "$EXPECTED_VERIFICATION" \
	$(get_verification_data $STD_ARGS)

test_equal words "$EXPECTED_WORDS" \
	$(get_verification_words $STD_ARGS | xxd -ps)

EXTRA_CMDS='xprv verification\n'
test_equal xprv "$EXPECTED_XPRV" \
	$(gethead "xprv verification" $STD_ARGS)

EXTRA_CMDS='xpub verification\n'
test_equal xpub "$EXPECTED_XPUB" \
	$(gethead "xpub verification" $STD_ARGS)

EXTRA_CMDS="xprv $SLASHES\\n"
test_equal xprv_slashes "$EXPECTED_XPRV_SLASHES" \
	$(gethead "xprv $SLASHES" $STD_ARGS)

EXTRA_CMDS="xpub $SLASHES\\n"
test_equal xpub_slashes "$EXPECTED_XPUB_SLASHES" \
	$(gethead "xpub $SLASHES" $STD_ARGS)

RUN_TG_CMDS="\n"
test_equal master-entropy "$EXPECTED_VERIFICATION" \
	$(get_verification_data --master-entropy=$EXPECTED_ALL3)

RUN_TG_CMDS="$EXPECTED_ALL3\n"
test_equal master-entropy-stdin "$EXPECTED_VERIFICATION" \
	$(get_verification_data --master-entropy=-)

# need the 'for' so it prints the command so gethead can get it
RUN_TG_CMDS="for xx 0 1: h .\n"
test_equal dot-addr "$EXPECTED_ALL3" \
	$(gethead "h ." --master-entropy="$EXPECTED_ALL3")

RUN_TG_CMDS=""

EXTRA_CMDS='for xx 0 1: h testacc/xx\n'
test_equal h "$EXPECTED_TESTACC" \
	$(gethead "h testacc/0" $STD_ARGS)

EXTRA_CMDS='for xx 0 1: h32 testacc/xx\n'
test_equal h32 $(echo "$EXPECTED_TESTACC" | head -c 64) \
	$(gethead "h32 testacc/0" $STD_ARGS)

EXTRA_CMDS='for xx 0 1: h16 testacc/xx\n'
test_equal h16 $(echo "$EXPECTED_TESTACC" | head -c 32) \
	$(gethead "h16 testacc/0" $STD_ARGS)

EXTRA_CMDS='for xx 0 1: eseed testacc/xx\n'
test_equal eseed "$EXPECTED_ESEED" \
	"$(gethead "eseed testacc/0" $STD_ARGS)"

EXTRA_CMDS='for xx 0 1: e1st testacc/xx\n'
test_equal e1st "$EXPECTED_E1ST" \
	$(gethead "e1st testacc/0" $STD_ARGS)

EXTRA_CMDS='for xx 0 1: exprv testacc/xx\n'
test_equal exprv "$EXPECTED_EXPRV" \
	$(gethead "exprv testacc/0" $STD_ARGS)

EXTRA_CMDS='for xx 0 1: expub testacc/xx\n'
test_equal expub "$EXPECTED_EXPUB" \
	$(gethead "expub testacc/0" $STD_ARGS)
