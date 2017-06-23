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

function run_tg() {
	echo -e "$SALT\n$PASSWORD\n$EXTRA_CMDS" | 
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

test_equal all3 "$EXPECTED_ALL3" \
	$(get_master_entropy --pbkdf2-iters=2048 \
		--scrypt-opslimit=32768 --scrypt-memlimit=16 \
		--argon2-iters=3 --argon2-parallel=4 --argon2-mem=4)

test_equal verification "$EXPECTED_VERIFICATION" \
	$(get_verification_data --pbkdf2-iters=2048 \
		--scrypt-opslimit=32768 --scrypt-memlimit=16 \
		--argon2-iters=3 --argon2-parallel=4 --argon2-mem=4)

test_equal words "$EXPECTED_WORDS" \
	$(get_verification_words --pbkdf2-iters=2048 \
		--scrypt-opslimit=32768 --scrypt-memlimit=16 \
		--argon2-iters=3 --argon2-parallel=4 --argon2-mem=4 | xxd -ps)

EXTRA_CMDS='xprv verification\n'
test_equal xprv "$EXPECTED_XPRV" \
	$(gethead "xprv verification" \
		--pbkdf2-iters=2048 --scrypt-opslimit=32768 --scrypt-memlimit=16 \
		--argon2-iters=3 --argon2-parallel=4 --argon2-mem=4)

EXTRA_CMDS='xpub verification\n'
test_equal xpub "$EXPECTED_XPUB" \
	$(gethead "xpub verification" \
		--pbkdf2-iters=2048 --scrypt-opslimit=32768 --scrypt-memlimit=16 \
		--argon2-iters=3 --argon2-parallel=4 --argon2-mem=4)
