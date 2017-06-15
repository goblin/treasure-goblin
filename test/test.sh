#! /bin/bash

SALT="salt"
PASSWORD="password"
EXTRA_CMDS=""

# b2sum -l 256
HASHED_SALT="3aa394787f34eb230efca0f1e966703d685515731780d34f729eeafa375721f1"

# PBKDF2, 2048 rounds
EXPECTED_PBKDF2="8c8b751010ad92f1f54151386a4eb5247ab343ce88de79983d5e3e995b7f5ae458cb9a0fb44d2d1e4b7feeeb966f17061174a55019f29e3ca59cc88d42ade53f"

# opslimit = 32k, memlimit = 16 MiB
# TODO: verify with external source! (remember these use the $HASHED_SALT)
EXPECTED_SCRYPT="824f41b868f8f1f7c0cd7fc526c02a00e478a309b06856011eacb0ee3afd04033c4b8ab349c2489f22813dfc0de9169c6bd0b0c3be7b36f4beb1cba73a89c98f"

# echo -n password | ./argon2 $(echo 3aa394787f34eb230efca0f1e966703d685515731780d34f729eeafa375721f1 | xxd -r -ps) -t 3 -m 12 -p 4 -l 64
EXPECTED_ARGON2="11eacdfd0a758f940b891b630b1a95e4de20ffb5a5c1baaf06307d79b2e19cec40cb1bcf8155fff6e187a136ba366bba530af7627f3d683d6742abfe1d41ad84"

# this is XOR of the 3 above
EXPECTED_ALL3="1f2ef9557220ec923e05359e47940ac040eb1f729d77953625c2f30ed363c20b244b0b737cda9a778879722121b06a2029aee2f1d8b4c0f57c6fa8d465658134"

# python2
#   from pyblake2 import blake2b
#   h = blake2b(key='1f2ef9557220ec923e05359e47940ac040eb1f729d77953625c2f30ed363c20b244b0b737cda9a778879722121b06a2029aee2f1d8b4c0f57c6fa8d465658134'.decode('hex'))
#   h.update(b'verification')
#   h.hexdigest()
EXPECTED_VERIFICATION="9216425d7c4d25d91d1fa93399b26bea6726f07528c0c6b116ae8f4aed52fc9d4ebd688bedef7bc32767b599dcf25f16d47622e00eaa4b8d6289475ec797592c"

# echo -e "\x1b[34;1mmust \x1b[35;1mrare\x1b[0m" | xxd -ps
EXPECTED_WORDS="1b5b33343b316d6d757374201b5b33353b316d726172651b5b306d0a"

# bx hd-new $EXPECTED_VERIFICATION
EXPECTED_XPRV="xprv9s21ZrQH143K3SqmpBASiQ9sEgFZTNjiGfcSvppKHoowEJM1f4JYwUkXknmSLf8qLPxenAxr8GYPPepp4bWCRwieG8bpAbqCJfoDEhML2hg"

# bx hd-to-public $EXPECTED_XPRV
EXPECTED_XPUB="xpub661MyMwAqRbcFvvEvChT5Y6bni63rqTZdtY3jDDvr9Lv76gACbcoVH51c632JanFZjULtQMigqeyggbN9Xd5WTMrqgdLPGNVE9cKGFi9wgA"

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
		echo "  " got: "$2"
		echo "  " exp: "$3"
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
