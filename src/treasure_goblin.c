#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <termios.h>
#include <unistd.h>

#include <sodium.h>
#include <openssl/evp.h>
#include <argon2.h>

#include "linenoise.h"

#include "config.h"
#include "defaults.h"
#include "colors.h"

#ifdef HAVE_LIBBITCOIN
#include "bitcoin.h"
#endif

struct tg_opts {
	long pbkdf2_iters;
	long scrypt_opslimit;
	long scrypt_memlimit; // in MiB
	long argon2_parallel;
	long argon2_iters;
	long argon2_mem; // in MiB
	char *master_entropy;
};

// globals
int debug_mode = 0;
int readable = 0;

static void print_version()
{
	printf("%s (libbitcoin: %s)\n", PACKAGE_STRING, 
#ifdef HAVE_LIBBITCOIN
			"yes"
#else
			"no"
#endif // HAVE_LIBBITCOIN
	);
}

static void print_usage()
{
	print_version();
	printf("switches: \n"
		"\t--help                      -h          	this help\n"
		"\t--version                   -v           version info\n"
		"\t--pbkdf2-iters=<num>        -k <num>    	PBKDF2 iterations (def: %d)\n"
		"\t--scrypt-opslimit=<num>     -s <num>    	scrypt opslimit (def: %llu)\n"
		"\t--scrypt-memlimit=<MiB>     -S <MiB>    	scrypt memlimit (def: %llu)\n"
		"\t--argon2-parallel=<threads> -p <threads>	Argon2 parallelization (def: %d)\n"
		"\t--argon2-iters=<num>        -i <num>    	Argon2 iterations (def: %d)\n"
		"\t--argon2-mem=<MiB>          -m <MiB>    	Argon2 memory (def: %d)\n"
		"\t--master-entropy=<hexdata>  -e <hexdata>	Set master entropy manually. Ignores pbkdf2/scrypt/argon2 switches. '-' means read from stdin.\n\n"
		"\t--readable                  -r        	Start in readable mode\n",
		DEFAULT_PBKDF2_ITERS,
		DEFAULT_SCRYPT_OPSLIMIT,
		DEFAULT_SCRYPT_MEMLIMIT,
		DEFAULT_ARGON2_PARALLEL,
		DEFAULT_ARGON2_ITERS,
		DEFAULT_ARGON2_MEM
	);
	exit(1);
}

static struct tg_opts parse_opts(int argc, char **argv)
{
	struct tg_opts rv = {
		DEFAULT_PBKDF2_ITERS,
		DEFAULT_SCRYPT_OPSLIMIT,
		DEFAULT_SCRYPT_MEMLIMIT,
		DEFAULT_ARGON2_PARALLEL,
		DEFAULT_ARGON2_ITERS,
		DEFAULT_ARGON2_MEM,
		NULL
	};
	struct option opts[] = {
		{"help", no_argument, NULL, 'h'},
		{"version", no_argument, NULL, 'v'},
		{"pbkdf2-iters", required_argument, NULL, 'k'},
		{"scrypt-opslimit", required_argument, NULL, 's'},
		{"scrypt-memlimit", required_argument, NULL, 'S'},
		{"argon2-parallel", required_argument, NULL, 'p'},
		{"argon2-iters", required_argument, NULL, 'i'},
		{"argon2-mem", required_argument, NULL, 'm'},
		{"master-entropy", required_argument, NULL, 'e'},

		{"readable", no_argument, NULL, 'r'},
		{"debug", no_argument, NULL, 'D'},

		{0, 0, NULL, 0}
	};

	while(1) {
		int c = getopt_long(argc, argv, "hvk:s:S:p:i:m:e:rD", opts, NULL);
		if(c == -1)
			break;
		switch(c) {
			case 'k':
				rv.pbkdf2_iters = atol(optarg);
				break;
			case 's':
				rv.scrypt_opslimit = atol(optarg);
				break;
			case 'S':
				rv.scrypt_memlimit = atol(optarg);
				break;
			case 'p':
				rv.argon2_parallel = atol(optarg);
				break;
			case 'i':
				rv.argon2_iters = atol(optarg);
				break;
			case 'm':
				rv.argon2_mem = atol(optarg);
				break;
			case 'D':
				debug_mode = 1;
				break;
			case 'h':
				print_usage();
				break;
			case 'v':
				print_version();
				exit(0);
				break;
			case 'e':
				rv.master_entropy = optarg;
				break;
			case 'r':
				readable = 1;
				break;
			default:
				printf("broken opts? %d\n", c);
		}
	}

	return rv;
}

static int switch_echo(int flag)
{
    struct termios tio;
	
    if (tcgetattr(STDIN_FILENO, &tio) == -1) {
		return debug_mode;
	}

	if(flag) {
		// enable echo
		tio.c_lflag |= ECHO;
	} else {
		// disable echo
		tio.c_lflag &= ~ECHO;
	}

    if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &tio) < 0) {
		return debug_mode;
	}

	return 1;
}

// remember to sodium_free()!
static char *get_password()
{
	char *rv;
	int i;
	rv = sodium_malloc(MAX_MASTER_PASSWD_LEN);
	if(!rv) {
		printf("sodium_malloc() failed\n");
		return NULL;
	}

	if(!switch_echo(0)) {
		sodium_free(rv);
		printf("unable to switch echo off?\n");
		return NULL;
	}

	for(i = 0; i < MAX_MASTER_PASSWD_LEN; i++) {
		rv[i] = getchar();
		if(rv[i] == EOF || rv[i] == '\n' || rv[i] == '\r') {
			rv[i] = 0;
			break;
		}
	}

	switch_echo(1);

	if(i >= MAX_MASTER_PASSWD_LEN || rv[i] != 0) {
		sodium_free(rv);
		printf("sorry, too long\n");
		return NULL;
	}

	return rv;
}

static void xor(unsigned char *dst, unsigned char *src, size_t len)
{
	for(size_t i = 0; i < len; i++) {
		dst[i] = dst[i] ^ src[i];
	}
}

static unsigned char *passwd_to_entropy(const struct tg_opts *tgo, 
		const char *salt, const char *passwd)
{
	unsigned char *tmp = sodium_malloc(MASTER_ENTROPY_SIZE);
	unsigned char *rv = sodium_malloc(MASTER_ENTROPY_SIZE);
	static const int hashlen = crypto_pwhash_scryptsalsa208sha256_SALTBYTES;
	unsigned char *hashed_salt = malloc(hashlen);
	int result;

	if(!tmp || !rv || !hashed_salt) {
		printf("sodium_malloc() failed\n");
		return NULL;
	}
	
	memset(rv, 0, MASTER_ENTROPY_SIZE);
	memset(tmp, 0, MASTER_ENTROPY_SIZE);

	crypto_generichash(hashed_salt, hashlen, (unsigned char*)salt, 
			strlen(salt), NULL, 0);

	if(tgo->pbkdf2_iters > 0) {
		printf("doing PBKDF2...\n");
		result = PKCS5_PBKDF2_HMAC(passwd, strlen(passwd),
				hashed_salt, hashlen, tgo->pbkdf2_iters, 
				PBKDF2_DIGEST_ALGO(), MASTER_ENTROPY_SIZE, rv);
		if(result != 1) {
			printf("pbkdf2 failed\n");
			sodium_free(rv);
			rv = NULL;
			goto done;
		}
	}

	if(tgo->scrypt_opslimit > 0) {
		printf("doing scrypt...\n");
		result = crypto_pwhash_scryptsalsa208sha256(tmp, MASTER_ENTROPY_SIZE,
				passwd, strlen(passwd), hashed_salt, tgo->scrypt_opslimit,
				tgo->scrypt_memlimit * 1024LU * 1024LU);
		if(result != 0) {
			printf("scrypt failed\n");
			sodium_free(rv);
			rv = NULL;
			goto done;
		}
	}

	xor(rv, tmp, MASTER_ENTROPY_SIZE);
	memset(tmp, 0, MASTER_ENTROPY_SIZE);

	if(tgo->argon2_iters > 0) {
		printf("doing argon2...\n");
		result = argon2i_hash_raw(tgo->argon2_iters, tgo->argon2_mem * 1024LU,
				tgo->argon2_parallel, passwd, strlen(passwd),
				hashed_salt, hashlen, tmp, MASTER_ENTROPY_SIZE);
		if(result != ARGON2_OK) {
			printf("argon2 failed\n");
			sodium_free(rv);
			rv = NULL;
			goto done;
		}
	}

	xor(rv, tmp, MASTER_ENTROPY_SIZE);

done:
	sodium_free(tmp);
	free(hashed_salt);

	return rv;
}

// remember to sodium_free!
// `keyname` is not considered a cryptographic string, it will be
//    a simple identifier like 'verification' or 'wallet/0'.
//    slashes are considered as separators.
//    dot means "use master entropy directly".
static unsigned char *derive_key_name(const unsigned char *entropy, 
		const int entsize, const char *keyname)
{
	unsigned char *rv = sodium_malloc(DERIVED_ENTROPY_SIZE);
	unsigned char *first = sodium_malloc(DERIVED_ENTROPY_SIZE);
	char *subkey = strdup(keyname);
	char *nextkey;

	if(!rv || !first || !subkey) {
		printf("memory allocation failed\n");
		goto failure;
	}

	if(strcmp(keyname, ".") == 0) {
		if(DERIVED_ENTROPY_SIZE != MASTER_ENTROPY_SIZE) {
			printf("assertion failed in derive_key_name\n");
			goto failure;
		}
		memcpy(rv, entropy, DERIVED_ENTROPY_SIZE);
		sodium_free(first);
		goto done;
	}

	if((nextkey = strchr(subkey, '/'))) {
		*nextkey = 0;
		nextkey++;
	}

	crypto_generichash(first, DERIVED_ENTROPY_SIZE, (unsigned char*)subkey, 
			strlen(subkey), entropy, entsize);
	crypto_generichash(rv, DERIVED_ENTROPY_SIZE, first, DERIVED_ENTROPY_SIZE,
			NULL, 0);

	sodium_free(first);

	if(nextkey) {
		unsigned char *rrv = derive_key_name(rv, DERIVED_ENTROPY_SIZE, nextkey);
		sodium_free(rv);
		rv = rrv;
	}

done:
	free(subkey);
	return rv;

failure:
	sodium_free(rv);
	sodium_free(first);
	free(subkey);
	return NULL;
}

static unsigned int get_bits(const unsigned char *data,
		const int start, const int len)
{
	unsigned int rv = 0;
	
	for(int i = 0; i < len; i++) {
		int byte_idx = (start + i) / 8;
		int bit_idx = 7 - (start + i) % 8;
		int curval = (data[byte_idx] & (1 << bit_idx)) >> bit_idx;

		rv |= curval << (len - i - 1); 
	}

	return rv;
}

static void pretty_print(const unsigned char *data, const int len,
		void (*printer)(const unsigned char*), int chunksize)
{
	for(int i = 0; i < len; i++) {
		if(readable) {
			int x = i % (chunksize * 4);
			if(i % chunksize == 0 && i > 0)
				printf(" ");
			if(i % chunksize == 0) {
				if(x == 0 || x == chunksize * 2)
					printf(C_RESET);
				if(x == chunksize)
					printf(C_WHITE);
				if(x == chunksize * 3)
					printf(C_GRAY);
			}
			if(i % (chunksize * 8) == 0 && i > 0)
				printf("\n");
		}
		printer(&data[i]);
	}
	if(readable)
		printf(C_RESET);
	printf("\n");
}

static void hex_printer(const unsigned char *what)
{
	printf("%02x", *what);
}

static void char_printer(const unsigned char *what)
{
	printf("%c", *what);
}

static void print_hex(const unsigned char *data, const int len)
{
	pretty_print(data, len, hex_printer, 2);
}

static void print_str(const char *data)
{
	pretty_print((const unsigned char*)data, strlen(data), char_printer, 4);
}

static void print_verification(const unsigned char *entropy, const int entsize, 
	const char **dict)
{
	unsigned char *data = derive_key_name(entropy, entsize,
			VERIFICATION_KEY_NAME);
	char *colors[] = {
		C_GRAY,
		C_RED,
		C_GREEN,
		C_YELLOW,
		C_BLUE,
		C_MAGENTA,
		C_CYAN,
		C_WHITE
	};
	unsigned int idx1, idx2, col1, col2;

	if(!data) {
		printf("computing verification code failed\n");
		return;
	}

	idx1 = get_bits(data, 0, WORDLIST_BITS);
	idx2 = get_bits(data, WORDLIST_BITS, WORDLIST_BITS);
	col1 = get_bits(data, WORDLIST_BITS * 2, 3);
	col2 = get_bits(data, WORDLIST_BITS * 2 + 3, 3);

	if(debug_mode) {
		printf("verification data: "); 
		print_hex(data, DERIVED_ENTROPY_SIZE);
	}

	sodium_free(data);

	printf("\nYour verification words are: %s%s %s%s" C_RESET "\n\n",
			colors[col1], dict[idx1],
			colors[col2], dict[idx2]);
}

static void print_help()
{
	printf("\n"
			"help            Show command help\n"
			"exit, quit      Exit program\n"
			"h <key>         Print hex data for <key>\n"
			"h32 <key>       as above but truncate to 256 bits\n"
			"h16 <key>       as above but truncate to 128 bits\n"
			"r               Toggle readable output\n"
			"for <var> <from> <to>: <cmd>\n"
			"                Iterate <var> on the range [<from>, <to>) and execute\n"
			"                <cmd> substituting <var> for each integer value\n"
#ifdef HAVE_LIBBITCOIN
		  "\nxprv <key>    Print HD xprv key for <key>\n"
			"xpub <key>    Print HD xpub key for <key>\n"
			"eseed <key>   Print Electrum seed for <key>\n"
			"e1st <key>    Print 1st bitcoin address used by Electrum from above seed\n"
			"exprv <key>   Print the master private key used by Electrum from eseed\n"
			"expub <key>   Print the master public key used by Electrum from eseed\n"
#endif // HAVE_LIBBITCOIN
			"\n" C_RED "THE '.' (dot) KEY IS DANGEROUS!" C_RESET " (it uses master entropy instead)\n");
}

#define RESULT_QUIT 0
#define RESULT_OK 1

#define CMD_ARGS const char *arg, const unsigned char *entropy, const int entsize, const char **dict
#define CMD_ARGNAMES arg, entropy, entsize, dict

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"

static int cmd_help(CMD_ARGS)
{
	print_help();
	return RESULT_OK;
}

static int cmd_quit(CMD_ARGS)
{
	return RESULT_QUIT;
}

static int cmd_hex(CMD_ARGS, int len)
{
	unsigned char *data;

	if(!arg) {
		printf("need a key\n");
		return RESULT_OK;
	}

	data = derive_key_name(entropy, entsize, arg);

	if(data)
		print_hex(data, len);
	else
		perror("derive_key_name failed");

	sodium_free(data);
	return RESULT_OK;
}

static int cmd_h(CMD_ARGS)
{
	return cmd_hex(CMD_ARGNAMES, DERIVED_ENTROPY_SIZE);
}

static int cmd_h32(CMD_ARGS)
{
	if(DERIVED_ENTROPY_SIZE <= 32) {
		perror("assertion failed in cmd_hex32");
		return RESULT_QUIT;
	}
	return cmd_hex(CMD_ARGNAMES, 32);
}

static int cmd_h16(CMD_ARGS)
{
	if(DERIVED_ENTROPY_SIZE <= 32) {
		perror("assertion failed in cmd_hex16");
		return RESULT_QUIT;
	}
	return cmd_hex(CMD_ARGNAMES, 16);
}

static int cmd_readable(CMD_ARGS)
{
	readable = !readable;
	printf("readable = %d\n", readable);
	return RESULT_OK;
}

static char* str_replace_all(const int maxlen, const char *haystack, 
		const char *needle, const int replacement)
{
	char *rv = malloc(maxlen);
	if(!rv)
		return NULL;

	char *c;
	if((c = strstr(haystack, needle))) {
		strncpy(rv, haystack, c-haystack);
		snprintf(rv + (c - haystack), 22, "%d", replacement);
		char *rest = str_replace_all(maxlen, c + strlen(needle), 
				needle, replacement);
		strcat(rv + strlen(rv), rest);
		free(rest);
	} else {
		strcpy(rv, haystack);
	}

	return rv;
}

static int process_cmd(const char *, const char *,
	const unsigned char *, const int, const char **);

static int cmd_for(CMD_ARGS)
{
	char *cmd = strstr(arg, ": ");
	if(!cmd) {
		printf("need a colon followed by a space\n");
		return RESULT_OK;
	}

	*cmd = 0;
	cmd += 2;

	char *first_space = strchr(arg, ' ');
	if(!first_space) {
		printf("need 2 spaces before the colon\n");
		return RESULT_OK;
	}
	const char *var = arg;
	*first_space = 0;
	first_space++;

	char *second_space = strchr(first_space, ' ');
	if(!second_space) {
		printf("need 2 spaces before the colon\n");
		return RESULT_OK;
	}
	*second_space = 0;
	second_space++;

	int from = atoi(first_space);
	int to = atoi(second_space);

	if(to <= from) {
		printf("to should be greater than from\n");
		return RESULT_OK;
	}

	if(to - from > 100000) {
		printf("max iterations is 100k\n");
		return RESULT_OK;
	}

	int numvars = 0;
	for(char *c = cmd; c && *c; ) {
		c = strstr(c, var);
		if(c) {
			numvars++;
			c++;
		}
	}

	for(int i = from; i < to; i++) {
		const int MAX_NUMLEN=24;
		const int newcmd_maxlen = strlen(cmd) + numvars * MAX_NUMLEN + 1;
		char *newcmd = str_replace_all(newcmd_maxlen, cmd, var, i);

		printf("%s: ", newcmd);
		
		char *newarg = strchr(newcmd, ' ');
		if(newarg) {
			*newarg = 0;
			newarg++;
		}

		process_cmd(newcmd, newarg, entropy, entsize, dict);

		free(newcmd);
	}

	return RESULT_OK;
}

#ifdef HAVE_LIBBITCOIN
#define BITCOIN_KEY_MAXLEN 512

typedef void (*subcmd_f)(CMD_ARGS, unsigned char *data, char *buf);

static int buffered_cmd(CMD_ARGS, size_t bufsize, subcmd_f subcmd)
{
	if(!arg) {
		printf("need an arg\n");
		return RESULT_OK;
	}

	if(DERIVED_ENTROPY_SIZE <= 16) {
		printf("assertion failed in buffered_cmd");
		return RESULT_QUIT;
	}

	unsigned char *data = derive_key_name(entropy, entsize, arg);
	char *buf = sodium_malloc(bufsize);

	if(data && buf) {
		subcmd(CMD_ARGNAMES, data, buf);
	} else {
		perror("malloc?");
	}
	sodium_free(data);
	sodium_free(buf);
	return RESULT_OK;
}

static void subcmd_xkey(CMD_ARGS, unsigned char *data, char *buf, 
		e_btc_xkeytype keytype)
{
	if(bitcoin_get_xkey(data, DERIVED_ENTROPY_SIZE, 
				buf, BITCOIN_KEY_MAXLEN, keytype)) {
		if(debug_mode)
			printf("%s %s: ", keytype == BTC_XPRV ? "xprv" : "xpub", arg);
		print_str(buf);
	}
	else
		perror("bitcoin_get_xkey");
}

static void subcmd_xprv(CMD_ARGS, unsigned char *data, char *buf)
{
	subcmd_xkey(CMD_ARGNAMES, data, buf, BTC_XPRV);
}

static void subcmd_xpub(CMD_ARGS, unsigned char *data, char *buf)
{
	subcmd_xkey(CMD_ARGNAMES, data, buf, BTC_XPUB);
}

static int cmd_xprv(CMD_ARGS)
{
	return buffered_cmd(CMD_ARGNAMES, BITCOIN_KEY_MAXLEN, subcmd_xprv);
}

static int cmd_xpub(CMD_ARGS)
{
	return buffered_cmd(CMD_ARGNAMES, BITCOIN_KEY_MAXLEN, subcmd_xpub);
}

static void subcmd_eseed(CMD_ARGS, unsigned char *data, char *buf)
{
	if(bitcoin_get_electrum_seed(data, 16, buf, 511)) {
		print_str(buf);
	} else
		perror("bitcoin_get_electrum_seed");
}

static int cmd_eseed(CMD_ARGS)
{
	return buffered_cmd(CMD_ARGNAMES, 512, subcmd_eseed);
}

static void subcmd_e1st(CMD_ARGS, unsigned char *data, char *buf)
{
	if(bitcoin_get_electrum_1st(data, 16, buf, 63)) {
		print_str(buf);
	} else
		perror("bitcoin_get_electrum_1st");
}

static int cmd_e1st(CMD_ARGS)
{
	return buffered_cmd(CMD_ARGNAMES, 256, subcmd_e1st);
}

static void subcmd_exprv(CMD_ARGS, unsigned char *data, char *buf)
{
	if(bitcoin_get_electrum_xprv(data, 16, buf, 255)) {
		print_str(buf);
	} else
		perror("bitcoin_get_electrum_xprv");
}

static int cmd_exprv(CMD_ARGS)
{
	return buffered_cmd(CMD_ARGNAMES, 256, subcmd_exprv);
}

static void subcmd_expub(CMD_ARGS, unsigned char *data, char *buf)
{
	if(bitcoin_get_electrum_xpub(data, 16, buf, 255)) {
		print_str(buf);
	} else
		perror("bitcoin_get_electrum_xpub");
}

static int cmd_expub(CMD_ARGS)
{
	return buffered_cmd(CMD_ARGNAMES, 256, subcmd_expub);
}
#endif // HAVE_LIBBITCOIN

#pragma GCC diagnostic pop

static int process_cmd(const char *cmd, const char *arg,
	const unsigned char *entropy, const int entsize, const char **dict)
{
	struct {
		char *name;
		int (*fn)(CMD_ARGS);
	} cmds[] = {
		{ "help", cmd_help },
		{ "quit", cmd_quit },
		{ "exit", cmd_quit },
		{ "h", cmd_h },
		{ "h32", cmd_h32 },
		{ "h16", cmd_h16 },
		{ "r", cmd_readable },
		{ "for", cmd_for },
#ifdef HAVE_LIBBITCOIN
		{ "xprv", cmd_xprv },
		{ "xpub", cmd_xpub },
		{ "eseed", cmd_eseed },
		{ "e1st", cmd_e1st },
		{ "exprv", cmd_exprv },
		{ "expub", cmd_expub },
#endif // HAVE_LIBBITCOIN
		{ NULL, NULL }
	};

	for(int i = 0; cmds[i].name; i++) {
		if(!strcmp(cmds[i].name, cmd)) {
			return cmds[i].fn(arg, entropy, entsize, dict);
		}
	}

	printf("unknown command: %s(%s)\n", cmd, arg);
	return RESULT_OK;
}

static int mainloop(const unsigned char *entropy, const int entsize,
	const char **dict)
{
	char *cmd = linenoise("cmd> ");
	char *arg;
	int rv = 1;

	if(!cmd)
		return 0;

	linenoiseHistoryAdd(cmd);

	arg = strchr(cmd, ' ');

	if(arg) {
		arg[0] = 0;
		arg++;
		if(arg[0] == 0)
			arg = NULL;
	}

	rv = process_cmd(cmd, arg, entropy, entsize, dict);

	free(cmd);

	return rv;
}

static void read_hex(unsigned char *data, const char *hex)
{
	char single[3] = "\x0\x0\x0";
	for(unsigned i = 0; i < strlen(hex); i+=2) {
		single[0] = hex[i];
		single[1] = hex[i+1];
		unsigned long int v = strtoul(single, NULL, 16);
		data[i/2] = (unsigned char)v;
	}
}

static unsigned char *get_master_entropy_from_param(struct tg_opts *tgo)
{
	char *hexdata = tgo->master_entropy;
	int read_from_stdin = 0;
	unsigned char *master_entropy = NULL;

	if(strcmp(hexdata, "-") == 0) {
		printf("Please enter your " C_YELLOW "MASTER ENTROPY"C_RESET":\n");
		hexdata = get_password();
		read_from_stdin = 1;
	}
	if(strlen(hexdata) != MASTER_ENTROPY_SIZE * 2) {
		sodium_memzero(hexdata, strlen(hexdata));
		printf("--master-entropy must be %d bytes long\n", MASTER_ENTROPY_SIZE);
		return NULL;
	}
	master_entropy = sodium_malloc(MASTER_ENTROPY_SIZE);
	read_hex(master_entropy, hexdata);
	if(read_from_stdin)
		sodium_free(hexdata);
	else
		sodium_memzero(hexdata, MASTER_ENTROPY_SIZE * 2);

	return master_entropy;
}

static unsigned char *get_master_entropy_by_pwd_hash(struct tg_opts *tgo)
{
	unsigned char *master_entropy = NULL;
	char *salt = NULL;
	char *master_passwd = NULL;

	printf("Please enter your " C_WHITE "salt" C_RESET ":\n");
	salt = linenoise(C_WHITE "salt" C_RESET "> ");
	if(!salt) {
		printf("no salt?\n");
		return NULL;
	}

	printf("Please enter your " C_RED "MASTER PASSWORD" C_RESET ":\n");
	master_passwd = get_password();
	if(!master_passwd) {
		printf("no password?\n");
		return NULL;
	}

	master_entropy = passwd_to_entropy(tgo, salt, master_passwd);
	sodium_free(master_passwd);
	free(salt);

	return master_entropy;
}

int main(int argc, char **argv)
{
	struct tg_opts tgo = parse_opts(argc, argv);
	unsigned char *master_entropy = NULL;
	const char *dict[] = {
#include "wordlist.h"
		NULL
	};

	if(sodium_init() == -1) {
		printf("sodium didn't initialize\n");
		return 1;
	}

	if(tgo.master_entropy) {
		master_entropy = get_master_entropy_from_param(&tgo);
	} else {
		master_entropy = get_master_entropy_by_pwd_hash(&tgo);
	}

	if(!master_entropy) {
		printf("error\n");
		return 2;
	}

	if(debug_mode) {
		printf("master entropy: "); 
		print_hex(master_entropy, MASTER_ENTROPY_SIZE);
	}

	print_help();
	print_verification(master_entropy, MASTER_ENTROPY_SIZE, dict);

	while(mainloop(master_entropy, MASTER_ENTROPY_SIZE, dict) == RESULT_OK);

	sodium_free(master_entropy);

	printf("Bye!\n");
	return 0;
}
