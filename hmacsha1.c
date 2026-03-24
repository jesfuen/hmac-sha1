#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <err.h>
#include <openssl/evp.h>
#include <string.h>
#include <strings.h>

enum {
	BUFSIZE = 4096,
	PADSIZE = 64,
	IPAD = 0x36,
	OPAD = 0x5c
};

void
usage()
{
	errx(EXIT_FAILURE, "usage: hash-sha1 datafile keyfile");
}

void
create_hash(unsigned int *md_len, unsigned char *hash, FILE *fd,
	    unsigned char *pad, size_t pad_len, unsigned char *data,
	    size_t data_len)
{
	EVP_MD_CTX *mdctx;
	unsigned char buffer[BUFSIZE];
	size_t br;

	mdctx = EVP_MD_CTX_new();
	if (mdctx == NULL) {
		errx(EXIT_FAILURE, "Message digest create failed.\n");
	}

	if (!EVP_DigestInit(mdctx, EVP_sha1())) {
		errx(EXIT_FAILURE, "Message digest initialization failed.\n");
	}

	if (pad != NULL) {
		if (!EVP_DigestUpdate(mdctx, pad, pad_len)) {
			errx(EXIT_FAILURE, "Message digest update failed.\n");
		}
	}

	if (fd != NULL) {
		while ((br = fread(buffer, sizeof(char), BUFSIZE, fd)) > 0) {
			if (!EVP_DigestUpdate(mdctx, buffer, br)) {
				errx(EXIT_FAILURE,
				     "Message digest update failed.\n");
			}
		}
	}

	if (data != NULL) {
		if (!EVP_DigestUpdate(mdctx, data, data_len)) {
			errx(EXIT_FAILURE, "Message digest update failed.\n");
		}
	}

	if (!EVP_DigestFinal_ex(mdctx, hash, md_len)) {
		errx(EXIT_FAILURE, "Message digest finalization failed.\n");
	}

	EVP_MD_CTX_free(mdctx);

}

unsigned char *
read_key(FILE *fd_key, int *key_len)
{
	unsigned char *key;
	size_t br;

	key = malloc(BUFSIZE);
	if (key == NULL)
		errx(EXIT_FAILURE, "error: malloc failed!");

	while ((br = fread(key + *key_len, sizeof(char), BUFSIZE, fd_key)) > 0) {
		*key_len += br;
		key = realloc(key, *key_len + BUFSIZE);
		if (key == NULL)
			errx(EXIT_FAILURE, "error: realloc failed!");
	}
	return key;
}

void
prepare_pads(unsigned char *key, int key_len, unsigned char *k_ipad,
	     unsigned char *k_opad)
{
	unsigned int md_len;
	int i;

	memset(k_ipad, 0x00, PADSIZE);
	memset(k_opad, 0x00, PADSIZE);

	if (key_len < 20) {
		warnx
		    ("warning: key is too short (should be longer than 20 bytes)");
	}

	if (key_len <= 64) {
		memcpy(k_ipad, key, key_len);
		memcpy(k_opad, key, key_len);
	} else {
		create_hash(&md_len, k_ipad, NULL, NULL, 0, key, key_len);
		memcpy(k_opad, k_ipad, md_len);
	}

	for (i = 0; i < 64; i++) {
		k_ipad[i] ^= IPAD;
		k_opad[i] ^= OPAD;
	}
}

int
main(int argc, char *argv[])
{

	unsigned char inner_hash[EVP_MAX_MD_SIZE];
	unsigned char final_hash[EVP_MAX_MD_SIZE];
	unsigned int md_len;
	FILE *fd_data, *fd_key;
	unsigned char k_ipad[PADSIZE], k_opad[PADSIZE];
	unsigned char *key;
	int key_len = 0;
	int i;

	if (argc != 3) {
		usage();
	}

	fd_data = fopen(argv[1], "r");
	if (fd_data == NULL) {
		err(EXIT_FAILURE, "error: open failed!");
	}

	fd_key = fopen(argv[2], "r");
	if (fd_key == NULL) {
		err(EXIT_FAILURE, "error: open failed!");
	}

	key = read_key(fd_key, &key_len);
	prepare_pads(key, key_len, k_ipad, k_opad);

	create_hash(&md_len, inner_hash, fd_data, k_ipad, sizeof(k_ipad), NULL,
		    0);
	create_hash(&md_len, final_hash, NULL, k_opad, sizeof(k_opad),
		    inner_hash, md_len);

	fclose(fd_data);
	fclose(fd_key);

	for (i = 0; i < (int)md_len; i++) {
		printf("%02x", final_hash[i]);
	}

	free(key);
	exit(EXIT_SUCCESS);
}
