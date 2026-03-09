#include <stdio.h>
#include <stdlib.h>
#include <err.h>
#include <openssl/evp.h>
#include <string.h>

enum {
    BUFSIZE = 4096
};

void
usage() {
    errx(EXIT_FAILURE,"usage: hash-sha1 str");
}



void
create_hash(unsigned int *md_len, unsigned char *hash , FILE *fd) {  
    EVP_MD_CTX *mdctx;
    unsigned char buffer[BUFSIZE];
    size_t br;

    mdctx = EVP_MD_CTX_new();
    if (mdctx == NULL) {
        errx(EXIT_FAILURE, "Message digest create failed.\n");
    }

    if (!EVP_DigestInit(mdctx, EVP_sha1())) {
        errx(EXIT_FAILURE,"Message digest initialization failed.\n");
    }

    // Leer del fichero e ir actualizando
    while ((br = fread(buffer, 1, sizeof(buffer), fd)) > 0) {
        if (!EVP_DigestUpdate(mdctx, buffer, br))
            errx(EXIT_FAILURE, "Message digest update failed.\n");
    }

    if (!EVP_DigestFinal_ex(mdctx,hash, md_len)) {
        errx(EXIT_FAILURE,"Message digest finalization failed.\n");
    }


    EVP_MD_CTX_free(mdctx);

}



int
main(int argc, char *argv[]) {

    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int md_len;
    FILE *fd;

    if (argc != 2) {
        usage();
    }

    fd = fopen(argv[1], "r");
    if (fd == NULL) {
        err(EXIT_FAILURE,"error: open failed!");
    }

    create_hash(&md_len,hash,fd);
    

    for (int i = 0; i < md_len; i++) {
        printf("%02x",hash[i]);
    }

    exit(EXIT_SUCCESS);
}