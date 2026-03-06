#include <stdio.h>
#include <stdlib.h>
#include <err.h>
#include <openssl/evp.h>
#include <string.h>

void
usage() {
    errx(EXIT_FAILURE,"usage: hash-sha1 str");
}

/*

unsigned char*
create_hash() {

}

*/

int
main(int argc, char *argv[]) {

    EVP_MD_CTX *mdctx;
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int md_len;
    char mess1[] = "Test Message\n";

    if (argc != 2) {
        usage();
    }

    // Leer de stdin o de un fichero y pasar el contenido a create_hash()

    mdctx = EVP_MD_CTX_new();
    if (mdctx == NULL) {
        errx(EXIT_FAILURE, "Message digest create failed.\n");
    }

    if (!EVP_DigestInit(mdctx, EVP_sha1())) {
        errx(EXIT_FAILURE,"Message digest initialization failed.\n");
    }

    // Cambiar seccion a un bucle for para ir haciendo update
    if (!EVP_DigestUpdate(mdctx, mess1, strlen(mess1))) {
        errx(EXIT_FAILURE,"Message digest update failed.\n");
    }

    if (!EVP_DigestFinal_ex(mdctx,hash, &md_len)) {
        errx(EXIT_FAILURE,"Message digest finalization failed.\n");
    }


    EVP_MD_CTX_free(mdctx);

    // hash = create_hash()

    for (int i = 0; i < md_len; i++) {
        printf("%02x",hash[i]);
    }

    exit(EXIT_SUCCESS);
}