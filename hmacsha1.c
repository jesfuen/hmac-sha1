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
    errx(EXIT_FAILURE,"usage: hash-sha1 datafile keyfile");
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
    FILE *fd_data;
    FILE *fd_key;
    unsigned char k_ipad[EVP_MAX_MD_SIZE];
    unsigned char k_opad[EVP_MAX_MD_SIZE];

    if (argc != 3) {
        usage();
    }

    // Fichero de datos
    fd_data = fopen(argv[1], "r");
    if (fd_data == NULL) {
        err(EXIT_FAILURE,"error: open failed!");
    }

    // Fichero de key
    fd_key = fopen(argv[2],"r");
    if (fd_key == NULL) {
        err(EXIT_FAILURE,"error: open failed!");
    }

    // Crear la hash de la key? -> Solo si la key es mayor de 64 bytes, se corresponde a la parte opcional
    // create_hash(fd_key);
    // De normal si la clave supera los 64 bytes, se manda tal cual pero rellenando con ceros hasta completar los 64 bytes
    // Dar un warning al usuario si la key es menor de 20 bytes

    // Aqui habria que crear el XOR y pasarselo a la funcion create_hash
    create_hash(&md_len,hash,fd_data);
    

    for (int i = 0; i < md_len; i++) {
        printf("%02x",hash[i]);
    }

    exit(EXIT_SUCCESS);
}