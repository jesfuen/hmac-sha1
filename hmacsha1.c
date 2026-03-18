#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <err.h>
#include <openssl/evp.h>
#include <string.h>
#include <strings.h>

enum {
    BUFSIZE = 4096
};



void
usage() {
    errx(EXIT_FAILURE,"usage: hash-sha1 datafile keyfile");
}


/*
USOS DE create_hash():

    1- Crear SHA1(key^ipad || data) 
    2- Crear SHA1(key^opad || SHA1(key^ipad || data))
    3- Crear SHA1(key) si key > 64 bytes
*/
void
create_hash(unsigned int *md_len, unsigned char *hash , FILE *fd_data, FILE *fd_key, unsigned char) {
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
    unsigned char *key;
    int key_len = 0;
    size_t br;
    int i;

    if (argc != 3) {
        usage();
    }

    fd_data = fopen(argv[1], "r");
    if (fd_data == NULL) {
        err(EXIT_FAILURE,"error: open failed!");
    }

    fd_key = fopen(argv[2],"r");
    if (fd_key == NULL) {
        err(EXIT_FAILURE,"error: open failed!");
    }

    // Leer con realloc para ver el tamaño de la key
    key = malloc(EVP_MAX_MD_SIZE);
    if (key == NULL) {
        errx(EXIT_FAILURE, "error: malloc failed!");
    }

    while ((br = fread(key + key_len, sizeof(char), EVP_MAX_MD_SIZE , fd_key)) > 0) {
        key_len += br;
        key = realloc(key, key_len + EVP_MAX_MD_SIZE);
        if (key == NULL) {
            errx(EXIT_FAILURE, "error: realloc failed!");
        }
    }

    // Inicializar los k_ipad y k_opad
    bzero(k_ipad,sizeof(k_ipad));
    bzero(k_opad,sizeof(k_opad));

    if (key_len < 20) {
        warnx("warning: key is too short (should be longer than 20 bytes)");
        // meter la key en ipad y opad
        bcopy(key, k_ipad, key_len);
        bcopy(key,k_opad,key_len);
    } else if (key_len <= 64) {
        // meter la key en ipad y opad
        bcopy(key, k_ipad, key_len);
        bcopy(key,k_opad,key_len);
    } else {
        // Hacer la hash de la key y meterla en ipad y opad
    }

    for (i = 0; i < 64; i++) {
        k_ipad[i] ^= 0x36;
        k_opad[i] ^= 0x5c;
    }


    // Aqui habria que crear el XOR y pasarselo a la funcion create_hash
    create_hash(&md_len,hash,fd_data);

    fclose(fd_data);
    fclose(fd_key);
    

    for (int i = 0; i < md_len; i++) {
        printf("%02x",hash[i]);
    }

    free(key);
    exit(EXIT_SUCCESS);
}