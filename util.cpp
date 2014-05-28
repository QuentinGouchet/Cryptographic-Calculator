#include "util.h"

/*Convertit un nb en base 256 en mpz*/
buff_t Util::convert(mpz_t n,unsigned int flag) {
    mpz_t cp,mod,_256;
    mpz_inits(cp,mod,_256,NULL);
    mpz_set(cp,n);
    mpz_set_ui(_256,256);

    unsigned int size = 0;

    while(mpz_cmp_ui(cp,0) > 0) {
        mpz_mod(mod,cp,_256);
        mpz_fdiv_q(cp,cp,_256);
        size++;
    }

    //printf("size = %u\n",size);

    if(flag == 0) {
        size = 30;
    }

    mpz_set(cp,n);

    unsigned char* exit = (unsigned char*)calloc(size,sizeof(unsigned char));

    unsigned int i = 0;
    while(mpz_cmp_ui(cp,0) > 0) {
        mpz_mod(mod,cp,_256);
        exit[size-(i++)-1] = mpz_get_ui(mod);
        mpz_fdiv_q(cp,cp,_256);
    }

    exit[size] = '\0';

    buff_t Ex;
    Ex.string = exit;
    Ex.size = size;

    //printf("Size = %d\n",Ex.size);
    //printf("%s\n",exit);
    //printf("%s\n",Ex.string);

    return Ex;
}

