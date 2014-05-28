#ifndef RABIN_H
#define RABIN_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "gmp.h"
#include "util.h"

class Rabin
{
public:
    int encrypt_Rabin (const char* ,const char* ,const char* );
    int decrypt_Rabin (const char* ,const char* ,const char*);
    int generateKey(unsigned int ,const char*);

private:
    int Bezout_coeff(mpz_t,mpz_t,const mpz_t,const mpz_t);
    int exact_root(mpz_t,mpz_t,mpz_t,mpz_t,mpz_t,mpz_t,mpz_t,int,int);
};

#endif // RABIN_H
