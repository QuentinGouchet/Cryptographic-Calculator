#ifndef ELGAMAL_H
#define ELGAMAL_H

#include <stdio.h>
#include <stdlib.h>
#include <QByteArray>

#include "gmp.h"
#include "time.h"
#include "util.h"

class ElGamal
{
public:
    ElGamal();
    unsigned char* realloc_s (unsigned char**, int);
    int generateKey(unsigned int , const char*);
    int cipherElGamal(const char*, const char* , const char*);
    int decipherElGamal(const char*, const char*, const char*);
    int sign(const char*, const char*, const char *);
    int verify(const char*, const char*, const char*);
};

#endif // ELGAMAL_H
