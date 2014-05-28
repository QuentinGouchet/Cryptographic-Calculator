#ifndef UTIL_H
#define UTIL_H

#include <stdio.h>
#include <stdlib.h>
#include "gmp.h"

typedef struct{
    unsigned char* string;
    unsigned int size;
}buff_t;

class Util
{
    public:
        static buff_t convert(mpz_t,unsigned int);
};

#endif // UTIL_H
