#ifndef MYSHA_H
#define MYSHA_H

#include <string.h>
#include <stdlib.h>
#include "gmp.h"
#include <openssl/sha.h>

typedef unsigned char u8;
typedef unsigned long long int u16;

class MySha
{
public:
    MySha();
    int computeSha256(const char *, const char *);
    int computeSha512(const char *, const char *);
    int sha1(const char*, const char*);

private:
    void print_hex(u8*,int,const char*);
    u16 string_size(char*);
    void compute_sha1(u8*,u8*,unsigned long long int);
    void H(u8*,u8*,u8*,u8*);
    void G(u8*,u8*,u8*,u8*);
    void F(u8*,u8*,u8*,u8*);
    void u8_xor(u8*,u8*,u8*);
    void shift_left(u8*,u8*,u8);
    void add(u8*,u8*,u8*);
    void u8_memcpy(u8*,u8*,u16);
};

#endif // MYSHA_H
