#ifndef RSA_H
#define RSA_H

#include "gmp.h"
#include "time.h"
#include <stdio.h>
#include <QByteArray>
#include <QVector>
#include <QFile>
#include <QTextStream>
#include <iostream>
#include "util.h"

#include "openssl/sha.h"

class RSA
{
public:
    RSA();
    int sign(const char *, const char *, const char *);
    int verify(const char *, const char *, const char *);
    int generateKey(unsigned int, const char *);
    int encrypt(const char*, const char*, const char*);
    int encryptOAEP(const char*, const char*, const char*);
    int decrypt(const char*, const char*, const char*);
    int decryptCRT(const char*, const char*, const char*);
    int decryptOAEP(const char*, const char*, const char*);
};

#endif // RSA_H
