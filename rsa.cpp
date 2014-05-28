#include "rsa.h"

RSA::RSA(){}

#ifdef __cplusplus
extern "C" {
#endif

int RSA::sign(const char * hashFilePath, const char * prKeyFilePath, const char * fileNameSign){
    FILE * hashFile;
    FILE * privateKey;
    char pathSign[50];

    hashFile = fopen(hashFilePath, "r");
    privateKey = fopen(prKeyFilePath, "r");

    if(hashFile == NULL || privateKey == NULL){
        return 1;
    }
    else{
        FILE * fileSigne;
        mpz_t signe, hash, d, n, e;
        mpz_inits(signe, hash, d, n, e, NULL);

        gmp_fscanf(hashFile, "%ZX", hash);
        gmp_fscanf(privateKey, "%ZX\n%ZX", d, n);

        mpz_powm(signe, hash, d, n);

        sprintf(pathSign, "../ressources/%s.sign", fileNameSign);

        fileSigne = fopen(pathSign, "w");
        if(fileSigne == NULL){
            return 1;
        }
        else{
            gmp_fprintf(fileSigne, "%ZX\n", signe);
        }

        fclose(hashFile);
        fclose(privateKey);
        fclose(fileSigne);
        mpz_clears(signe, hash, d, n, e, NULL);
        return 0;
    }
}

int RSA::verify(const char * hashFilePath, const char * signFilePath, const char * puKeyFilePath){
    FILE * hashFile;
    FILE * signFile;
    FILE * puKeyFile;

    hashFile = fopen(hashFilePath, "r");
    signFile = fopen(signFilePath, "r");
    puKeyFile = fopen(puKeyFilePath, "r");

    if(hashFile == NULL || signFile == NULL || puKeyFile == NULL){
        return 1;
    }
    else{
        mpz_t verif, hash, signe, e, n;
        mpz_inits(verif, hash, signe, e, n, NULL);

        gmp_fscanf(hashFile, "%ZX", hash);
        gmp_fscanf(signFile, "%ZX", signe);
        gmp_fscanf(puKeyFile, "%ZX\n%ZX", e, n);

        mpz_powm(verif, signe, e, n);

        if(mpz_cmp(verif, hash) == 0){
            mpz_clears(verif, hash, signe, e, n, NULL);
            fclose(hashFile);
            fclose(signFile);
            fclose(puKeyFile);
            return 0;
        }
        else{
            mpz_clears(verif, hash, signe, e, n, NULL);
            fclose(hashFile);
            fclose(signFile);
            fclose(puKeyFile);
            return 1;
        }
    }
}

int RSA::generateKey(unsigned int tailleCle, const char* fileNameKeys){
    mpz_t e, p, underP, q, underQ, n, fiN, d, gcd, bidon, res;
    gmp_randstate_t state;
    char pathPublicKey[50], pathPrivateKey[50];
    FILE * publicKey;
    FILE * privateKey;

    mpz_inits(e, p, underP, q, underQ, n, fiN, d, gcd, bidon, res, NULL);

    // définition de l'aléa
     gmp_randinit_default(state);
     gmp_randseed_ui(state, time(NULL));

    mpz_set_ui(e, 17);

    // Génération de p
    do{
        mpz_urandomb(p, state, tailleCle/2);
        mpz_sub_ui(underP, p, 1);
        mpz_gcd(gcd, underP, e);
    }while(mpz_sizeinbase(p, 2) != tailleCle/2 || mpz_probab_prime_p(p, 10) == 0 || mpz_cmp_ui(gcd, 1) != 0);

    // Génération de q
    do{
        mpz_urandomb(q, state, (tailleCle/2)+1);
        mpz_sub_ui(underQ, q, 1);
        mpz_gcd(gcd, underQ, e);
    }while(mpz_sizeinbase(q, 2) != (tailleCle/2)+1 || mpz_probab_prime_p(q, 10) == 0 || mpz_cmp_ui(gcd, 1) != 0);

    // Calcul de n
    mpz_mul(n, p, q);

    // Calcul de fiN
    mpz_mul(fiN, underP, underQ);

    // Calcul de d
    mpz_invert(d, e, fiN);

    sprintf(pathPublicKey, "../ressources/%s.puKey", fileNameKeys);
    sprintf(pathPrivateKey, "../ressources/%s.prKey", fileNameKeys);

    //Stockage des différentes valeurs dans des fichier
    publicKey = fopen(pathPublicKey, "w");
    privateKey = fopen(pathPrivateKey, "w");

    if(publicKey == NULL || privateKey == NULL){
        return 1;
    }
    else{
        gmp_fprintf(privateKey, "%ZX\n%ZX\n%ZX\n%ZX\n%ZX", d, n, p, q, e);
        gmp_fprintf(publicKey, "%ZX\n%ZX", e, n);
    }
    mpz_clears(e, p, underP, q, underQ, n, fiN, d, gcd, NULL);
    fclose(publicKey);
    fclose(privateKey);
    return 0;
}

int RSA::encrypt(const char* textFilePath, const char* keyFilePath, const char* fileNameCrypt) {
    FILE* textFile;
    FILE* pubKeyFile;
    FILE* fileCrypt;

    char pathCrypt[50];
    unsigned int res, i;

    mpz_t m, c, e, n, zero;

    mpz_inits(m, c, e, n, zero, NULL);

    sprintf(pathCrypt, "../ressources/%s.cipher", fileNameCrypt);

    fileCrypt = fopen(pathCrypt, "w");
    textFile = fopen(textFilePath, "r");
    pubKeyFile = fopen(keyFilePath, "r");

    if(textFile == NULL || pubKeyFile == NULL || fileCrypt == NULL){
        mpz_inits(m, c, e, n, zero, NULL);
        return 1;
    }
    else{
        gmp_fscanf(pubKeyFile, "%ZX\n%ZX", e, n);

        fseek(textFile, 0, SEEK_END);
        size_t size = ftell(textFile);
        rewind(textFile);

        unsigned char* buff = (unsigned char*)malloc(size*sizeof(unsigned char));
        res = fread(buff, sizeof(unsigned char), size, textFile);
        fclose(textFile);

        if(res != size){
            mpz_inits(m, c, e, n, zero, NULL);
            return 1;
        }
        else{
            mpz_set_ui(m,0);
            for(i=0;i<size;i++) {
                if(i%30 == 0 && i > 0) {
                    mpz_powm(c, m, e, n);
                    gmp_fprintf(fileCrypt, "%ZX\n", c);
                    mpz_set_ui(m,0);
                }
                mpz_mul_ui(m,m,256);
                mpz_add_ui(m,m,buff[i]);
            }

            mpz_powm(c, m, e, n);
            mpz_set_ui(zero, 0);
            gmp_fprintf(fileCrypt, "%ZX\n", zero);
            gmp_fprintf(fileCrypt, "%ZX", c);
            fclose(fileCrypt);

            mpz_clears(m,c,e,n,zero,NULL);

            return 0;
        }
    }
}

int RSA::encryptOAEP(const char * plainFilePath, const char * puKeyFilePath, const char * cipherFileName){
    SHA256_CTX sha256;
      unsigned char gS[SHA256_DIGEST_LENGTH], hashS[SHA256_DIGEST_LENGTH];
      char *rS, *toHashS;
      int i, ret;
      FILE *plainFile;
      FILE *puKeyFile;
      FILE *tmpFile;
      FILE *cipherFile;
      char cipherFilePath[50], toCipherS[4096];
      mpz_t e, n, r, toHash, hash, g, plain, cipher, taille, droite, gauche, toCipher;
      gmp_randstate_t state;

      mpz_inits(e, n, r, toHash, hash, g, plain, cipher, taille, droite, gauche, toCipher, NULL);
      gmp_randinit_default(state);
      gmp_randseed_ui(state, time(NULL));

      sprintf(cipherFilePath, "../ressources/%s.cipher", cipherFileName);

      /*
          Section of gathering information in files
      */
      if((plainFile = fopen(plainFilePath, "r")) == NULL){
          mpz_clears(e, n, r, toHash, hash, g, plain, cipher, taille, droite, gauche, toCipher, NULL);
          return 1;
      }
      gmp_fscanf(plainFile, "%ZX", plain);
      fclose(plainFile);

      if((puKeyFile = fopen(puKeyFilePath, "r")) == NULL){
          mpz_clears(e, n, r, toHash, hash, g, plain, cipher, taille, droite, gauche, toCipher, NULL);
          return 1;
      }
      gmp_fscanf(puKeyFile, "%ZX\n%ZX", e, n);
      fclose(puKeyFile);

      /*
          Processing encryption
          Ek = ek(m + g(r) || r + H(m + g(r)))
      */
      mpz_set_ui(taille, mpz_sizeinbase(n, 2));
      mpz_div_ui(taille, taille, 2);
      mpz_urandomb(r, state, mpz_get_ui(taille));

      rS = mpz_get_str(NULL, 16, r);

      SHA256_Init(&sha256);
      SHA256_Update(&sha256, rS, mpz_sizeinbase(r, 16));
      SHA256_Final(gS, &sha256);

      // execution de g(r) avec passage par fichier
      // pour ce qui est de la mise en forme
      if((tmpFile = fopen("../ressources/hash.tmp", "w")) == NULL){
          mpz_clears(e, n, r, toHash, hash, g, plain, cipher, taille, droite, gauche, toCipher, NULL);
          return 1;
      }
      for(i = 0 ; i<SHA256_DIGEST_LENGTH ; i++){
          gmp_fprintf(tmpFile, "%02X", gS[i]);
      }
      fclose(tmpFile);
      if((tmpFile = fopen("../ressources/hash.tmp", "r")) == NULL){
          mpz_clears(e, n, r, toHash, hash, g, plain, cipher, taille, droite, gauche, toCipher, NULL);
          return 1;
      }
      gmp_fscanf(tmpFile, "%ZX", g);
      fclose(tmpFile);
      ret = system("rm -f ../ressources/hash.tmp");
      if(ret != 0){
          return 1;
      }

      mpz_xor(toHash, g, plain);
      toHashS = mpz_get_str(NULL, 16, toHash);

      SHA256_Init(&sha256);
      SHA256_Update(&sha256, toHashS, mpz_sizeinbase(toHash, 16));
      SHA256_Final(hashS, &sha256);

      // execution de H(m + g(r)) avec passage par fichier
      // pour ce qui est de la mise en forme
      if((tmpFile = fopen("../ressources/hash.tmp", "w")) == NULL){
          mpz_clears(e, n, r, toHash, hash, g, plain, cipher, taille, droite, gauche, toCipher, NULL);
          return 1;
      }
      for(i = 0 ; i<SHA256_DIGEST_LENGTH ; i++){
          gmp_fprintf(tmpFile, "%02X", hashS[i]);
      }
      fclose(tmpFile);
      if((tmpFile = fopen("../ressources/hash.tmp", "r")) == NULL){
          mpz_clears(e, n, r, toHash, hash, g, plain, cipher, taille, droite, gauche, toCipher, NULL);
          return 1;
      }
      gmp_fscanf(tmpFile, "%ZX", hash);
      fclose(tmpFile);
      ret = system("rm -f ../ressources/hash.tmp");
      if(ret != 0){
          return 1;
      }

      // compute r + H(m + g(r))
      mpz_xor(droite, r, hash);

      // compute plain + g(r)
      mpz_xor(gauche, plain, g);

      // realisation de la concatenation entre
      // partie gauche et droite;
      gmp_sprintf(toCipherS, "%ZX%ZX", gauche, droite);
      mpz_set_str(toCipher, toCipherS, 16);

      // Realisation de ek(m + g(r) || r + H(m + g(r)))
      mpz_powm(cipher, toCipher, e, n);

      if((cipherFile = fopen(cipherFilePath, "w")) == NULL){
          mpz_clears(e, n, r, toHash, hash, g, plain, cipher, taille, droite, gauche, toCipher, NULL);
          return 1;
      }
      gmp_fprintf(cipherFile, "%d\n%ZX\n", mpz_sizeinbase(r, 16), cipher);
      fclose(cipherFile);

      mpz_clears(e, n, r, toHash, hash, g, plain, cipher, taille, droite, gauche, toCipher, NULL);
      return 0;
}

int RSA::decrypt(const char* cryptFilePath, const char* keyFilePath, const char* fileNameUncrypt) {
    FILE* textFile;
    FILE* keyFile;
    FILE* fileClear;

    char pathClear[50];
    unsigned int i;

    mpz_t crypt, clear, d, n, m;

    mpz_inits(crypt, clear, d, n, m, NULL);

    sprintf(pathClear, "../ressources/%s", fileNameUncrypt);

    // Ouverture du fichier de la clé et du fichier chiffré
    keyFile = fopen(keyFilePath, "r");
    textFile = fopen(cryptFilePath, "r");
    fileClear = fopen(pathClear, "w");

    if(keyFile == NULL || textFile == NULL || fileClear == NULL) {
        mpz_clears(crypt, clear, d, n, m, NULL);
        return 1;
    }
    else{
        // Lecture clé privée
        gmp_fscanf(keyFile, "%ZX\n%ZX", d, n);

        // Lecture des nombres (chiffrés des caractères)
        while(gmp_fscanf(textFile, "%ZX\n", crypt) == 1) {
            int flag = 0;
            if(mpz_cmp_ui(crypt,0) == 0) {
                gmp_fscanf(textFile, "%ZX", crypt);
                flag = 1;
            }

            mpz_powm(m, crypt, d, n);

            buff_t exit = Util::convert(m,flag);
            for(i = 0 ; i < exit.size ; i++) {
                fprintf(fileClear,"%c",exit.string[i]);
            }
            free(exit.string);

        }
        fclose(fileClear);
        mpz_clears(crypt, clear, d, n, m, NULL);
        return 0;
    }
}

int RSA::decryptCRT(const char* cipherFilePath, const char* prKeyFilePath, const char* plainFileName){
    FILE *cipherFile;
    FILE *prKeyFile;
    FILE *plainFile;

    mpz_t d, n, p, q, e, pSub, dP, dQ, qSub, qInv, crypt, m, m1, m2, h, plain;
    char pathPlainFile[50];
    unsigned int i;

    mpz_inits(d, n, p, q, e, pSub, dP, dQ, qSub, qInv, crypt, plain, m, m1, m2, h, NULL);

    sprintf(pathPlainFile, "../ressources/%s.plain", plainFileName);

    cipherFile = fopen(cipherFilePath, "r");
    prKeyFile = fopen(prKeyFilePath, "r");
    plainFile = fopen(pathPlainFile, "w");

    if((cipherFile) == NULL || (prKeyFile) == NULL || (plainFile) == NULL){
        mpz_clears(d, n, p, q, e, pSub, dP, dQ, qSub, qInv, crypt, plain, m, m1, m2, h, NULL);
        return 1;
    }
    gmp_fscanf(cipherFile, "%ZX", crypt);
    gmp_fscanf(prKeyFile, "%ZX\n%ZX\n%ZX\n%ZX\n%ZX", d, n, p, q, e);

    int flag;
    while(gmp_fscanf(cipherFile, "%ZX\n", crypt) == 1) {

        flag = 0;
        if(mpz_cmp_ui(crypt,0) == 0) {
            gmp_fscanf(cipherFile, "%ZX", crypt);
            flag = 1;
        }

        //Decipher process
        mpz_sub_ui(pSub, p, 1);
        mpz_sub_ui(qSub, q, 1);

        mpz_invert(dP, e, pSub);
        mpz_invert(dQ, e, qSub);
        mpz_invert(qInv, q, p);

        mpz_powm(m1, crypt, dP, p);
        mpz_powm(m2, crypt, dQ, q);
        mpz_sub(h, m1, m2);
        mpz_mul(h, h, qInv);
        mpz_mod(h, h, p);
        mpz_mul(m, h, q);
        mpz_add(m, m, m2);

        buff_t exit = Util::convert(m,flag);
        for(i = 0 ; i < exit.size ; i++) {
            fprintf(plainFile,"%c",exit.string[i]);
        }
        free(exit.string);

    }

    fclose(plainFile);
    fclose(prKeyFile);
    fclose(cipherFile);

    mpz_clears(d, n, p, q, e, pSub, dP, dQ, qSub, qInv, crypt, plain, m, m1, m2, h, NULL);
    return 0;
}

int RSA::decryptOAEP(const char *cipherFilePath, const char *prKeyFilePath, const char *plainFileName){
    SHA256_CTX sha256_1, sha256_2;
    char plainFilePath[50];
    unsigned char hashR[SHA256_DIGEST_LENGTH];
    int lengthR = 0, i = 0, ret = 0;
    QByteArray qb, qbGauche, qbDroite;
    FILE *cipherFile;
    FILE *prKeyFile;
    FILE *plainFile;
    FILE *tmpFile;
    mpz_t cipher, toDecipher, d, n, p, q, g, gauche, droite, hash, r, plain;

    sprintf(plainFilePath, "../ressources/%s.plain", plainFileName);
    mpz_inits(cipher, toDecipher, d, n, p, q, g, gauche, droite, hash, r, plain, NULL);

    cipherFile = fopen(cipherFilePath, "r");
    prKeyFile = fopen(prKeyFilePath, "r");
    plainFile = fopen(plainFilePath, "w");

    /*
        Gathering needed informations
    */
    if((cipherFile == NULL) || (prKeyFile == NULL) || (plainFile == NULL)){
        mpz_clears(cipher, toDecipher, d, n, p, q, g, gauche, droite, hash, r, plain, NULL);
        return 1;
    }
    gmp_fscanf(cipherFile, "%d\n%ZX", &lengthR, cipher);
    gmp_fscanf(prKeyFile, "%ZX\n%ZX\n%ZX\n%ZX", d, n, p, q);

    // On dechiffre grâce à RSA
    mpz_powm(toDecipher, cipher, d, n);
    qb = QByteArray(mpz_get_str(NULL, 16, toDecipher));
    qbGauche = QByteArray();
    qbDroite = QByteArray();

    for(i = 0 ; i < qb.length() ; i++){
        if(i < qb.length() - lengthR){
            qbGauche.append(qb.at(i));
        }
        else{
            qbDroite.append(qb.at(i));
        }
    }

    mpz_set_str(gauche, qbGauche.constData(), 16);
    mpz_set_str(droite, qbDroite.constData(), 16);

    // on calcul H(m+g(r))
    SHA256_Init(&sha256_1);
    SHA256_Update(&sha256_1, qbGauche.constData(), qbGauche.length());
    SHA256_Final(hashR, &sha256_1);

    if((tmpFile = fopen("../ressources/hash.tmp", "w")) == NULL){
        mpz_clears(cipher, toDecipher, d, n, p, q, g, gauche, droite, hash, r, plain, NULL);
        return 1;
    }
    for(i = 0 ; i<SHA256_DIGEST_LENGTH ; i++){
        gmp_fprintf(tmpFile, "%02X", hashR[i]);
    }
    fclose(tmpFile);
    if((tmpFile = fopen("../ressources/hash.tmp", "r")) == NULL){
        mpz_clears(cipher, toDecipher, d, n, p, q, g, gauche, droite, hash, r, plain, NULL);
        return 1;
    }
    gmp_fscanf(tmpFile, "%ZX", hash);
    fclose(tmpFile);
    ret = system("rm -f ../ressources/hash.tmp");
    if(ret != 0){
        return 1;
    }

    //On récupère ici notre r
    mpz_xor(r, hash, droite);

    //On calcul g(r)
    SHA256_Init(&sha256_2);
    SHA256_Update(&sha256_2, mpz_get_str(NULL, 16, r), mpz_sizeinbase(r, 16));
    SHA256_Final(hashR, &sha256_2);

    if((tmpFile = fopen("../ressources/hash.tmp", "w")) == NULL){
        mpz_clears(cipher, toDecipher, d, n, p, q, g, gauche, droite, hash, r, plain, NULL);
        return 1;
    }
    for(i = 0 ; i<SHA256_DIGEST_LENGTH ; i++){
        gmp_fprintf(tmpFile, "%02X", hashR[i]);
    }
    fclose(tmpFile);
    if((tmpFile = fopen("../ressources/hash.tmp", "r")) == NULL){
        mpz_clears(cipher, toDecipher, d, n, p, q, g, gauche, droite, hash, r, plain, NULL);
        return 1;
    }
    gmp_fscanf(tmpFile, "%ZX", g);
    fclose(tmpFile);
    ret = system("rm -f ../ressources/hash.tmp");
    if(ret != 0){
        return 1;
    }

    //on récupère m & stockage
    mpz_xor(plain, gauche, g);
    gmp_fprintf(plainFile, "%ZX", plain);

    fclose(plainFile);
    fclose(cipherFile);
    fclose(prKeyFile);

    mpz_clears(cipher, toDecipher, d, n, p, q, g, gauche, droite, hash, r, plain, NULL);
    return 0;
}

#ifdef __cplusplus
}
#endif
