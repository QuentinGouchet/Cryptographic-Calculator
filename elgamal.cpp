#include "elgamal.h"

ElGamal::ElGamal(){}

#ifdef __cplusplus
extern "C" {
#endif

int ElGamal::generateKey(unsigned int tailleCle, const char* fileNameKeys){
    mpz_t p, g, x, exp, h, pSub;
    gmp_randstate_t state;
    char pathFileNamePublicKey[50];
    char pathFileNamePrivateKey[50];
    FILE * publicKey;
    FILE * privateKey;

    mpz_inits(p, g, pSub, exp, x, h, NULL);

    // Initialisation du random
    gmp_randinit_default(state);
    gmp_randseed_ui(state, time(NULL));

    do{
        mpz_urandomb(p, state, tailleCle);
        mpz_setbit(p, tailleCle-1);
        mpz_sub_ui(pSub,p,1);
        mpz_divexact_ui (pSub,pSub,2);
    }while(mpz_probab_prime_p(p, 10) == 0 || mpz_probab_prime_p(pSub,10) == 0);

    while(1){
        mpz_urandomm(g, state, p);
        mpz_powm(exp, g, pSub, p);
        if(mpz_cmp_ui(exp, 1) == 0){
            continue;
        }
        mpz_powm_ui(exp, g, 2, p);
        if(mpz_cmp_ui(exp, 1) == 0){
            continue;
        }
        break;
    }

    // pSub = p-1/2 = q (cf. wiki / elGamal)
    mpz_urandomm(x, state, pSub);
    mpz_powm(h, g, x, p);

    //stockage
    sprintf(pathFileNamePublicKey, "../ressources/%s.puKey", fileNameKeys);
    sprintf(pathFileNamePrivateKey, "../ressources/%s.prKey", fileNameKeys);

    publicKey = fopen(pathFileNamePublicKey, "w");
    privateKey = fopen(pathFileNamePrivateKey, "w");

    if(publicKey == NULL || privateKey == NULL){
        mpz_clears(p, g, pSub, exp, x, h, NULL);
        return 1;
    }

    gmp_fprintf(publicKey, "%ZX\n%ZX\n%ZX", g, p, h);
    gmp_fprintf(privateKey, "%ZX\n%ZX\n%ZX", x, g, p);

    fclose(publicKey);
    fclose(privateKey);
    mpz_clears(p, g, pSub, exp, x, h, NULL);
    return 0;
}

int ElGamal::cipherElGamal(const char* root_plaintext, const char* root_publicKey, const char* fileNameCipher){
    FILE* plaintext;
    FILE* publicKey;
    FILE* ciphertext;
    mpz_t g, p, h, y, c_1, c_2, plain, s, q;
    gmp_randstate_t state;
    char pathFileCipher[50];
    unsigned char* buffer;
    unsigned int res, i, size;

    mpz_inits(g, p, h, y, c_1, c_2, plain, s, q, NULL);

    sprintf(pathFileCipher, "../ressources/%s.cipher", fileNameCipher);

    plaintext = fopen(root_plaintext, "r");
    publicKey = fopen(root_publicKey, "r");
    ciphertext = fopen(pathFileCipher, "w");

    if((plaintext == NULL) || (publicKey == NULL) || (ciphertext == NULL)) {
        mpz_clears(g, p, h, y, c_1, c_2, plain, s, q, NULL);
        return 1;
    }
    gmp_fscanf(publicKey, "%ZX\n%ZX\n%ZX", g, p, h);

    //Recuperation de la taille du fichier
    fseek (plaintext , 0 , SEEK_END);
    size = ftell(plaintext);
    rewind(plaintext);

    gmp_randinit_default(state);
    gmp_randseed_ui(state, time(NULL));

    mpz_sub_ui(q, p, 1);
    mpz_divexact_ui(q, q, 2);

    mpz_urandomm(y, state, q);
    mpz_powm(s, h, y, p);

    mpz_powm(c_1, g, y, p);

    //Write c_1 into cipherfile
    gmp_fprintf(ciphertext, "%ZX\n", c_1);

    /*
        On lit ici la totalité du text à chiffrer que l'on stocke
        dans buffer en pensant à bien rajouter le caractere de fin de chaine ('\0')
    */
    buffer = (unsigned char*)malloc((sizeof(unsigned char)*size)+1);
    res = fread(buffer, sizeof(unsigned char), size, plaintext);
    buffer[size] = '\0';
    // Si la lecture echoue :
    if(res != size){
        return 1;
        mpz_clears(g, p, h, y, c_1, c_2, plain, s, q, NULL);
    }
    else{
        /*
            Ici commence notre routine de chiffrement.
            Dans un premier temps il est necessaire d'etablir un nombre de caracteres maximum
            que l'on peut chiffrer afin de ne pas depasser la taille du module du chiffrement
            ce ferait echoue le chiffrement. Nous avons choisis de composer des blocs de 30
            caractères.
            Ensuite pour chaque caractere de notre buffer :
                - nous l'ajoutons a 'plain' qui aura prealablement ete multiplie par 256 de tel
                sorte nous obtenons, pour la chaine 'ABC' = 'A'*256^2 + 'B'*256 + 'C'
                - si nous atteignons la taille maximale de notre bloc (30), nous effectuons la
                routine de chiffrement, puis nous stockons le chiffré obtenu dans notre fichier.
        */
        mpz_set_ui(plain, 0);
        for(i = 0 ; i < size ; i++){
            if(i % 30 == 0 && i > 0){
                mpz_mul(c_2, plain, s);
                mpz_mod(c_2, c_2, p);

                //Write c_2 into cipherfile
                gmp_fprintf(ciphertext, "%ZX\n", c_2);
                mpz_set_ui(plain, 0);
            }
            mpz_mul_ui(plain, plain, 256);
            mpz_add_ui(plain, plain, buffer[i]);
        }
        /*
            Etape necessaire de chiffrement afin de considerer le dernier caractère
        */
        mpz_mul(c_2, plain, s);
        mpz_mod(c_2, c_2, p);
        //Write c_2 into cipherfile
        gmp_fprintf(ciphertext, "0\n");
        gmp_fprintf(ciphertext, "%ZX", c_2);
    }

    fclose(ciphertext);
    fclose(plaintext);
    fclose(publicKey);
    mpz_clears(g, p, h, y, c_1, c_2, plain, s, q, NULL);
    return 0;
}

int ElGamal::decipherElGamal(const char* root_ciphertext, const char* root_privateKey, const char* fileNamePlain) {
    FILE* ciphertext;
    FILE* privateKey;
    FILE* plaintext;
    unsigned int flag = 0, i, inc = 0;
    mpz_t g, p, m, c_1, c_2, cipher, s, x, tmp, car;
    char pathFilePlain[50];

    mpz_inits(g, p, m, c_1, c_2, cipher, s, x, tmp, car, NULL);

    sprintf(pathFilePlain, "../ressources/%s", fileNamePlain);

    ciphertext = fopen(root_ciphertext, "r");
    privateKey = fopen(root_privateKey, "r");
    plaintext = fopen(pathFilePlain, "w");

    if((ciphertext == NULL) || (privateKey == NULL) || (plaintext == NULL)){
        mpz_clears(g, p, m, c_1, c_2, cipher, s, x, tmp, car, NULL);
        return 1;
    }

    gmp_fscanf(privateKey, "%ZX\n%ZX\n%ZX", x, g, p);

    while(gmp_fscanf(ciphertext, "%ZX\n", cipher) == 1){
        if(inc == 0){
            mpz_set(c_1, cipher);
            mpz_powm(s, c_1, x, p);
        }
        else{
            flag = 0;
            if(mpz_cmp_ui(cipher,0) == 0) {
                flag = 1;
                gmp_fscanf(ciphertext,"%ZX ",cipher);
            }

            mpz_set(c_2, cipher);
            mpz_invert(tmp, s, p);
            mpz_mul(m, c_2, tmp);
            mpz_mod(m, m, p);

            buff_t exit = Util::convert(m,flag);
            for(i = 0; i < exit.size ; i++) {
                fprintf(plaintext,"%c",exit.string[i]);
            }
            free(exit.string);
        }
        inc++;
    }

    fclose(plaintext);
    fclose(ciphertext);
    fclose(privateKey);
    mpz_clears(g, p, m, c_1, c_2, cipher, s, x, tmp, car, NULL);
    return 0;
}

int ElGamal::sign(const char * hashFilePath, const char * prKeyFilePath, const char * fileNameSign){
    FILE* hashFile;
    FILE* privateKey;
    FILE* signature;

    char pathSignFile[50];
    gmp_randstate_t state;

    mpz_t gcd, k, pSub, p, r, hash, x, k_inv, g, h, s;
    mpz_inits(gcd, k, pSub, p, r, hash, x, k_inv, g, h, s, NULL);

    gmp_randinit_default(state);
    gmp_randseed_ui(state, time(NULL));

    sprintf(pathSignFile, "../ressources/%s.sign", fileNameSign);

    privateKey = fopen(prKeyFilePath, "r");
    hashFile = fopen(hashFilePath, "r");
    signature = fopen(pathSignFile, "w");

    if((privateKey == NULL) || (hashFile == NULL) || (signature == NULL)){
        mpz_clears(gcd, k, pSub, p, r, hash, x, k_inv, g, h, s, NULL);
        return 1;
    }

    gmp_fscanf(hashFile, "%ZX", hash);
    gmp_fscanf(privateKey, "%ZX\n%ZX\n%ZX", x, g, p);

    mpz_sub_ui(pSub, p, 1);

    do{
        do{
            mpz_urandomm(k, state, pSub);
            mpz_gcd(gcd, k, pSub);
        }while(mpz_cmp_ui(gcd,1) != 0);

        mpz_powm(r, g, k, p);   

        mpz_mul(s, x, r);
        mpz_sub(s, hash, s);
        mpz_invert(k_inv, k, pSub);
        mpz_mul(s, s, k_inv);
        mpz_mod(s, s, pSub);
    }while(mpz_cmp_ui(s,0) == 0);

    gmp_fprintf(signature, "%ZX\n%ZX", r, s);

    fclose(signature);
    fclose(privateKey);
    fclose(hashFile);

    mpz_clears(gcd, k, pSub, p, r, hash, x, k_inv, g, s, NULL);
    return 0;
}

int ElGamal::verify(const char* pathSignFile, const char* pathPuKeyFile, const char* pathHashFile){
    FILE *signFile;
    FILE *puKeyFile;
    FILE *hashFile;
    mpz_t g, p, pSub, h, r, s, hash, op1, op2, op21, op22;

    mpz_inits(g, p, pSub, h, r, s, hash, op1, op2, op21, op22, NULL);

    signFile = fopen(pathSignFile, "r");
    puKeyFile = fopen(pathPuKeyFile, "r");
    hashFile = fopen(pathHashFile, "r");

    if((signFile == NULL) || (puKeyFile == NULL) || (hashFile == NULL)){
        mpz_clears(g, p, pSub, h, r, s, hash, op1, op2, op21, op22, NULL);
        return 2;
    }
    gmp_fscanf(signFile, "%ZX\n%ZX", r, s);
    gmp_fscanf(puKeyFile, "%ZX\n%ZX\n%ZX", g, p, h);
    gmp_fscanf(hashFile, "%ZX", hash);

    /*
        Ici commence la vérification
        On test :
            0 < r < p
            0 < s < p-1
            g^H(m) mod p = y^r * r^s mod p

        ==>
            op1 = g^H(m) mod p
            op2 = op21* op22 mod p
            op21 = y^r mod p
            op22 = r^s mod p
    */
    mpz_sub_ui(pSub, p, 1);
    if(mpz_cmp_ui(r, 0) < 0 || mpz_cmp(r, p) > 0 || mpz_cmp_ui(s, 0) < 0 || mpz_cmp(s, pSub) > 0){
        return 1;
    }
    else{
        mpz_powm(op1, g, hash, p);

        mpz_powm(op21, h, r, p);
        mpz_powm(op22, r, s, p);
        mpz_mul(op2, op21, op22);
        mpz_mod(op2, op2, p);
        if(mpz_cmp(op1, op2) == 0){
            mpz_clears(g, p, pSub, h, r, s, hash, op1, op2, op21, op22, NULL);
            return 0;
        }
        else{
            mpz_clears(g, p, pSub, h, r, s, hash, op1, op2, op21, op22, NULL);
            return 1;
        }
    }    

    fclose(signFile);
    fclose(hashFile);
    fclose(puKeyFile);
}

#ifdef __cplusplus
}
#endif
