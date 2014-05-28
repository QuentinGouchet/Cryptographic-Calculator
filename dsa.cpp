#include "dsa.h"

DSA::DSA(){}

#ifdef __cplusplus
extern "C" {
#endif

int DSA::generateKey(const char* root_keys){
        FILE* puKey;
        FILE* prKey;

        char pathPuKey[50];
        char pathPrKey[50];

        sprintf(pathPuKey, "../ressources/%s.puKey", root_keys);
        sprintf(pathPrKey, "../ressources/%s.prKey", root_keys);

        int length[] = {512, 576, 640, 704, 768, 832, 896, 960, 1024};

        unsigned int taille;

        mpz_t g, p, q, y, x, z, h, pSub, L, div_ex, exp;
        mpz_inits(g, p, q, y, x, z, h, pSub, L, div_ex, exp, NULL);

        gmp_randstate_t state;
        gmp_randinit_default(state);
        gmp_randseed_ui(state, time(NULL));

        srand(time(NULL));

        do{
            do{
                mpz_urandomb(q, state, 160);
                mpz_setbit(q, 159);
            }while((mpz_probab_prime_p(q, 25) == 0));

            do{
                taille = length[rand()%9];
                mpz_urandomb(z, state, taille-160);
                mpz_setbit(z, taille-161);
                mpz_mul(p, q, z);
                mpz_add_ui(p, p, 1);
            }while(taille != mpz_sizeinbase(p,2));
        }while(mpz_probab_prime_p(p, 25) == 0);

        mpz_sub_ui(pSub, p, 1);

        do{
            mpz_urandomm(h, state, pSub);
            mpz_powm(g, h, z, p);
        }while((mpz_cmp_ui(g, 1) < 0) || (mpz_cmp_ui(h, 1) < 0));

        do{
            mpz_urandomm(x, state, q);
        }while(mpz_cmp_ui(x, 0) == 0);

        mpz_powm(y, g, x, p);

        if((puKey = fopen(pathPuKey, "w")) == NULL){
            mpz_clears(g, p, q, y, x, z, h, pSub, L, div_ex, exp, NULL);
            return 1;
        }
        gmp_fprintf(puKey, "%ZX\n%ZX\n%ZX\n%ZX", p, q, g, y);
        fclose(puKey);

        if((prKey = fopen(pathPrKey, "w")) == NULL){
            mpz_clears(g, p, q, y, x, z, h, pSub, L, div_ex, exp, NULL);
            return 1;
        }
        gmp_fprintf(prKey, "%ZX", x);
        fclose(prKey);

        mpz_clears(g, p, q, y, x, z, h, pSub, L, div_ex, exp, NULL);
        return 0;
}

int DSA::sign(const char* root_hash, const char* root_puKey, const char* root_prKey, const char* root_sign_file) {
    FILE* hashFile;
    FILE* puKey;
    FILE* prKey;
    FILE* signFile;

    char pathSignFile[50];

    sprintf(pathSignFile, "../ressources/%s.sign", root_sign_file);

    mpz_t p, q, g, y, x, hash, s, s1, s2, s_inv;
    mpz_inits(p, q, g, y, x, hash, s, s1, s2, s_inv, NULL);

    gmp_randstate_t state;
    gmp_randinit_default(state);
    gmp_randseed_ui(state, time(NULL));

    if((puKey = fopen(root_puKey, "r")) == NULL){
        mpz_clears(p, q, g, y, x, hash, s, s1, s2, s_inv, NULL);
        return 1;
    }
    gmp_fscanf(puKey, "%ZX\n%ZX\n%ZX\n%ZX", p, q, g, y);
    fclose(puKey);

    if((prKey = fopen(root_prKey, "r")) == NULL){
        mpz_clears(p, q, g, y, x, hash, s, s1, s2, s_inv, NULL);
        return 1;
    }
    gmp_fscanf(prKey, "%ZX", x);
    fclose(prKey);

    if((hashFile = fopen(root_hash, "r")) == NULL){
        mpz_clears(p, q, g, y, x, hash, s, s1, s2, s_inv, NULL);
        return 1;
    }
    gmp_fscanf(hashFile, "%ZX", hash);
    fclose(hashFile);

    do{
        mpz_urandomm(s, state, q);
    }while(mpz_cmp_ui(s, 0) == 0);

    mpz_powm(s1, g, s, p);				//s1 = g^s mod p
    mpz_mod(s1, s1, q);				//s1 = (g^s mod p)mod q

    mpz_mul(s2, s1, x);				//s2 = s1*x
    mpz_add(s2, s2, hash);				//s2 = H(m)+s1*x
    mpz_invert(s_inv, s, q);			//s_inv = s^-1 mod q
    mpz_mul(s2, s2, s_inv);				//s2 = (H(m)+s1*x)s^-1
    mpz_mod(s2, s2, q);				//s2 = (H(m)+s1*x)s^-1 mod q

    if((signFile = fopen(pathSignFile, "w")) == NULL) {
        mpz_clears(p, q, g, y, x, hash, s, s1, s2, s_inv, NULL);
        return 1;
    }
    gmp_fprintf(signFile, "%ZX\n%ZX", s1, s2);
    fclose(signFile);

    mpz_clears(p, q, g, y, x, hash, s, s1, s2, s_inv, NULL);
    return 0;
}

int DSA::verify(const char* root_sign, const char* root_puKey, const char* root_hash_file) {
     FILE* signFile;
     FILE* hashFile;
     FILE* puKey;

     mpz_t s1, s2, p, q, g, y, hash, w, u1, u2, v, tmp;
     mpz_inits(s1, s2, p, q, g, y, hash, w, u1, u2, v, tmp, NULL);

     if((signFile = fopen(root_sign, "r")) == NULL){
         mpz_clears(s1, s2, p, q, g, y, hash, w, u1, u2, v, tmp, NULL);
         return 2;
     }
     gmp_fscanf(signFile, "%ZX\n%ZX", s1, s2);
     fclose(signFile);

     if((hashFile = fopen(root_hash_file, "r")) == NULL){
         mpz_clears(s1, s2, p, q, g, y, hash, w, u1, u2, v, tmp, NULL);
         return 2;
     }
     gmp_fscanf(hashFile, "%ZX", hash);
     fclose(hashFile);

     if((puKey = fopen(root_puKey, "r")) == NULL){
         mpz_clears(s1, s2, p, q, g, y, hash, w, u1, u2, v, tmp, NULL);
         return 2;
     }
     gmp_fscanf(puKey, "%ZX\n%ZX\n%ZX\n%ZX", p, q, g, y);
     fclose(puKey);

     mpz_invert(w, s2, q);

     if((mpz_cmp(s1, q) > 0) || (mpz_cmp(s2, q) > 0) || (mpz_cmp_ui(s1, 0) < 0) || (mpz_cmp_ui(s2, 0) < 0)) return 1;

     mpz_invert(w, s2, q);						//w = (s_2)^-1 mod q
     mpz_mul(u1, hash, w);						//u1 = H(m)*w
     mpz_mod(u1, u1, q);						//u1 = (H(m)*w) mod q

     mpz_mul(u2, s1, w);						//u2 = s1*w
     mpz_mod(u2, u2, q);						//u2 = (s1*w) mod q

     mpz_powm(w, g, u1, p);						//w = g^u1 mod p
     mpz_powm(tmp, y, u2, p);					//tmp = y^u2 mod p
     mpz_mul(w, w, tmp);						//w = (g^u1 mod p)(y^u2 mod p)
     mpz_mod(v, w, p);						//v = (g^u1 mod p)(y^u2 mod p) mod p
     mpz_mod(v, v, q);						//v = [(g^u1 mod p)(y^u2 mod p) mod p] mod q

     if(mpz_cmp(s1, v) == 0) {
         mpz_clears(s1, s2, p, q, g, y, hash, w, u1, u2, v, tmp, NULL);
         return 0;
     }
     else {
         mpz_clears(s1, s2, p, q, g, y, hash, w, u1, u2, v, tmp, NULL);
         return 1;
     }
     mpz_clears(s1, s2, p, q, g, y, hash, w, u1, u2, v, tmp, NULL);
 }
#ifdef __cplusplus
}
#endif
