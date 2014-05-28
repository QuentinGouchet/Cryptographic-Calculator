#include "rabin.h"

#ifdef __cplusplus
extern "C" {
#endif

/* THOSE FILES NEED 4 INPUT FILES:

    - 1) PLAINTEXT.txt file (or root)
    - 2) PUBLIC_KEY.txt file (or root)
    - 3) PRIVATE_KEY.txt file (ONLY FOR DECIPHERING FUNCTION) (or root)
    - 4) CIPHERTEXT.txt file (or root)

    PLAINTEXT CORRESPOND TO WHAT YOU WANT TO ENCRYPT, PUBLIC_KEY IS THE KEY YOU WILL USE (N,b) COUPLE SUCH THAT
    CIPHER = (PLAIN)*(PLAIN + B) MOD N

    THE PUBLIC_KEY FILE IS SUCH THAT N IS ON THE FIRST LINE AND B ON THE SECOND
    THE PRIVATE_KEY FILE IS SUCH THAT P IS ON THE FIRST LINE AND Q ON THE SECOND

    **NOTE THAT B = 0 IS USUALLY A GOOD CHOICE**
*/

/*COMPUTES BEZOUTS' COEFFICIENTS SUCH THAT U*A + V*B = 1*/
int Rabin::Bezout_coeff (mpz_t rop_u,mpz_t rop_v,const mpz_t n,const mpz_t m) {

    mpz_t a,b,q,r,u0,u1,u2,v0,v1,v2;
    mpz_inits(a,b,q,r,u0,u1,u2,v0,v1,v2,NULL);

    mpz_set(a,n);
    mpz_set(b,m);
    mpz_set_ui(u0,1);
    mpz_set_ui(u1,0);
    mpz_set_ui(v0,0);
    mpz_set_ui(v1,1);

    mpz_fdiv_r(r,a,b);
    mpz_fdiv_q(q,a,b);

    while(mpz_cmp_ui(r,0)>0) {
        mpz_set(a,b);
        mpz_set(b,r);
        mpz_fdiv_r(r,a,b);
        mpz_mul(u2,q,u1); mpz_sub(u2,u0,u2);
        mpz_mul(v2,q,v1); mpz_sub(v2,v0,v2);
        mpz_set(u0,u1);
        mpz_set(v0,v1);
        mpz_set(u1,u2);
        mpz_set(v1,v2);
        mpz_fdiv_q(q,a,b);
    }

    mpz_set(rop_u,u1);
    mpz_set(rop_v,v1);

    mpz_clears(a,b,q,r,u0,u1,u2,v0,v1,v2,NULL);
    return 0;
}

/*COMPUTES THE EXACT ROOT WITH THE GIVEN PARAMETERS*/
int Rabin::exact_root (mpz_t res,mpz_t r1,mpz_t r2,mpz_t r3,mpz_t r4,mpz_t N,mpz_t b,int bit_parity,int bit_jacobi) {
    mpz_t two,m,tmp,invert,b_2;
    mpz_inits(two,m,tmp,invert,b_2,NULL);

    int parity,jacobi;

    /*
        Routine :
            two = 2
            invert = 2⁻¹ mod N
            b_2 = b * (2⁻¹ mod N)
            b_2 = (b * (2⁻¹ mod N)) mod N
    */
    mpz_set_ui(two,2);
    mpz_invert(invert,two,N);
    mpz_mul(b_2,b,invert);
    mpz_mod(b_2,b_2,N);

    /*
        Routine :
            tmp = r1 mod 2
            (int) parity = r1 mod 2
            jacobi = (r1/N)
            r1 = r1 - b_2
            r1 = (r1 mod N)
    */
    mpz_mod(tmp,r1,two);
    parity = mpz_get_ui(tmp);
    jacobi = mpz_jacobi(r1,N);
    mpz_sub(r1,r1,b_2);
    mpz_mod(r1,r1,N);
    if( (parity == bit_parity) && (jacobi == bit_jacobi) ) {
        mpz_clears(two,m,tmp,invert,b_2,NULL);
        mpz_set(res,r1);
        return 0;
    }

    /*
        Routine :
            tmp = r2 mod 2
            (int) parity = r2 mod 2
            jacobi = (r2/N)
            r2 = r2 - b_2
            r2 = (r2 mod N)
    */
    mpz_mod(tmp,r2,two);
    parity = mpz_get_ui(tmp);
    jacobi = mpz_jacobi(r2,N);
    mpz_sub(r2,r2,b_2);
    mpz_mod(r2,r2,N);
    if( (parity == bit_parity) && (jacobi == bit_jacobi) ) {
        mpz_clears(two,m,tmp,invert,b_2,NULL);
        mpz_set(res,r2);
        return 0;
    }

    /*
        Routine :
            tmp = r3 mod 2
            (int) parity = r3 mod 2
            jacobi = (r3/N)
            r3 = r3 - b_2
            r3 = (r3 mod N)
    */
    mpz_mod(tmp,r3,two);
    parity = mpz_get_ui(tmp);
    jacobi = mpz_jacobi(r3,N);
    mpz_sub(r3,r3,b_2);
    mpz_mod(r3,r3,N);
    if( (parity == bit_parity) && (jacobi == bit_jacobi) ) {
        mpz_clears(two,m,tmp,invert,b_2,NULL);
        mpz_set(res,r3);
        return 0;
    }

    /*
        Routine :
            tmp = r4 mod 2
            (int) parity = r4 mod 2
            jacobi = (r4/N)
            r4 = r4 - b_2
            r4 = r4 mod N
    */
    mpz_mod(tmp,r4,two);
    parity = mpz_get_ui(tmp);
    jacobi = mpz_jacobi(r4,N);
    mpz_sub(r4,r4,b_2);
    mpz_mod(r4,r4,N);
    if( (parity == bit_parity) && (jacobi == bit_jacobi) ) {
        mpz_clears(two,m,tmp,invert,b_2,NULL);
        mpz_set(res,r4);
        return 0;
    }

    mpz_clears(two,m,tmp,invert,b_2,NULL);
    return 0;
}

int Rabin::encrypt_Rabin (const char* root_plaintext,const char* root_ciphertext,const char* root_public_key) {
    FILE * plaintext;
    FILE * public_key;
    FILE * ciphertext;

    unsigned int i, bit_parity, bit_jacobi, res;

    char pathFileName[50];

    mpz_t m,c,N,b,m_b,bit_par,b_2,m_b_2,two,invert;

    mpz_inits(m,c,N,b,m_b,bit_par,b_2,m_b_2,two,invert,NULL);

    sprintf(pathFileName, "../ressources/%s.cipher", root_ciphertext);

    public_key = fopen(root_public_key,"r");
    plaintext = fopen(root_plaintext,"r");
    ciphertext = fopen(pathFileName,"w");

    if((public_key == NULL) || (plaintext == NULL) || (ciphertext == NULL)){
        mpz_clears(m,c,N,b,m_b,bit_par,b_2,m_b_2,two,invert,NULL);
        return 1;
    }

    gmp_fscanf(public_key,"%ZX\n%ZX",N,b);
    fclose(public_key);

    fseek(plaintext, 0, SEEK_END);
    size_t size = ftell(plaintext);
    rewind(plaintext);

    unsigned char* buff = (unsigned char*)malloc(size*sizeof(unsigned char));
    res = fread(buff, sizeof(unsigned char), size, plaintext);
    fclose(plaintext);

    if(res != size){
        mpz_clears(m,c,N,b,m_b,bit_par,b_2,m_b_2,two,invert,NULL);
        return 1;
    }
    else{
        mpz_set_ui(m,0);
        for(i = 0 ; i < size ; i++) {
            if(i % 30 == 0 && i > 0) {
                mpz_add(m_b,m,b);
                mpz_mul(c,m,m_b);
                mpz_mod(c,c,N);

                mpz_set_ui(two,2);
                mpz_invert(invert,two,N);
                mpz_mul(b_2,b,invert);

                mpz_add(m_b_2,m,b_2);
                mpz_mod(m_b_2,m_b_2,N);

                mpz_mod(bit_par,m_b_2,two);
                bit_parity = mpz_get_ui(bit_par);
                bit_jacobi = mpz_jacobi(m_b_2,N);

                gmp_fprintf(ciphertext,"%ZX ",c);
                gmp_fprintf(ciphertext,"%ZX ",bit_par);
                gmp_fprintf(ciphertext,"%d\n",bit_jacobi);

                mpz_set_ui(m,0);
            }
            mpz_mul_ui(m,m,256);
            mpz_add_ui(m,m,buff[i]);
        }

        mpz_add(m_b,m,b);
        mpz_mul(c,m,m_b);
        mpz_mod(c,c,N);

        mpz_set_ui(two,2);
        mpz_invert(invert,two,N);
        mpz_mul(b_2,b,invert);

        mpz_add(m_b_2,m,b_2);
        mpz_mod(m_b_2,m_b_2,N);

        mpz_mod(bit_par,m_b_2,two);
        bit_parity = mpz_get_ui(bit_par);
        bit_jacobi = mpz_jacobi(m_b_2,N);
        mpz_set_ui(two,0);
        gmp_fprintf(ciphertext,"%ZX\n",two);
        gmp_fprintf(ciphertext,"%ZX ",c);
        gmp_fprintf(ciphertext,"%ZX ",bit_par);
        gmp_fprintf(ciphertext,"%d\n",bit_jacobi);
    }

    fclose(ciphertext);

    free(buff);
    mpz_clears(m,c,N,b,m_b,bit_par,b_2,m_b_2,two,invert,NULL);

    return 0;
}

int Rabin::decrypt_Rabin (const char* root_ciphertext,const char* root_plaintext,const char* root_private_key) {
    FILE * plaintext;
    FILE * private_key;
    FILE * ciphertext;

    unsigned int flag, i;
    char pathFileName[50];

    mpz_t c,p,q,N,b,u,v,rp,rq,r1,r2,r3,r4,tmp,upr,vqr,cp,invert,four;

    mpz_inits(c,p,q,N,b,u,v,rp,rq,r1,r2,r3,r4,tmp,upr,vqr,cp,invert,four,NULL);

    int bit_parity,bit_jacobi;

    sprintf(pathFileName, "../ressources/%s", root_plaintext);

    private_key = fopen(root_private_key,"r");
    ciphertext = fopen(root_ciphertext,"r");
    plaintext = fopen(pathFileName,"w");

    if((private_key == NULL) || (ciphertext == NULL) || (plaintext == NULL)){
        mpz_clears(c,p,q,N,b,u,v,rp,rq,r1,r2,r3,r4,tmp,upr,vqr,cp,invert,four,NULL);
        return 1;
    }

    gmp_fscanf(private_key,"%ZX %ZX\n%ZX\n%ZX", p, q, N, b);

    while(gmp_fscanf(ciphertext,"%ZX",c) == 1) {
        flag = 0;
        if(mpz_cmp_ui(c,0) == 0) {
            flag = 1;
            gmp_fscanf(ciphertext,"\n%ZX ",c);
        }

        fscanf(ciphertext," %d %d\n",&bit_parity,&bit_jacobi);

        Bezout_coeff(u,v,p,q);

        mpz_set_ui(four,4);

        mpz_add_ui(tmp,p,1); 			//tmp = p+1
        mpz_divexact_ui(tmp,tmp,4);		//tmp = (p+1)/4
        mpz_mul(cp,b,b);			//cp = b²
        mpz_invert(invert,four,p);		//invert = 4⁻¹ mod p
        mpz_mul(cp,cp,invert);			//cp = b² * (4⁻¹ mod p)
        mpz_add(cp,c,cp);			//cp = c + b² * (4⁻¹ mod p)
        mpz_powm_sec(rp,cp,tmp,p);		//tmp = (c+b²*4⁻¹)^(p+1)/4
        mpz_mod(rp,rp,p);			//r_p = (c+b²*4⁻¹)^(p+1)/4 mod p

        mpz_add_ui(tmp,q,1);			//tmp = q+1
        mpz_divexact_ui(tmp,tmp,4);		//tmp = (q+1)/4
        mpz_mul(cp,b,b);			//cp = b²
        mpz_invert(invert,four,q);		//invert = 4⁻¹ mod q
        mpz_mul(cp,invert,cp);			//cp = b² * (4⁻¹ mod q)
        mpz_add(cp,c,cp);			//cp = c + b² * (4⁻¹ mod q)
        mpz_powm_sec(rq,cp,tmp,q);		//tmp = (c+b²*4⁻¹)^(q+1)/4
        mpz_mod(rq,rq,q);			//r_q = (c+b²/4)^(q+1)/4 mod q

        mpz_mul(upr,u,p);			//upr = u*p
        mpz_mul(upr,upr,rq);			//upr = u*p*r_q
        mpz_mul(vqr,v,q);			//vqr = v*q
        mpz_mul(vqr,vqr,rp);			//vqr = v*q*r_p

        mpz_add(r1,upr,vqr);			//r1 = u*p*r_q + v*q*r_p
        mpz_mod(r1,r1,N);			//r1 = (u*p*r_q + v*q*r_p) mod N

        mpz_neg(r2,r1);				//r2 = -r1 = - u*p*r_q - v*q*r_p
        mpz_mod(r2,r2,N);			//r2 = (- u*p*r_q - v*q*r_p) mod N

        mpz_sub(r3,upr,vqr);			//r3 = u*p*r_q - v*q*r_p
        mpz_mod(r3,r3,N);			//r3 = (u*p*r_q - v*q*r_p) mod N

        mpz_sub(r4,vqr,upr);			//r4 = v*q*r_p - u*p*r_q
        mpz_mod(r4,r4,N);			//r4 = (v*q*r_p - u*p*r_q) mod N

        exact_root(c,r1,r2,r3,r4,N,b,bit_parity,bit_jacobi);
        buff_t exit = Util::convert(c,flag);

        for(i = 0 ; i < exit.size ; i++) {
            fprintf(plaintext,"%c",exit.string[i]);
        }
        free(exit.string);
    }

    fclose(plaintext);
    fclose(private_key);
    fclose(ciphertext);
    mpz_clears(c,p,q,N,b,u,v,rp,rq,r1,r2,r3,r4,tmp,NULL);

    return 0;
}

int Rabin::generateKey(unsigned int tailleCle, const char* fileNameKeys){
    mpz_t p, q, n, res, b;
    gmp_randstate_t state;
    char pathPublicKey[50], pathPrivateKey[50];
    FILE * publicKey;
    FILE * privateKey;

    mpz_inits(p, q, n, res, b, NULL);

    // définition de l'aléa
    gmp_randinit_default(state);
    gmp_randseed_ui(state, time(NULL));

    // Génération de p
    do{
        mpz_urandomb(p, state, tailleCle/2);
        mpz_mod_ui(res,p,4);
    }while(mpz_sizeinbase(p, 2) != tailleCle/2 || mpz_probab_prime_p(p, 10) == 0 || mpz_cmp_ui(res,3) != 0);

    // Génération de q
    do{
        mpz_urandomb(q, state, (tailleCle/2)+1);
        mpz_mod_ui(res,q,4);
    }while(mpz_sizeinbase(q, 2) != (tailleCle/2)+1 || mpz_probab_prime_p(q, 10) == 0 || mpz_cmp_ui(res,3) != 0);

    // Calcul de n
    mpz_mul(n, p, q);

    // Calcul de b
    mpz_urandomm(b, state, n);

    sprintf(pathPublicKey, "../ressources/%s.puKey", fileNameKeys);
    sprintf(pathPrivateKey, "../ressources/%s.prKey", fileNameKeys);

    //Stockage des différentes valeurs dans des fichier
    publicKey = fopen(pathPublicKey, "w");
    privateKey = fopen(pathPrivateKey, "w");

    if(publicKey == NULL || privateKey == NULL){
        return 1;
    }
    gmp_fprintf(privateKey, "%ZX\n%ZX\n%ZX\n%ZX", p, q, n, b);
    gmp_fprintf(publicKey, "%ZX\n%ZX", n, b);

    mpz_clears(p, q, n, res, b, NULL);
    fclose(publicKey);
    fclose(privateKey);
    return 0;
}

#ifdef __cplusplus
}
#endif

