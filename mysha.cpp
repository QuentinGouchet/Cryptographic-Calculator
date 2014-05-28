#include "mysha.h"

MySha::MySha(){}

#ifdef __cplusplus
extern "C" {
#endif

#define BLOC_MAX 0x7fff

int MySha::computeSha256(const char * plaintextPath, const char * fileNameHash){
    SHA256_CTX sha256;
    unsigned char hash[SHA256_DIGEST_LENGTH];
    int i;
    FILE *plaintext;
    FILE *hashFile;
    char ligne[256];
    char pathHash[50];

    SHA256_Init(&sha256);
    plaintext = fopen(plaintextPath, "r");

    if(plaintext == NULL){
        return 1;
    }
    else{
        while(fgets(ligne, 256, plaintext) != NULL){
            SHA256_Update(&sha256, ligne, strlen(ligne));
        }
        SHA256_Final(hash, &sha256);

        sprintf(pathHash, "../ressources/%s.hash", fileNameHash);

        // On stocke le hash dans un fichier
        if((hashFile = fopen(pathHash, "w")) == NULL){
            return 1;
        }
        else{
            for(i=0 ; i<SHA256_DIGEST_LENGTH ; i++){
                gmp_fprintf(hashFile, "%02X", hash[i]);
            }
            fclose(plaintext);
            fclose(hashFile);
            return 0;
        }
    }
}

int MySha::computeSha512(const char * plaintextPath, const char * fileNameHash){
    SHA512_CTX sha512;
    unsigned char hash[SHA512_DIGEST_LENGTH];
    int i;
    FILE *plaintext;
    FILE *hashFile;
    char ligne[512];
    char pathHash[50];

    SHA512_Init(&sha512);

    if((plaintext = fopen(plaintextPath, "r")) == NULL){
        return 1;
    }
    else{
        while(fgets(ligne, 512, plaintext) != NULL){
            SHA512_Update(&sha512, ligne, strlen(ligne));
        }
        SHA512_Final(hash, &sha512);

        sprintf(pathHash, "../ressources/%s.hash", fileNameHash);

        // On stocke le hash dans un fichier
        if((hashFile = fopen(pathHash, "w")) == NULL){
            return 1;
        }
        else{
            for(i=0 ; i<SHA512_DIGEST_LENGTH ; i++){
                gmp_fprintf(hashFile, "%02X", hash[i]);
            }
            fclose(plaintext);
            fclose(hashFile);
            return 0;
        }
    }
}

/*
Copy op2 in op1.
op2 and op1 are size bytes word.
*/
void MySha::u8_memcpy(u8* op1, u8* op2, u16 size)
{
    u16 i;

    for(i=0x0000 ; i < size ; i++)
        op1[i] = op2[i];

    return;
}
/*
Add 2 u8[4] words (32 bits) and store the result in res.

res must be allocate by caller.
res, op1 and op2 are 32 bits word.
*/
void MySha::add(u8* res, u8* op1, u8* op2)
{
    u8 i, j;
    u8 curr_carry = 0x00;
    u8 bit;
    u8 curr_bit, curr_bit_op1, curr_bit_op2, curr_res;

    for(i=0x04 ; i != 0x00 ; i--){

        bit = 0x01;
        res[i-1] = 0x00;


        for(j=0x00 ; j < 0x08 ; j++){

            curr_bit = bit << j;

            curr_bit_op1 = (op1[i-0x01] & curr_bit) == curr_bit ? 0x01 : 0x00;
            curr_bit_op2 = (op2[i-0x01] & curr_bit) == curr_bit ? 0x01 : 0x00;

            curr_res = curr_bit_op1 ^ curr_bit_op2 ^ curr_carry;
            curr_carry = (curr_bit_op1 & curr_bit_op2) | (curr_bit_op2 & curr_carry) | (curr_bit_op1 & curr_carry);
            res[i-0x01] |= (curr_res << j);
        }
    }
    return;
}

/*
number_shift must be write in HEX format
res and string has to be allocate by caller
*/
void MySha::shift_left(u8* res, u8* string, u8 number_shift)
{
    u8 i, j, carry, cache_carry;

    for(i=0x00 ; i < 0x04 ; i++)
        res[i] = string[i];

    for(i=0x00 ; i < number_shift ; i++){

        carry = 0x00;
        for(j=0x04 ; j != 0x00 ; j--){

            cache_carry = ((res[j-1] & 0x80) == 0X80) ? 0X01 : 0X00;
            res[j-1] = (res[j-1] << 1) | carry;
            carry = cache_carry;
        }
        res[0x03] |= carry;
    }
    return;
}

/*
This is a function used in a SHA1 round.
Compute the xor between op1 and op2 and store the result in res.
res, op1 and op2 are 4 bytes word.
*/
void MySha::u8_xor(u8* res, u8* op1, u8* op2)
{
    u8 i;
    for(i=0x00 ; i < 0x04 ; i++)
        res[i] = op1[i] ^ op2[i];
    return;
}

/*This is a function used in a SHA1 round.*/
void MySha::F(u8* res, u8* X, u8* Y, u8* Z)
{
    u8 i;
    for(i=0x00 ; i < 0x04 ; i++)
        res[i] = ((X[i] & Y[i]) | ((0xFF - X[i]) & Z[i]));
    return;
}

/*This is a function used in a SHA1 round.*/
void MySha::G(u8* res, u8* X, u8* Y, u8* Z)
{
    u8 i;
    for(i=0x00 ; i < 0x04 ; i++)
        res[i] = (X[i] ^ Y[i] ^ Z[i]);
    return;
}

/*This is a function used in a SHA1 round.*/
void MySha::H(u8* res, u8* X, u8* Y, u8* Z)
{
    u8 i;
    for(i=0x00 ; i < 0x04 ; i++)
        res[i] = ((X[i] & Y[i]) | (X[i] & Z[i]) | (Y[i] & Z[i]));
    return;
}

/*
Compute the hash SHA1 of the message.

size is the length of the message in bytes.
result must be an 20 bytes word allocate by caller.
*/
void MySha::compute_sha1(u8* result, u8* message, unsigned long long int size)
{
    u8 i, j, flag=0x00, pad_word;
    u16 i_word, j_word, k_word, temp_word=0x00;

    u8 temp[0x04] = {0x00}, temp_2[0x04] = {0x00}, temp_3[0x04] = {0x00};

    /*Constant values in SHA1*/
    u8 A[0x04] = {0x67, 0x45, 0x23, 0x01};
    u8 B[0x04] = {0xEF, 0xCD, 0xAB, 0x89};
    u8 C[0x04] = {0x98, 0xBA, 0xDC, 0xFE};
    u8 D[0x04] = {0x10, 0x32, 0x54, 0x76};
    u8 E[0x04] = {0xC3, 0xD2, 0xE1, 0xF0};

    u8 AA[0x04] = {0x00}, BB[0x04]= {0x00}, CC[0x04] = {0x00}, DD[0x04] = {0x00}, EE[0x04] = {0x00};
    u8 AAA[0x04] = {0x00}, BBB[0x04] = {0x00}, CCC[0x04] = {0x00}, DDD[0x04] = {0x00}, EEE[0x04] = {0x00};

    u8 K_0[0x04] = {0x5A, 0x82, 0x79, 0x99};
    u8 K_1[0x04] = {0x6E, 0xD9, 0xEB, 0xA1};
    u8 K_2[0x04] = {0x8F, 0x1B, 0xBC, 0xDC};
    u8 K_3[0x04] = {0xCA, 0x62, 0xC1, 0xD6};

    u8 W[0x50][0x20] = {{0x00}};

    u8 size_high = (u8)(size >> 0x0D);

    /*Compute how many 512 bits bloc there are in string*/
    u16 size_bloc = ((size<<3)/ 0x200) + 0x01;

    if(0x1C0 <= ((size<<0x03)%0x200) )
        size_bloc++;

    u8 w[BLOC_MAX][0x10][0x04];

    /*Cut string into 512 bits blocs and store them in MM*/
    for(k_word=0x00 ; k_word < size_bloc ; k_word++){

        for(i_word=0x00 ; i_word < 0x10 ; i_word++){
            for(j_word=0x00 ; j_word < 0x04 ; j_word++){

                /*When message is stored*/
                if(temp_word == size){

                    /*Padding : we append 1*/
                    w[k_word][i_word][j_word] = 0x80;

                    /*We append size (u16 : 2 bytes)*/
                    i_word = 0x0F;
                    j_word = 0x02;

                    /*length in bits (!= bytes)*/
                    size <<= 0x03;

                    w[size_bloc - 0x01][i_word][j_word - 0x01] = size_high;
                    w[size_bloc - 0x01][i_word][j_word] = (u8)(size >> 0x08);
                    w[size_bloc - 0x01][i_word][j_word+0x01] = (u8)(size);

                    flag = 0x01;
                    break;
                }

                /*We append piece of message*/
                w[k_word][i_word][j_word] = message[temp_word];
                temp_word++;
            }

            if(flag == 0x01)
                break;
        }

        if(flag == 0x01)
            break;
    }

    /*We store first values*/
    for(i=0x00 ; i < 0x04 ; i++){
            AA[i] = A[i];
            BB[i] = B[i];
            CC[i] = C[i];
            DD[i] = D[i];
            EE[i] = E[i];
    }

    /*For each 512 bits blocs*/
    for(k_word = 0x00 ; k_word < size_bloc ; k_word++){

        /*Update A B C D*/
        for(i=0x00 ; i < 0x04 ; i++){
            A[i] = AA[i];
            B[i] = BB[i];
            C[i] = CC[i];
            D[i] = DD[i];
            E[i] = EE[i];
        }

        /*We compute W*/
        for(i=0x00 ; i < 0x50 ; i++){
            if(i < 0x10)
                u8_memcpy(W[i], w[k_word][i], 0x04);
            else{

                u8_xor(temp, W[i-0x03], W[i-0x08]);
                u8_xor(temp, temp, W[i-0x0E]);
                u8_xor(temp, temp, W[i-0x10]);
                shift_left(temp_2, temp, 0x01);
                u8_memcpy(W[i], temp_2, 0x04);
            }
        }


        /*Boucle principale*/
        for(i=0x00 ; i < 0x50 ; i++){

            if(i < 0x14){
                add(temp, W[i], K_0);
                add(temp_2, temp, E);
                F(temp, B, C, D);
            }


            else if(i < 0x28){
                add(temp, W[i], K_1);
                add(temp_2, temp, E);
                G(temp, B, C, D);
            }

            else if(i < 0x3C){
                add(temp, W[i], K_2);
                add(temp_2, temp, E);
                H(temp, B, C, D);
            }

            else if(i < 0x50){
                add(temp, W[i], K_3);
                add(temp_2, temp, E);
                G(temp, B, C, D);
            }

            add(temp_3, temp, temp_2);
            shift_left(temp_2, A, 0x05);
            add(temp, temp_2, temp_3);

            u8_memcpy(E, D, 4);
            u8_memcpy(D, C, 4);

            shift_left(temp_2, B, 0x1E);

            u8_memcpy(C, temp_2, 4);
            u8_memcpy(B, A, 4);
            u8_memcpy(A, temp, 4);

        }

        /*Add A with AA etc*/
        add(AAA, AA, A);
        add(BBB, BB, B);
        add(CCC, CC, C);
        add(DDD, DD, D);
        add(EEE, EE, E);

        /*Update AA BB CC DD*/
        for(i=0x00 ; i < 0x04 ; i++){
            AA[i] = AAA[i];
            BB[i] = BBB[i];
            CC[i] = CCC[i];
            DD[i] = DDD[i];
            EE[i] = EEE[i];
        }
    }

    pad_word = 0x00;

    /*To have a result, we have to join AA BB CC DD EE*/
    for(i=0x00 ; i < 0x05 ; i++){
        for(j=0x00 ; j < 0x04 ; j++){

            switch(i%0x05){
                case 0x00 :
                    result[pad_word] = AA[j];
                    break;

                case 0x01 :
                    result[pad_word] = BB[j];
                    break;

                case 0x02 :
                    result[pad_word] = CC[j];
                    break;

                case 0x03 :
                    result[pad_word] = DD[j];
                    break;

                case 0x04 :
                    result[pad_word] = EE[j];
                    break;
            }
            pad_word++;
        }
    }

    return;
}
/*Compute the size of a string. Only used in the main test function.*/
u16 MySha::string_size(char* string)
{
    u16 curr_letter = 0x00;

    if(*string == 0x00)
        return (u16)0x00;

    while(string[curr_letter] != 0x00)
        curr_letter++;

    return curr_letter;
}
/* This function is only used in the main test function.
 * Print a string in a hex format
 * Test function only
 * string must be allocat by caller.
 **/
void MySha::print_hex(u8* string, int size,const char* hashFile)
{
    FILE *hash;

    char pathHashFile[50];
    sprintf(pathHashFile,"../ressources/%s.hash",hashFile);

    hash = fopen(pathHashFile,"w");

    int i;
    u8* tmp = (u8*)calloc(3, sizeof(char));

    for(i=0 ; i < size ; i++){
        sprintf((char*)tmp, "%x", string[i]);

        if(strlen((const char*)tmp) == 2)
            fprintf(hash,"%s", tmp);

        else
            fprintf(hash,"0%s", tmp);
    }

    free(tmp);
    fclose(hash);
    return;
}

int MySha::sha1(const char* plainFile,const char* hashFile)
{
    //We compute size (in bytes) of the string
    u8 result[20] = {0x00};
    //We collect the string from the file
    FILE *plaintext;

    plaintext = fopen(plainFile,"r");
    fseek(plaintext, 0, SEEK_END);
    size_t size = ftell(plaintext);
    rewind(plaintext);

    unsigned char* buff = (unsigned char*)malloc(size*sizeof(unsigned char));
    fread(buff, sizeof(unsigned char), size, plaintext);
    fclose(plaintext);

    //We compute the hash
    compute_sha1(result, (u8*)buff, size);

    print_hex(result, 20, hashFile);

    return 0;
}


#ifdef __cplusplus
}
#endif
