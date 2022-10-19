#pragma
#include <stdio.h>
#include <string.h>
#include <openssl/rsa.h>

int rsat()
{
    printf("\nRSA_generate_key_ex TESTING...\n\n");
    RSA *rsa = RSA_new();
    int ret = 0;
    BIGNUM *bne=BN_new();
    ret=BN_set_word(bne,RSA_F4);
    ret = RSA_generate_key_ex(rsa,1024,bne,NULL);
    FILE* fp;
    fp = fopen("rsakey.txt", "wr");
    RSA_print_fp(stdout, rsa, 0);
    RSA_print_fp(fp, rsa, 0);
    unsigned char plain[128]="Hello world!";
    unsigned char cipper[128]={0};
    unsigned char newplain[128]={0};
    size_t outl;
    size_t outl2;
    printf("%s\n", plain);
    for(int i =0;i<strlen((char*)plain);i++){
        printf("%02x ",plain[i]);
    }
    printf("\n---------------\n");
    outl=RSA_public_encrypt(strlen((char*)plain),plain,cipper,rsa,RSA_PKCS1_OAEP_PADDING);
    for(int i =0;i<outl;i++){
        printf("%02x ",cipper[i]);
        if((i+1)%10 ==0) printf("\n");
    }
    printf("\n");
    outl2=RSA_private_decrypt(outl,cipper,newplain,rsa,RSA_PKCS1_OAEP_PADDING);
    printf("-----------------\n%s\n", newplain);
    for(int i =0;i<outl2;i++) {
        printf("%02x ",newplain[i]);
    }
    printf("\n");
    return 0;
}