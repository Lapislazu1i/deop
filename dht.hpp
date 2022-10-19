#pragma once
#include <stdio.h>
#include <string.h>
#include <openssl/dh.h>

int dht()
{
    DH* d1;
    DH* d2;
    BIO* b;
    int ret, size, i, len1, len2;
    char sharekey1[128] = {0};
    char sharekey2[128] = {0};

    d1 = DH_new();
    d2 = DH_new();

    ret = DH_generate_parameters_ex(d1, 64, DH_GENERATOR_2, NULL);
    if(ret != 1) {
        printf("dh generate parameters ex err.n");
        return -1;
    }
    ret = DH_check(d1, &i);
    if(ret != 1) {
        printf("dh check err.\n");
        if(i & DH_CHECK_P_NOT_PRIME) {
            printf("p value is not prime.\n");
        }
        if(i & DH_CHECK_P_NOT_SAFE_PRIME) {
            printf("p value is not safe prime.\n");
        }
        if(i & DH_UNABLE_TO_CHECK_GENERATOR) {
            printf("unable to check the generator.\n");
        }
        if(i & DH_NOT_SUITABLE_GENERATOR) {
            printf("the g value is not a generator.\n");
        }
        return -1;
    }

    printf("dh paraeters appear to be ok.\n");
    
    size = DH_size(d1);
    printf("dh key1 size: %d.\n", size);

    ret = DH_generate_key(d1);
    if(ret != 1) {
        printf("dh generator key err.\n");
        return -1;
    }


}
