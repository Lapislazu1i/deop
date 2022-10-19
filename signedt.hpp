#pragma once
#include <stdio.h>
#include <string.h>
#include <openssl/md5.h>
#include <openssl/sha.h>

void print_x16(unsigned char *in, size_t inlen)
{
    for (size_t i = 0; i < inlen; ++i)
    {
        printf("%02x ", in[i]);
    }
    printf("\n");
}

int signedt()
{
    unsigned char in[] = "3dsferyewyrtetegvbzVEgarhaggavxcv";

    unsigned char out[20];

    size_t n;

    int i;

    n = strlen((const char *)in);

    MD5(in, n, out);

    printf("\n\nMD5 digest result :\n");

    for (i = 0; i < 16; i++)
    {

        printf("%x ", out[i]);
    }

    SHA1(in, n, out);

    printf("\n\nSHA digest result :\n");

    for (i = 0; i < 20; i++)
    {

        printf("%x ", out[i]);
    }

    SHA1(in, n, out);

    printf("\n\nSHA1 digest result :\n");

    for (i = 0; i < 20; i++)
    {

        printf("%x ", out[i]);
    }

    SHA256(in, n, out);

    printf("\n\nSHA256 digest result :\n");

    for (i = 0; i < 32; i++)
    {

        printf("%x ", out[i]);
    }

    printf("\n");

    return 0;
}