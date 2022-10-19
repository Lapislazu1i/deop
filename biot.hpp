#pragma once
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <openssl/asn1.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int mem_bio()
{
    BIO *b = NULL;
    int len = 0;
    char *out = NULL;
    b = BIO_new(BIO_s_mem());
    len = BIO_write(b, "openssl", 4);
    len = BIO_printf(b, "%s", "zcp");
    len = BIO_ctrl_pending(b);
    out = (char *)OPENSSL_malloc(len);
    len = BIO_read(b, out, len);
    printf("mem_bui- out: %s, len: %d.\n", out, len);
    OPENSSL_free(out);
    BIO_free(b);
    // printf("mem_bui- out: %s, len: %d.\n", out, len);
    return 0;
}

int file_bio()
{
    BIO *b = NULL;
    int len = 0, outlen = 0;
    char *out = NULL;
    b = BIO_new_file("bf.txt", "w");
    len = BIO_write(b, "openssl", 4);
    len = BIO_printf(b, "%s", "zcp");
    BIO_free(b);
    b = BIO_new_file("bf.txt", "r");
    len = BIO_pending(b);
    len = 50;
    out = (char *)OPENSSL_malloc(len);
    len = 1;
    while (len > 0)
    {
        len = BIO_read(b, out + outlen, 1);
        outlen += len;
    }
    printf("file bio- str: %s, len: %d.\n", out, outlen);
    BIO_free(b);
    free(out);
    return 0;
}

int sockt_bio()
{
    BIO *b = NULL, *c = NULL;
    int sock, ret, len;
    char *addr = NULL;
    char *out[80] = {0};
    return 0;
}

int md_bio()
{
    BIO *bmd = NULL;
    BIO *b = NULL;
    const EVP_MD *md = EVP_md5();
    int len = 0;
    char tmp[20] = {0};
    bmd = BIO_new(BIO_f_md());
    BIO_set_md(bmd, md);
    b = BIO_new(BIO_s_null());
    b = BIO_push(bmd, b);
    len = BIO_write(b, "openssl", 7);
    len = BIO_gets(b, tmp, sizeof(tmp));
    BIO_free(b);
    printf("md_bio- str: %x, len: %d.\n", tmp, 20);
    return 0;
}

int cipher_desecb_bio()
{
    const char *input = "openssl";
    BIO *bc = NULL;
    BIO *b = NULL;
    const EVP_CIPHER *c = EVP_des_ecb();
    int len = 0;
    int i = 0;
    char tmp[1024] = {0};
    unsigned char key[8] = {0};
    unsigned char iv[8] = {0};
    for (i = 0; i < 8; ++i)
    {
        memset(&key[i], i + 1, 1);
        memset(&iv[i], i + 1, 1);
    }
    // set encoder
    bc = BIO_new(BIO_f_cipher());
    BIO_set_cipher(bc, c, key, iv, 1);
    b = BIO_new(BIO_s_null());
    b = BIO_push(bc, b);
    len = BIO_write(b, input, strlen(input));
    len = BIO_read(b, tmp, 1024);
    BIO_free_all(bc);
    printf("cipher_desecb_bio- enstr: %s, len: %d.\n", tmp, strlen(tmp));

    // set decoder
    BIO *bdec = NULL;
    BIO *bd = NULL;
    const EVP_CIPHER *cd = EVP_des_ecb();
    bdec = BIO_new(BIO_f_cipher());
    BIO_set_cipher(bdec, cd, key, iv, 0);
    bd = BIO_new(BIO_s_null());
    bd = BIO_push(bdec, bd);
    len = BIO_write(bdec, tmp, len);
    len = BIO_read(bdec, tmp, 1024);
    BIO_free(bdec);

    // the decrypted data is one bit higher than previous data.
    tmp[strlen(input)] = 0;
    printf("cipher_desecb_bio- destr: %s, len: %d.\n", tmp, strlen(tmp));
    return 0;
}

int ssl_bio()
{
    BIO *sbio;
    BIO *out;
    int len = 0;
    char tmpbuf[1024] = {0};
    SSL_CTX *ctx;
    SSL *ssl;
    SSLeay_add_ssl_algorithms();
    OpenSSL_add_all_algorithms();
    ctx = SSL_CTX_new(SSLv23_client_method());
    sbio = BIO_new_ssl_connect(ctx);
    BIO_get_ssl(sbio, &ssl);
    if (!ssl)
    {
        fprintf(stderr, "can not find locate ssl pointer.\n");
        return -1;
    }
    SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);
    BIO_set_conn_hostname(sbio, "cn.bing.com:https");
    out = BIO_new_fp(stdout, BIO_NOCLOSE);
    BIO_printf(out, "connecting...\n");
    if (BIO_do_connect(sbio) <= 0)
    {
        fprintf(stderr, "error connecting to server.\n");
        return -1;
    }
    if (BIO_do_handshake(sbio) <= 0)
    {
        fprintf(stderr, "error establishing SSL connection.\n");
        return -1;
    }
    BIO_puts(sbio, "GET /HTTP/1.1 \r\n");
    while (1)
    {
        len = BIO_read(sbio, tmpbuf, 1024);
        if (len <= 0)
        {
            break;
        }
        BIO_write(out, tmpbuf, len);
    }
    BIO_free_all(sbio);
    BIO_free(out);
    printf("\n");
    return 0;
}

int ans1_bio()
{
    int ret, len, indent;
    BIO *bp;
    char *pp;
    char buf[5000];
    FILE *fp;
    bp = BIO_new(BIO_s_file());
    BIO_set_fp(bp, stdout, BIO_NOCLOSE);
    fp = fopen("der.cer", "rb");
    len = fread(buf, 1, 5000, fp);

    fclose(fp);
    pp = buf;
    indent = 5;
    ret = BIO_dump_indent(bp, pp, len, indent);
    BIO_free(bp);
    return 0;
}

int base64t_bio()
{
    BIO *bio, *b64;
    char message[] = "hello world \n";
    char buf[1024] = {0};
    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);
    BIO_write(bio, message, strlen(message));
    int retlen = BIO_read(b64, buf, 1024);
    printf("base64 bio- str: %s, len: %d.\n", buf, retlen);
    // BIO_flush(bio);
    retlen = BIO_write(b64, buf, retlen);
    BIO_read(b64, buf, retlen);
    printf("base64 bio- str: %s, len: %d.\n", buf, strlen(buf));
    BIO_free_all(bio);
}

void base64_encode_to_output()
{
    printf("strat base64_encode_to_output\n");
}

void base64_decode_to_output()
{
    printf("start base64_decode_to_output\n");
    BIO *bio, *b64, *bio_out;
    char inbuf[512];
    int inlen;
    char message[] = "Hello World \n";
    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new_fp(stdin, BIO_NOCLOSE);
    bio_out = BIO_new_fp(stdout, BIO_NOCLOSE);
    bio = BIO_push(b64, bio);
    while ((inlen = BIO_read(bio, inbuf, strlen(message))) > 0)
        BIO_write(bio_out, inbuf, inlen);
    BIO_free_all(bio);
}