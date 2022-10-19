#pragma once
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <openssl/asn1.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <iostream>

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

int base64_to_f()
{
    FILE* fp;
    fp = fopen("base.txt", "wr");
    BIO* bio=NULL;
	BIO* biofile=NULL;
	char* readstr=NULL;
	char mydata[]= "this is my test"; //要进行编码的字符
	bio=BIO_new(BIO_f_base64());//filter类型，对输入的信息进行base64编码
	biofile=BIO_new_fp(stdout,BIO_NOCLOSE);//我的另外一个测试，输出到屏幕，标准的输入输出
    // biofile = BIO_new_fp(fp, BIO_CLOSE);
	// biofile=BIO_new(BIO_s_file());//定义的一个文件输出
	// BIO_write_filename(biofile,"123.txt");//输出的目的
	if(bio)
	{
	    BIO_push(bio,biofile);//开始连接两个BIO
	    BIO_write(bio,mydata,sizeof(mydata));//向连接完毕的BIO写入数据
	    BIO_flush(bio);//这个很重要，如果没有这个，就无法把信息写到文件或者打印到计算机屏幕上，作用是把BIO内部的数据读出来
	}
	BIO_free_all(biofile);//释放
	// BIO_free(bio);
	// BIO_free(biofile);
	printf("ok\n");
	return 0;
}
using namespace std;
int Base64Encode(const unsigned char* in, int len, char* out_base64)
{
    if (!in || len <= 0 || !out_base64)
        return 0;
    //内存源 source
    auto mem_bio = BIO_new(BIO_s_mem());
    if (!mem_bio)return 0;

    //base64 filter
    auto b64_bio = BIO_new(BIO_f_base64());
    if (!b64_bio)
    {
        BIO_free(mem_bio);
        return 0;
    }

    //形成BIO链
    //b64-mem
    BIO_push(b64_bio, mem_bio);
    //超过64字节不添加换行（\n）,编码的数据在一行中
    // 默认结尾有换行符\n 超过64字节再添加\n
    BIO_set_flags(b64_bio, BIO_FLAGS_BASE64_NO_NL);
    
    // 写入到base64 filter 进行编码，结果会传递到链表的下一个节点
    // 到mem中读取结果(链表头部代表了整个链表)
    // BIO_write 编码 3字节=》4字节  不足3字节补充0 和 =
    // 编码数据每64字节（不确定）会加\n 换行符
    int re = BIO_write(b64_bio, in, len);
    if (re <= 0)
    {
        //情况整个链表节点
        BIO_free_all(b64_bio);
        return 0;
    }

    //刷新缓存，写入链表的mem
    BIO_flush(b64_bio);

    int outsize = 0;
    //从链表源内存读取
    BUF_MEM* p_data = 0;
    BIO_get_mem_ptr(b64_bio, &p_data);
    if (p_data)
    {
        memcpy(out_base64, p_data->data, p_data->length);
        outsize = p_data->length;
    }
    BIO_free_all(b64_bio);
    return outsize;
}

int Base64Decode(const char* in, int len, unsigned char* out_data)
{
    if (!in || len <= 0 || !out_data)
        return 0;
    //内存源 （密文）
    auto mem_bio = BIO_new_mem_buf(in, len);
    if (!mem_bio)return 0;
    //base64 过滤器
    auto b64_bio = BIO_new(BIO_f_base64());
    if (!b64_bio)
    {
        BIO_free(mem_bio);
        return 0;
    }
    //形成BIO链
    BIO_push(b64_bio, mem_bio);

    //默认读取换行符做结束
    //设置后编码中如果有\n会失败
    BIO_set_flags(b64_bio, BIO_FLAGS_BASE64_NO_NL);

    //读取 解码 4字节转3字节
    size_t size = 0;
    BIO_read_ex(b64_bio, out_data,len,&size);
    BIO_free_all(b64_bio);
    return size;

    

}

int base64_bio_f_test()
{
    using namespace std;
    cout << "Test  openssl BIO base64!" << endl;
    
    unsigned char data[] = "测试base64数据0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789";
    int len = sizeof(data);
    char out[4096] = { 0 };
    unsigned char out2[4096] = { 0 };
    cout <<"source:"<< data << endl;
    int re = Base64Encode(data, len, out);
    if (re > 0)
    {
        //ncode:[suLK1GJhc2U2NMr9vt0A]
        out[re] = '\0';
        cout << "encode:["<<out<<"]" << endl;
    }
    re = Base64Decode(out, re, out2);
    cout <<"decode:"<< out2 << endl;
    return 0;
}

