/* BearSSL 0.6 known-answer tests. No TLS connection or entropy claim. */
#include "bearssl.h"
static int equal(const unsigned char *a,const unsigned char *b,unsigned n){
 unsigned diff=0; for(unsigned i=0;i<n;i++)diff|=a[i]^b[i]; return diff==0;
}
__attribute__((section(".entry"),used))
unsigned int tls_platform_probe(void){
 static const unsigned char sha_expected[32]={0xba,0x78,0x16,0xbf,0x8f,0x01,0xcf,0xea,0x41,0x41,0x40,0xde,0x5d,0xae,0x22,0x23,0xb0,0x03,0x61,0xa3,0x96,0x17,0x7a,0x9c,0xb4,0x10,0xff,0x61,0xf2,0x00,0x15,0xad};
 static const unsigned char hmac_expected[32]={0xb0,0x34,0x4c,0x61,0xd8,0xdb,0x38,0x53,0x5c,0xa8,0xaf,0xce,0xaf,0x0b,0xf1,0x2b,0x88,0x1d,0xc2,0x00,0xc9,0x83,0x3d,0xa7,0x26,0xe9,0x37,0x6c,0x2e,0x32,0xcf,0xf7};
 unsigned char out[32],key[20];
 br_sha256_context sha;
 br_hmac_key_context kc;
 br_hmac_context hc;
 br_sha256_init(&sha);br_sha256_update(&sha,"abc",3);br_sha256_out(&sha,out);
 if(!equal(out,sha_expected,32))return 0xBAD00001u;
 for(unsigned i=0;i<20;i++)key[i]=0x0b;
 br_hmac_key_init(&kc,&br_sha256_vtable,key,20);
 br_hmac_init(&hc,&kc,32);
 br_hmac_update(&hc,"Hi There",8);br_hmac_out(&hc,out);
 if(!equal(out,hmac_expected,32))return 0xBAD00002u;
 return 0x544c5332u;
}
#ifdef HOST_TEST
#include <stdio.h>
int main(void){unsigned r=tls_platform_probe();printf("BearSSL SHA-256/HMAC self-test: %08X\n",r);return r!=0x544c5332u;}
#endif
