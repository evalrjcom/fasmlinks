/* BearSSL 0.6 known-answer tests. No TLS connection or entropy claim. */
#include "bearssl.h"
/* Offline-only TLS context. No trust anchors or network transport yet.
 * These contexts and the deterministic test seed never service live traffic.
 * A real client must use independent secure entropy and trusted roots.
 */
static br_ssl_client_context test_client;
static br_x509_minimal_context test_x509;
static unsigned char test_buffer[BR_SSL_BUFSIZE_BIDI];
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
 /* Exercise actual TLS engine initialization and ClientHello record creation.
  * Fixed entropy is strictly a local test fixture, not a usable TLS session.
  */
 static const unsigned char fixture[32]={1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32};
 size_t len=0;
 unsigned char *record;
 br_ssl_client_init_full(&test_client,&test_x509,0,0);
 br_ssl_engine_set_versions(&test_client.eng,BR_TLS12,BR_TLS12);
 br_ssl_engine_set_buffer(&test_client.eng,test_buffer,sizeof test_buffer,1);
 br_ssl_engine_inject_entropy(&test_client.eng,fixture,sizeof fixture);
 if(!br_ssl_client_reset(&test_client,"example.com",0))return 0xBAD00003u;
 if(!(br_ssl_engine_current_state(&test_client.eng)&BR_SSL_SENDREC))return 0xBAD00004u;
 record=br_ssl_engine_sendrec_buf(&test_client.eng,&len);
 if(!record||len<9||record[0]!=22||record[5]!=1)return 0xBAD00005u;
 /* Never acknowledge/send this record; no live session is exposed. */
 return 0x544c5333u;
}
#ifdef HOST_TEST
#include <stdio.h>
int main(void){unsigned r=tls_platform_probe();printf("BearSSL SHA-256/HMAC/ClientHello self-test: %08X\n",r);return r!=0x544c5333u;}
#endif
