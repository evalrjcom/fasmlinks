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
static unsigned int tls_platform_probe(void){
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
/* Diagnostic live record interface. Empty trust store deliberately prevents
 * authentication. Never release application plaintext or send HTTP in this build.
 * RDRAND is conditional: without advertised, successful hardware entropy, stop.
 * Emulator implementations must be independently trusted before production use.
 */
#ifndef HOST_TEST
#include "trust_anchors.h"
struct tls_mailbox { unsigned char *ptr; unsigned len; };
static unsigned live_enabled;
static char live_host[74];
static int live_entropy(unsigned char seed[32])
{
 unsigned a=1,b,c,d;
 __asm__ volatile("cpuid":"+a"(a),"=b"(b),"=c"(c),"=d"(d));
 if(!(c & (1u<<30)))return 0;
 for(unsigned i=0;i<8;i++){
  unsigned value=0; unsigned char ok=0;
  for(unsigned j=0;j<10;j++){
   __asm__ volatile("rdrand %0; setc %1":"=r"(value),"=qm"(ok)::"cc");
   if(ok)break;
  }
  if(!ok)return 0;
  for(unsigned j=0;j<4;j++)seed[4*i+j]=(unsigned char)(value>>(8*j));
 }
 return 1;
}
/* Guest RTC must be set to UTC. Fail closed on invalid date/time. */
static unsigned char cmos(unsigned char reg){
 unsigned char v; __asm__ volatile("outb %0,$0x70"::"a"(reg));__asm__ volatile("inb $0x71,%0":"=a"(v));return v;
}
static unsigned decode(unsigned v,int binary){return binary?v:((v>>4)*10+(v&15));}
static unsigned rtc_days(unsigned *seconds){
 unsigned char a[7],b[7];const unsigned char regs[7]={0,2,4,7,8,9,0x0b};
 for(unsigned tries=0;tries<16;tries++){
  if(cmos(0x0a)&128)continue;
  for(unsigned i=0;i<7;i++)a[i]=cmos(regs[i]);
  if(cmos(0x0a)&128)continue;
  for(unsigned i=0;i<7;i++)b[i]=cmos(regs[i]);
  if(!equal(a,b,7))continue;
  if(!(a[6]&2))return 0;
  int binary=(a[6]&4)!=0;
  if(!binary){for(unsigned i=0;i<6;i++)if((a[i]&15)>9||(a[i]>>4)>9)return 0;}
  unsigned sec=decode(a[0],binary),min=decode(a[1],binary),hour=decode(a[2],binary);
  unsigned day=decode(a[3],binary),month=decode(a[4],binary),year=2000+decode(a[5],binary);
  if(year<2024||year>2099||month<1||month>12||day<1||hour>23||min>59||sec>59)return 0;
  unsigned leap=(year%4==0&&(year%100!=0||year%400==0));
  static const unsigned char md[12]={31,28,31,30,31,30,31,31,30,31,30,31};
  if(day>md[month-1]+(month==2?leap:0))return 0;
  unsigned days=365*year+(year+3)/4-(year+99)/100+(year+399)/400;
  for(unsigned i=1;i<month;i++)days+=md[i-1]+(i==2?leap:0);
  *seconds=hour*3600+min*60+sec;return days+day-1;
 }
 return 0;
}
static void wipe(unsigned char *p,unsigned n){
 volatile unsigned char *v=p;while(n--)*v++=0;
}
__attribute__((section(".entry"),used))
unsigned tls_dispatch(unsigned op,struct tls_mailbox *m,unsigned count)
{
 br_ssl_engine_context *e=&test_client.eng;
 size_t n=0; unsigned char *p;
 if(op==0){live_enabled=0;return tls_platform_probe();}
 if(op==1){
  unsigned char seed[32];
  live_enabled=0;
  if(!live_entropy(seed)){wipe(seed,sizeof seed);return 0xBAD00101u;}
  /* No application bytes until BearSSL has authenticated the server. */
  if(!m->ptr||!m->len||m->len>=sizeof live_host||!TAs_NUM){wipe(seed,sizeof seed);return 0xBAD00108u;}
  for(unsigned i=0;i<m->len;i++)live_host[i]=(char)m->ptr[i];
  live_host[m->len]=0;
  unsigned seconds,days=rtc_days(&seconds);
  if(!days){wipe(seed,sizeof seed);return 0xBAD00109u;}
  br_ssl_client_init_full(&test_client,&test_x509,TAs,TAs_NUM);
  br_x509_minimal_set_time(&test_x509,days,seconds);
  br_ssl_engine_set_versions(e,BR_TLS12,BR_TLS12);
  br_ssl_engine_set_buffer(e,test_buffer,sizeof test_buffer,1);
  br_ssl_engine_inject_entropy(e,seed,sizeof seed);
  wipe(seed,sizeof seed);
  if(!br_ssl_client_reset(&test_client,live_host,0))return 0xBAD00102u;
  live_enabled=1;return 1;
 }
 if(op==8){live_enabled=0;return 0;}
 if(!live_enabled)return 0;
 switch(op){
 case 2:return br_ssl_engine_current_state(e);
 case 3: /* SENDREC span */
 case 5: /* RECVREC span */
  p=op==3?br_ssl_engine_sendrec_buf(e,&n):br_ssl_engine_recvrec_buf(e,&n);
  m->ptr=p;m->len=(unsigned)n;return (unsigned)n;
 case 4:
 case 6:
  p=op==4?br_ssl_engine_sendrec_buf(e,&n):br_ssl_engine_recvrec_buf(e,&n);
  if(!p||!count||count>n)return 0;
  if(op==4)br_ssl_engine_sendrec_ack(e,count);else br_ssl_engine_recvrec_ack(e,count);
  return 1;
 case 9:
 case 11:
  p=op==9?br_ssl_engine_sendapp_buf(e,&n):br_ssl_engine_recvapp_buf(e,&n);
  m->ptr=p;m->len=(unsigned)n;return (unsigned)n;
 case 10:
 case 12:
  p=op==10?br_ssl_engine_sendapp_buf(e,&n):br_ssl_engine_recvapp_buf(e,&n);
  if(!p||!count||count>n)return 0;
  if(op==10){br_ssl_engine_sendapp_ack(e,count);br_ssl_engine_flush(e,0);}
  else br_ssl_engine_recvapp_ack(e,count);
  return 1;
 case 7:return br_ssl_engine_last_error(e);
 default:return 0;
 }
}
#endif
#ifdef HOST_TEST
#include <stdio.h>
int main(void){unsigned r=tls_platform_probe();printf("BearSSL SHA-256/HMAC/ClientHello self-test: %08X\n",r);return r!=0x544c5333u;}
#endif
