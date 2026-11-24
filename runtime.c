/* Minimal freestanding C runtime; compile with -fno-builtin. */
#include <stddef.h>
void *memcpy(void *d,const void *s,size_t n){unsigned char *a=d;const unsigned char *b=s;while(n--)*a++=*b++;return d;}
void *memset(void *d,int c,size_t n){unsigned char *a=d;while(n--)*a++=(unsigned char)c;return d;}
void *memmove(void *d,const void *s,size_t n){unsigned char *a=d;const unsigned char *b=s;if((size_t)a<(size_t)b){for(size_t i=0;i<n;i++)a[i]=b[i];}else{while(n){--n;a[n]=b[n];}}return d;}
int memcmp(const void *a,const void *b,size_t n){const unsigned char *x=a,*y=b;while(n--){if(*x!=*y)return (int)*x-(int)*y;++x;++y;}return 0;}

/* FIX 0.8.1: BearSSL's SNI and X.509 parsers need strlen.
 * Standard C contract; caller supplies a NUL-terminated string.
 */
size_t strlen(const char *s)
{
    const char *p = s;
    while (*p != '\0') ++p;
    return (size_t)(p - s);
}
