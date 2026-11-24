/* Freestanding ABI probe only; no TLS library linked. */
typedef unsigned int u32;
__attribute__((section(".entry"),used)) u32 tls_platform_probe(void) { return 0x544c5331u; }
