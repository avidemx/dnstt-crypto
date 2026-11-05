#include "dnstt_crypto.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int unhex(const char *s,unsigned char *out,size_t cap,size_t *n){
 size_t i,l=strlen(s); if(l%2||l/2>cap)return -1;
 for(i=0;i<l/2;i++){unsigned x; if(sscanf(s+2*i,"%2x",&x)!=1)return -1;out[i]=(unsigned char)x;}
 *n=l/2;return 0;
}
static void hexout(const unsigned char *p,size_t n){size_t i;for(i=0;i<n;i++)printf("%02x",p[i]);putchar('\n');}
static void usage(void){fprintf(stderr,"Usage:\n  dnstt-crypto blake2s HEX\n  dnstt-crypto hmac-blake2s KEYHEX DATAHEX\n  dnstt-crypto hkdf-blake2s IKMHEX SALTHEX INFOHEX LENGTH\n  dnstt-crypto x25519-public PRIVATEHEX\n  dnstt-crypto x25519 PRIVATEHEX PEER_PUBLICHEX\n  dnstt-crypto aead-encrypt KEYHEX NONCEHEX AADHEX PLAINTEXTHEX\n  dnstt-crypto aead-decrypt KEYHEX NONCEHEX AADHEX CIPHERTEXTHEX TAGHEX\n");}
int main(int argc,char **argv){
 unsigned char a[65536],b[65536],c[65536],d[65536],out[65552],tag[16];size_t al=0,bl=0,cl=0,dl=0;int rc=-1;
 if(argc<3){usage();return 2;}
 if(!strcmp(argv[1],"blake2s")&&argc==3){if(!unhex(argv[2],a,sizeof a,&al))rc=dnstt_blake2s(out,a,al);if(!rc)hexout(out,32);}
 else if(!strcmp(argv[1],"hmac-blake2s")&&argc==4){if(!unhex(argv[2],a,sizeof a,&al)&&!unhex(argv[3],b,sizeof b,&bl))rc=dnstt_hmac_blake2s(out,a,al,b,bl);if(!rc)hexout(out,32);}
 else if(!strcmp(argv[1],"hkdf-blake2s")&&argc==6){char *e;unsigned long n=strtoul(argv[5],&e,10);if(*e||n>sizeof out)return 2;if(!unhex(argv[2],a,sizeof a,&al)&&!unhex(argv[3],b,sizeof b,&bl)&&!unhex(argv[4],c,sizeof c,&cl))rc=dnstt_hkdf_blake2s(out,n,a,al,b,bl,c,cl);if(!rc)hexout(out,n);}
 else if(!strcmp(argv[1],"x25519-public")&&argc==3){if(!unhex(argv[2],a,sizeof a,&al)&&al==32)rc=dnstt_x25519_public(out,a);if(!rc)hexout(out,32);}
 else if(!strcmp(argv[1],"x25519")&&argc==4){if(!unhex(argv[2],a,sizeof a,&al)&&al==32&&!unhex(argv[3],b,sizeof b,&bl)&&bl==32)rc=dnstt_x25519(out,a,b);if(!rc)hexout(out,32);}
 else if(!strcmp(argv[1],"aead-encrypt")&&argc==6){if(!unhex(argv[2],a,sizeof a,&al)&&al==32&&!unhex(argv[3],b,sizeof b,&bl)&&bl==12&&!unhex(argv[4],c,sizeof c,&cl)&&!unhex(argv[5],d,sizeof d,&dl))rc=dnstt_chachapoly_encrypt(out,tag,a,b,c,cl,d,dl);if(!rc){hexout(out,dl);hexout(tag,16);}}
 else if(!strcmp(argv[1],"aead-decrypt")&&argc==7){size_t tl;if(!unhex(argv[2],a,sizeof a,&al)&&al==32&&!unhex(argv[3],b,sizeof b,&bl)&&bl==12&&!unhex(argv[4],c,sizeof c,&cl)&&!unhex(argv[5],d,sizeof d,&dl)&&!unhex(argv[6],tag,sizeof tag,&tl)&&tl==16)rc=dnstt_chachapoly_decrypt(out,a,b,c,cl,d,dl,tag);if(!rc)hexout(out,dl);}
 else {usage();return 2;}
 if(rc){fprintf(stderr,"dnstt-crypto: operation failed\n");return 1;}return 0;
}
