// -*- coding: utf-8 -*-

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/sha.h>
#include <time.h>
#include "gmp.h"


#define LG_BLOC 128
#define LG_HASH SHA_DIGEST_LENGTH

typedef unsigned char uchar;

void copyInFrom (uchar* a, uchar *b, int s, int n){
  for(int i = s ; i < n ; i++ ){
    a[i]=b[i-s];
  }
}

void printSTR (unsigned char* a, int t){

  for(int i = 0; i < t; i++){
    printf("%02x",a[i]);
  }
  printf("\n");
}

unsigned char* concatSTR (uchar * a , int ta, uchar * b, int tb){
  
  uchar* newSTR = malloc((ta+tb)*sizeof(unsigned char));
  if(newSTR == NULL){
    fprintf(stderr,"erreur malloc\n");
  }
  int i = 0;
  for(i = 0; i< ta; i++){
    newSTR[i]=a[i];
  }
  for(i = ta; i< ta+tb; i++){
    newSTR[i]=b[i-ta];
  }
  return newSTR;
}

int main(void) {

  mpz_t e, n, d;
  mpz_init(n);         // Le module de la clef publique
  mpz_init(e);         // L'exposant de la clef publique
  mpz_init(d);         // L'exposant de la clef privée
  mpz_set_str(n,
	      "00af7958cb96d7af4c2e6448089362\
	      31cc56e011f340c730b582a7704e55\
	      9e3d797c2b697c4eec07ca5a903983\
	      4c0566064d11121f1586829ef6900d\
	      003ef414487ec492af7a12c34332e5\
	      20fa7a0d79bf4566266bcf77c2e007\
	      2a491dbafa7f93175aa9edbf3a7442\
	      f83a75d78da5422baa4921e2e0df1c\
	      50d6ab2ae44140af2b", 16);
  mpz_set_str(e, "10001", 16);
  mpz_set_str(d,
	      "35c854adf9eadbc0d6cb47c4d11f9c\
	      b1cbc2dbdd99f2337cbeb2015b1124\
	      f224a5294d289babfe6b483cc253fa\
	      de00ba57aeaec6363bc7175fed20fe\
	      fd4ca4565e0f185ca684bb72c12746\
	      96079cded2e006d577cad2458a5015\
	      0c18a32f343051e8023b8cedd49598\
	      73abef69574dc9049a18821e606b0d\
	      0d611894eb434a59", 16);

  gmp_printf("Module          (N): %Zd\n", n);
  gmp_printf("Exposant public (E): %Zd\n", e);
  gmp_printf("Exposant privé  (D): %Zd\n", d);
 
  const uchar message[6] = { 0x41, 0x6C, 0x66, 0x72, 0x65, 0x64 } ;
  printf("Message clair          : ");
  for (int i = 0 ; i<sizeof(message) ; i++) printf("%02X", message[i]);
  printf("\n");
  if(sizeof(message)>=87){
    printf("message trop long pour un chiffrement RSA 1024 bits \n");
    exit(0);
  }

  uchar bloc[LG_BLOC];
  for (int i = 0 ; i < LG_BLOC ; i++) bloc[i] = 0;
  int i ;
  for ( i = 0 ; i < sizeof(message) ; i++) {
    bloc[128-sizeof(message)+i] = message[i];
  }
  bloc[128-sizeof(message)-1]= 0x01;

  uchar hash[LG_HASH];
  uchar voidChain[] = {};
  SHA1(voidChain, sizeof(voidChain), hash);
  for(int i = 0 ; i < sizeof(hash); i++){
    bloc[i+1+LG_HASH]=hash[i];
  }

  uchar **tab = malloc(sizeof(unsigned char*)*7);
  for(int s = 0; s<7;s++){
    tab[s] = malloc(sizeof(unsigned char)*4);
  }
  for(int i = 0 ; i < 7 ; i++){
    tab[i][0]=0x00;
    tab[i][1]=0x00;
    tab[i][2]=0x00;
    tab[i][3]=(uchar)i;
  }

  srand(time(0));
  uchar seed[LG_HASH];
  printf(" seed : ");
  for(int i = 0 ; i<LG_HASH ; i++){
    int t = rand()%256;
    seed[i]= (unsigned char)t ;
    printf("%02x",seed[i]);
  }
  printf("\n");

  int DBmask_length = 128-LG_HASH-1;
  int nbDBDigest = DBmask_length / LG_HASH;
  int troncatedDigest = DBmask_length % LG_HASH;

  uchar *DBmask = malloc(sizeof(char)*DBmask_length);

  uchar digest[LG_HASH];

  int p = 0;
  for(p = 0 ; p < nbDBDigest ; p++){
    copyInFrom(DBmask,SHA1(concatSTR(seed,LG_HASH,tab[p],4), 24, digest),p*LG_HASH,(p+1)*LG_HASH);
  }
  if(troncatedDigest >= 1){
    copyInFrom(DBmask,SHA1(concatSTR(seed,LG_HASH,tab[p],4), 24, digest),p*LG_HASH,(p*LG_HASH)+troncatedDigest);
  }

  for(int i = 0 ;i<DBmask_length;i++){
    bloc[LG_BLOC-DBmask_length+i]=bloc[LG_BLOC-DBmask_length-1+i]^DBmask[i];
  }

  uchar seedMask[LG_HASH];
  copyInFrom(seedMask,SHA1(concatSTR(DBmask,107,tab[0],4), 107+4, digest),0,LG_HASH);

  for(int i = 0 ; i < LG_HASH;i++){
    bloc[LG_BLOC-DBmask_length-LG_HASH+i]=seed[i]^seedMask[i];
  }

  mpz_t m;
  mpz_init(m);                      // Le message clair sous forme d'entier
  mpz_set_ui(m, 0UL);
  for(int i = 0; i < sizeof(bloc) ; i++){
    mpz_mul_ui(m, m, (unsigned int) 256);
    mpz_add_ui(m, m, (unsigned int) bloc[i]);
  }
  gmp_printf("m = %Zd\n", m);       // en décimal
  gmp_printf("m = 0x%0256Zx\n", m); // en hexadécimal (sur 256 caractères)

  mpz_t chiffre;
  mpz_init(chiffre);              
  mpz_powm(chiffre, m, e, n);
  gmp_printf("m^e mod n = %Zd\n", chiffre);  

  mpz_t dechiffre;
  mpz_init(dechiffre);        
  mpz_powm(dechiffre, chiffre, d, n);
  gmp_printf("(m^e)^d mod n = %Zd\n", dechiffre);

  free(DBmask);
  mpz_clear(m);
  mpz_clear(chiffre);
  mpz_clear(dechiffre);
  mpz_clear(n);
  mpz_clear(e);
  mpz_clear(d);
  exit(EXIT_SUCCESS);
} 