// -*- coding: utf-8 -*-

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include "gmp.h"

// LG_MAX est la longueur maximale du texte clair (en nombre de caractères ASCII)
#ifndef LG_MAX
#define LG_MAX 10
#endif

typedef unsigned char uchar;

const uchar message[LG_MAX+1] = "Alfred" ;
uchar *message_dechiffre ;

/* Déclaration et initialisation des variables globales GMP */
mpz_t code, code_chiffre, code_dechiffre, e, n, d;

int est_probablement_premier(mpz_t n)
{
  if(mpz_probab_prime_p(n,25))
    return 1;
  return 0;			     
}

void fabrique(void){
  mpz_t p, q;
  mpz_init(p); mpz_init(q);

  gmp_randstate_t randState;
  gmp_randinit_default(randState);
  mpz_t seed;
  mpz_init(seed);
  mpz_set_ui(seed, time(0));

  gmp_randseed(randState, seed);
  mpz_urandomb(p, randState, 513);
  mpz_urandomb(q, randState, 513);
  
  int tmp = est_probablement_premier(p);
  while(tmp == 0){
    mpz_urandomb(p, randState, 513);
    tmp = est_probablement_premier(p);
  }
  int tmp2 = est_probablement_premier(q);
  while(tmp2 == 0){
    mpz_urandomb(q, randState, 513);
    tmp2 = est_probablement_premier(q);
  }

  //gmp_printf("premier nombre premier (p) : %Zd\n", p);
  //gmp_printf("deuxième nombre premier (q) : %Zd\n", q);

  mpz_mul(n, p, q);

  mpz_t w, pMinus1, qMinus1, wMinus1, one, tampon, l;
  mpz_init(l);
  mpz_init(one);
  mpz_init(w);
  mpz_init(tampon);
  mpz_init(pMinus1);
  mpz_init(qMinus1);
  mpz_init(wMinus1);
  mpz_set_str(one, "1", 10);

  mpz_sub(pMinus1, p, one);
  mpz_sub(qMinus1, q, one);

  mpz_mul(w, pMinus1, qMinus1);
  
  mpz_sub(wMinus1, w, one);

  mpz_urandomm(d, randState, wMinus1);
  mpz_gcd(tampon, d, w);
  
  while(mpz_cmp_d(tampon, 1)!=0){
    mpz_urandomm(d, randState, wMinus1);
    mpz_gcd(tampon, d, w);
  }

  mpz_gcdext(tampon, e, l, d, w);
  
  gmp_printf(" (l)   : %Zd\n", l);

  mpz_clear(tampon);
  mpz_clear(one);
  mpz_clear(pMinus1);
  mpz_clear(qMinus1);
  mpz_clear(wMinus1);
  mpz_clear(w);
  mpz_clear(l);
  mpz_clear(p);
  mpz_clear(q);
  mpz_clear(seed);
  gmp_randclear(randState);
} // À modifier lors de l'exercice 1

void os2ip (void){
  mpz_t powerKof256, tampon, mpz256, mpzINT;
  mpz_init(mpzINT);
  mpz_init(mpz256);
  mpz_init(powerKof256);
  mpz_init(tampon);
  
  mpz_set_str(mpz256, "256", 10);

  char *msg = "Alfred";
  int length = strlen(msg);
  for(int j = 0; j<length;j++){
    int charInt = 0;
    for(int i = 0; i<8; i++){
      if(!!((msg[j] << i) & 0x80)){
        charInt += (1 << (7-i));
        
      }
      
    }
    mpz_pow_ui(powerKof256, mpz256, (length-1-j));
    mpz_mul_ui(tampon, powerKof256, charInt);
    mpz_add(code, code, tampon);
  }
  mpz_clear(mpzINT);
  mpz_clear(mpz256);
  mpz_clear(powerKof256);
  mpz_clear(tampon);  
} // Le nombre 71933831046500 est le codage de la chaîne "Alfred".

void i2osp(void){
  mpz_t q, r, comp;
  mpz_init(comp);
  mpz_init(q);
  mpz_init(r);
  int length = 1;
  mpz_ui_pow_ui(comp, 256, length);
  
  while(mpz_cmp(code_dechiffre, comp) > 0){
    length++;
    mpz_ui_pow_ui(comp, 256, length);
  }
  char* message_dechiffre = malloc(length*sizeof(char));
  mpz_fdiv_qr_ui(q, r, code_dechiffre, 256);
  message_dechiffre[length-1]=mpz_get_ui(r);
  for(int i=1 ; i<length-1 ; i++){
    mpz_fdiv_qr_ui(q, r, q, 256);
    message_dechiffre[length-1-i]=mpz_get_ui(r);
  }
  message_dechiffre[0]=mpz_get_ui(q);
  printf(" message dechiffre : %s \n", message_dechiffre);

  mpz_clear(comp);
  mpz_clear(q);
  mpz_clear(r);
} // Décodez ici le code message et placer dans message_dechiffre le texte correspondant.

int main(void){
  mpz_init(code);               // Le code du message clair
  mpz_init(code_chiffre);       // Le code chiffré
  mpz_init(code_dechiffre);     // Le code déchiffré
  mpz_init(n);                  // Le module de la clef publique
  mpz_init(e);                  // L'exposant de la clef publique
  mpz_init(d);                  // L'exposant de la clef privée
  os2ip() ;  // <------------------------------------------------------ Exercice 2
  gmp_printf("Message de %d caractères codé par %Zd\n", strlen((char*) message), code) ;
  fabrique(); // <----------------------------------------------------- Exercice 1    
  /* Affichage des clefs utilisées à l'aide de la fonction gmp_printf() */
  gmp_printf("Clef publique (n) : %Zd\n", n);
  gmp_printf("Clef publique (e) : %Zd\n", e);
  gmp_printf("Clef privée (d)   : %Zd\n", d);
  /* On effectue à présent le chiffrement RSA du code du message clair */
  mpz_powm(code_chiffre, code, e, n);                    // Calcul du code chiffré
  gmp_printf("Code chiffré      : %Zd\n", code_chiffre);
  mpz_powm(code_dechiffre, code_chiffre, d, n);        // Calcul du code déchiffré
  gmp_printf("Code déchiffré    : %Zd\n", code_dechiffre);

  i2osp();

  mpz_clear(code);
  mpz_clear(code_chiffre);
  mpz_clear(code_dechiffre);
  mpz_clear(n);
  mpz_clear(e);
  mpz_clear(d);
  exit(EXIT_SUCCESS);
}  