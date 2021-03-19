#include "utilities.h"

// Assigns result = min(k, D - k) where k is (N % D) 
void mpz_correct_mod(mpz_t result, const mpz_t n, const mpz_t d) {
  mpz_t temp;
  mpz_init(temp);

  mpz_tdiv_r(result, n, d);         // result: N % D

  mpz_fdiv_q_2exp(temp, d, 1);      // temp: D / 2

  if (mpz_cmp(result, temp) > 0)    // if (N % D) > D/2,
	mpz_sub(result, d, result); // result: D - (N % D)

  mpz_clear(temp);
}
