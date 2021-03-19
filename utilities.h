#ifndef UTILITIES_H
#define UTILITIES_H
#include <gmp.h>

#define COLOR_OUTPUT 1

// Assigns result = min(k, D - k) where k is (N % D)
void mpz_correct_mod(mpz_t result, const mpz_t n, const mpz_t d);

#endif //UTILITIES_H
