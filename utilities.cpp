#include "utilities.h"

// TODO: What is "correct mod"?
void mpz_correct_mod(mpz_t result, const mpz_t n, const mpz_t d) {
  mpz_t temp;
  mpz_init(temp);

  // Divide N by D and store the remainder in result
  mpz_tdiv_r(result, n, d);

  // Divide D by 2^1 and store the quotient in temp
  mpz_fdiv_q_2exp(temp, d, 1);

  if (mpz_cmp(result, temp) > 0)
	mpz_sub(result, d, result);

  mpz_clear(temp);
}

void textcolor(int attr, int fg) {
  if (COLOR_OUTPUT)
	printf("%c[%d;%dm", 0x1B, attr, fg + 30);
}

void resettextcolor() {
  if (COLOR_OUTPUT)
	printf("%c[0m", 0x1B);
}
