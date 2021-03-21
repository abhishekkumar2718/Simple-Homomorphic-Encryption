#include "cipher_bit.h"

void CipherBit::initialize_ciphertext() {
  mpz_init(old_ciphertext);
}

void CipherBit::initialize_z_vector(const unsigned long int length) {
  z_vector = new unsigned long[length];
}

// Calculate the z-vector by setting z_vector[i] = ciphertext * y[i],
// keeping only ceil(log2(theta)) + 3 bits of precision.
void CipherBit::calculate_z_vector(const SecuritySettings &sec, const PublicKey &pk) {
  unsigned int precision = ceil(log2(sec.theta)) + 3;
  unsigned long bitmask = (1l << (precision + 1)) - 1;
  auto z_vector_length = sec.public_key_y_vector_length;

  initialize_z_vector(z_vector_length);

  mpz_t temp;
  mpz_init(temp);
  for (unsigned int i = 0; i < z_vector_length; i++) {
    mpz_mul(temp, old_ciphertext, pk.y_vector[i]);
    mpz_fdiv_q_2exp(temp, temp, sec.kappa - precision);
    z_vector[i] = mpz_get_ui(temp) & bitmask;
  }
  mpz_clear(temp);
}

// If the ciphertext is larger than the public key integers, reduce it
// by taking remainders
void CipherBit::reduce_by_public_key(const SecuritySettings &sec, const PublicKey &pk) {
  for (int i = sec.gamma; i >= 0; i--)
    mpz_mod(old_ciphertext, old_ciphertext, pk.old_key_extra[i]);
}

// Is the cipher text greater than 2^size?
const bool CipherBit::greater_than_base_2(const unsigned long int size) {
  mpz_t bound;
  mpz_init2(bound, size + 1);
  mpz_setbit(bound, size);

  bool result = mpz_cmp(old_ciphertext, bound) > 0;
  mpz_clear(bound);

  return result;
}

std::ostream& operator<<(std::ostream &os, const CipherBit &cipher_bit) {
  os << "--- Cipher Bit ---" << std::endl;
  os << "Cipher Text: " << cipher_bit.old_ciphertext  << std::endl;
  os << "Size of Cipher Text (in bits): " << mpz_sizeinbase(cipher_bit.old_ciphertext, 2) << std::endl;
  os << "Z-Vector (first 50 elements): " ;
  for (int i = 0; i < 50; i++)
    os << cipher_bit.z_vector[i] << " ";
  os << std::endl;

  return os;
}
