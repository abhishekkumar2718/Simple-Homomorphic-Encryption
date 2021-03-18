#ifndef FULLY_HOMOMORPHIC_H
#define FULLY_HOMOMORPHIC_H

#include "cipher_bit.h"
#include "type_defs.h"
#include <cstdio>
#include <cmath>
#include <gmp.h>
#include "utilities.h"
#include "circuit.h"
#include "security_settings.h"
#include <cryptopp/osrng.h>
#include <vector>
#include <stack>

class FullyHomomorphic {
 private:
  static unsigned int MAX_SOMEWHAT_PUBLIC_KEY_TRIES;
  SecuritySettings *sec;
  gmp_randstate_t rand_state;
  CryptoPP::RandomPool rng;

  // Generate the somewhat private key.
  void generate_somewhat_private_key(SomewhatPrivateKey ssk);

  // Generate the somewhat public key.
  SomewhatPublicKey generate_somewhat_public_key(const SomewhatPrivateKey &sk);

  // Generate the additional somewhat public key.
  SomewhatPublicKey generate_additional_somewhat_public_key(const SomewhatPrivateKey &sk);

  // Generate private key (also called s-vector).
  PrivateKey generate_private_key();


  // Generate y-vector for the public key.
  //
  // y-vector is a set of big-theta rational numbers in [0, 2) with
  // kappa bits of precision such that there is a sparse subset of
  // y-vector of size theta such that sum of subset is approximately
  // equal to (1/p mod 2).
  //
  // The y-vector acts as a hint about the secret key and this extra
  // information is used to "post process" the ciphertext, making it more
  // efficiently decryptable than the original ciphertext and the
  // bootstrapping of fully homomorphic encryption circuits possible.
  mpz_t_arr generate_y_vector(const PrivateKey &sk);

  // x_p is the closest integer to 2^kappa/ssk. Used in generating
  // y-vector.
  void generate_x_p(mpz_t x_p);

  // Assigns an integer result = p*q + r where p is the somewhatPrivateKey,
  // q belongs to [0, 2^gamma/p) and r belongs to [-2^rho + 1, 2^rho).
  void choose_random_d(mpz_t result, const SomewhatPrivateKey p);

  void store_cipher_bit(FILE* stream, CipherBit &c);

  // Seed the CryptoPP RNG using system time and srand()
  void seed_rng();

  // Seed the GMP random state using entropy generated from RNG
  void seed_random_state(void *source, size_t n_bytes);
 public:
  FullyHomomorphic(SecuritySettings *security_settings);

  // Generate private, public key pair and assign to
  // sk and pk variables
  void generate_key_pair(PrivateKey &sk, PublicKey &pk);

  void encrypt_bit(CipherBit &result, const PublicKey &pk, const bool m);
  bool decrypt_bit(const CipherBit &c, const PrivateKey &sk);
  void clear_cipher_bit(CipherBit &c);
  CipherBit** encrypt_bit_vector(const PublicKey &pk, const bool* m_vector, const unsigned long int m_vector_length);
  bool* decrypt_bit_vector(const PrivateKey &sk, CipherBit** c_vector, const unsigned long int c_vector_length);
  //std::vector<CipherBit> evaluate(CircuitNode *circuit, std::vector<CipherBit> inputs);
  CipherBit** evaluate(std::vector<Gate*> output_gates, CipherBit** inputs, const PublicKey &pk);
  std::vector<Gate*> create_decryption_cicuit();
  Gate*** create_3_for_2_circuit(Gate** a, Gate** b, Gate** c, unsigned int n);
  void test_decryption_circuit(const PublicKey &pk, const PrivateKey &sk);

  bool is_allowed_circuit(std::vector<Gate*> output_gates);

  mpz_t ssk;

  void old_encrypt_bit(mpz_t result, const PublicKey &pk, const bool m);
};

#endif //FULLY_HOMOMORPHIC_H
