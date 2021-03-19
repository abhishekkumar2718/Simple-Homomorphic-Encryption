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

  // Generate the somewhat private key - a random integer between
  // [2^(eta - 1) + 1, 2^eta + 1].
  void generate_somewhat_private_key(SomewhatPrivateKey ssk);

  // Generate the somewhat public key, which consists of tau + 1 integers
  // of the form p*q + r where p is the somewhat private key and q lies in
  // [0, 2^gamma/p), r lies in [-2^rho + 1, 2^rho) such that the largest
  // integer is odd and the remainder after division by p is is even.
  SomewhatPublicKey generate_somewhat_public_key(const SomewhatPrivateKey &sk);

  // Generate gamma + 1 random integers of the form 2*(p*q[i] + r)
  // where p is the somewhatPrivateKey, q lies in 
  // [2^(gamma + i - 1)/p, 2^(gamma + i)/p) and r lies in 
  // [-2^rho - 1, 2^rho + 2).
  SomewhatPublicKey generate_additional_somewhat_public_key(const SomewhatPrivateKey &sk);

  // Generate private key (also called s-vector), which consists of tau
  // unique integers between [0, theta).
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

  // x_p is the closest integer to 2^kappa/ssk. Used to construct y-vector. 
  void generate_x_p(mpz_t x_p);

  // Assigns an integer result = p*q + r where p is the somewhatPrivateKey,
  // q belongs to [0, 2^gamma/p) and r belongs to [-2^rho + 1, 2^rho).
  //
  // Used to construct the somewhat public key.
  void choose_random_d(mpz_t result, const SomewhatPrivateKey p);

  // Seed the CryptoPP RNG using system time and srand().
  void seed_rng();

  // Seed the GMP random state using entropy generated from RNG.
  // Used to generate large random integers.
  void seed_random_state(void *source, size_t n_bytes);

  // Generate ciphertext for a bit: Choose a random subset S of
  // {1, 2, 3, ..., tau} and a random integer r in (-2^rho', 2^rho')
  // and assign ciphertext as c = (m + 2 * r + 2 * sum) % X[0], where
  // X[i] are the public key integers and sum is summation of X[i]
  // where i belongs to set S.
  void generate_ciphertext(mpz_t ciphertext, const PublicKey &pk, const bool value);

  // Returns whether the circuit is valid.
  //
  // As each computation of homomorphic encryption adds more noise, after
  // certain number of operations it is no longer possible to decrypt the
  // ciphertext correctly.
  //
  // A circuit is valid if for the equivalent polynomial f, the following
  // condition is true:
  //
  //                 d <= (eta - 4 - log2(|f|))/(rho' + 2)
  //
  // where d is the degree of polynomial, |f| is the l-1 norm of the
  // coefficient vector of f and eta, rho' are security parameters
  const bool is_valid(const std::vector<Gate*> &output_gates);
 public:
  mpz_t ssk;

  FullyHomomorphic(SecuritySettings *security_settings);

  // Generate private, public key pair and assign to
  // sk and pk variables
  void generate_key_pair(PrivateKey &sk, PublicKey &pk);

  // Encrypt a bit by generating ciphertext and z-vector by setting
  // z[i] = ciphertext * y[i], keeping only ceil(log2(theta)) + 3 bits of
  // precision.
  void encrypt_bit(CipherBit &result, const PublicKey &pk, const bool value);

  // Decrypt ciphertext, producing a bit as follows: For each element i in the
  // private key, subtract z_vector[i] from the ciphertext and return
  // the resultant mod 2.
  bool decrypt_bit(const CipherBit &c, const PrivateKey &sk);

  std::vector<bool> decrypt_bit_vector(const PrivateKey &sk, CipherBit** c_vector, const unsigned long int c_vector_length);

  // TODO: Refactor along with demo_vote_counter
  CipherBit** encrypt_bit_vector(const PublicKey &pk, const bool* m_vector, const unsigned long int m_vector_length);

  // Evaluate the expression represented by the circuit.
  CipherBit** evaluate(std::vector<Gate*> output_gates, CipherBit** inputs, const PublicKey &pk);
};

#endif //FULLY_HOMOMORPHIC_H
