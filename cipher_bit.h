#ifndef CIPHER_BIT_H
#define CIPHER_BIT_H

#include <gmp.h>
#include "type_defs.h"
#include "security_settings.h"

class CipherBit {
  public:
    mpz_t old_ciphertext;
    unsigned long *z_vector;

    void initialize_ciphertext();

    void initialize_z_vector(const unsigned long int length);

    void calculate_z_vector(const SecuritySettings &sec, const PublicKey &pk);

    void reduce_by_public_key(const SecuritySettings &sec, const PublicKey &pk);

    const bool greater_than_base_2(const unsigned long int size);

    friend ostream& operator<<(ostream &os, const CipherBit &cipher_bit);

    ~CipherBit() {
      mpz_clear(old_ciphertext);
      delete[] z_vector;
    }
};

#endif // CIPHER_BIT_H
