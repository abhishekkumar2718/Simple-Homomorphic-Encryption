#include "fully_homomorphic.h"

int main(int argc, char** argv) {
  CryptoPP::AutoSeededRandomPool rng;
  SecuritySettings *security_settings = new SecuritySettings(5);
  FullyHomomorphic fh(security_settings);
  PrivateKey sk;
  PublicKey pk;

  cout << *security_settings << endl;

  fh.generate_key_pair(sk, pk);
}
