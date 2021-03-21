#include "fully_homomorphic.h"
#include <set>

unsigned int FullyHomomorphic::MAX_SOMEWHAT_PUBLIC_KEY_TRIES = 10;

FullyHomomorphic::FullyHomomorphic (SecuritySettings *security_settings) : sec(security_settings) {
  size_t n_bytes = 8;
  CryptoPP::byte seed_bytes[n_bytes];

  // Seed the CryptoPP RNG using system time and srand()
  seed_rng();

  // Generate 8 bytes of entropy to seed the random state
  rng.GenerateBlock(seed_bytes, n_bytes);

  seed_random_state(seed_bytes, n_bytes);
}

void FullyHomomorphic::seed_rng() {
  srand(time(NULL));

  unsigned int init_seed = rand();

  rng.IncorporateEntropy((CryptoPP::byte*) &init_seed, sizeof(unsigned int));
}

void FullyHomomorphic::seed_random_state(void *source, size_t n_bytes) {
  mpz_t seed;

  mpz_init(seed);
  mpz_import(seed, n_bytes, 1, 1, 1, 0, source);

  gmp_randinit_default(rand_state);
  gmp_randseed(rand_state, seed);
}

void FullyHomomorphic::generate_key_pair(PrivateKey &sk, PublicKey &pk) {
  generate_somewhat_private_key(ssk);

  sk = generate_private_key();

  pk.old_key = generate_somewhat_public_key(ssk);

  pk.old_key_extra = generate_additional_somewhat_public_key(ssk);

  pk.y_vector = generate_y_vector(sk);
}

// Returns a random integer between [2^(eta - 1) + 1, 2^eta + 1]
void FullyHomomorphic::generate_somewhat_private_key(SomewhatPrivateKey key) {
  mpz_t temp;

  mpz_init(key);
  mpz_init2(temp, sec->eta-1);

  mpz_setbit(temp, sec->eta-2);        // temp: 2^(eta - 2)
  mpz_add_ui(temp, temp, 1);           // temp: 2^(eta - 2) + 1

  mpz_urandomm(key, rand_state, temp); // key:  [0, 2^(eta - 2)]

  mpz_sub_ui(temp, temp, 1);           // temp: 2^(eta - 2)
  mpz_add(key, key, temp);             // key:  [2^(eta - 2), 2^(eta - 1)]

  mpz_mul_ui(key, key, 2);             // key:  [2^(eta - 1), 2^eta]
  mpz_add_ui(key, key, 1);             // key:  [2^(eta - 1) + 1, 2^eta + 1]

  mpz_clear(temp);
}

// Generate private key (also called s-vector), which consists of tau
// unique integers between [0, theta).
//
// tau: sec->private_key_length
// theta: sec->public_key_y_vector_length
PrivateKey FullyHomomorphic::generate_private_key() {
  auto key_length = sec->private_key_length;
  auto key_range = sec->public_key_y_vector_length - 1;

  PrivateKey key = new unsigned int[key_length];

  std::set<unsigned int> generated_keys;

  while (generated_keys.size() < key_length) {
    auto word = rng.GenerateWord32(0, key_range);

    if (generated_keys.find(word) == generated_keys.end()) {
      key[generated_keys.size()] = word;
      generated_keys.insert(word);
    }
  }

  return key;
}

// Generate the somewhat public key, which consists tau + 1 integers
// of the form p*q + r where p is the somewhat private key and q lies in
// [0, 2^gamma/p), r lies in [-2^rho + 1, 2^rho) such that the largest
// integer is odd and the remainder after division by p is even.
SomewhatPublicKey FullyHomomorphic::generate_somewhat_public_key(const SomewhatPrivateKey &sk) {
  auto key_length = sec->public_key_old_key_length;
  SomewhatPublicKey key = new __mpz_struct* [key_length];

  for (unsigned int i = 0; i < key_length; i++) {
    key[i] = new mpz_t;
    mpz_init(key[i]);
  }

  for (unsigned int try_count = 0; try_count < MAX_SOMEWHAT_PUBLIC_KEY_TRIES; try_count++) {
    bool valid_key = false;
    unsigned long int max_index = 0;

    for (unsigned long int i = 0; i < key_length; i++) {
      choose_random_d(key[i], sk);

      if (mpz_cmp(key[i], key[max_index]) > 0)
        max_index = i;
    }

    mpz_t mod_result;
    mpz_init(mod_result);
    mpz_correct_mod(mod_result, key[max_index], sk);

    // If the largest integer is odd and the remainder after division
    // by p is even, we have generated a valid somewhat public key.
    valid_key = mpz_odd_p(key[max_index]) && mpz_even_p(mod_result);

    mpz_clear(mod_result);

    if (valid_key) {
      mpz_swap(key[0], key[max_index]);
      return key;
    }
  }

  for (unsigned int i = 0; i < key_length; i++) {
    mpz_clear(key[i]);
    delete key[i];
  }

  delete[] key;
  std::cout << "Could not generate a somewhat public key!" << std::endl;
  std::cout << "Try with a different seed!" << std::endl;
  exit(1);
}

// Generates gamma + 1 random integers of the form 2*(p*q[i] + r)
// where p is the secret key, q lies in [2^(gamma + i - 1)/p, 2^(gamma + i)/p)
// and r lies in [-2^rho - 1, 2^rho + 2).
SomewhatPublicKey FullyHomomorphic::generate_additional_somewhat_public_key(const SomewhatPrivateKey &sk) {
  auto key_length = sec->gamma + 1;
  SomewhatPublicKey key = new __mpz_struct*[key_length];

  // Initialize range for q's
  mpz_t q_range;
  mpz_init2(q_range, sec->gamma);
  mpz_setbit(q_range, sec->gamma-1); // q_range: 2^(gamma - 1)
  mpz_cdiv_q(q_range, q_range, sk);  // q_range: 2^(gamma - 1)/p

  // Initialize range for r's
  mpz_t r_range;
  mpz_init2(r_range, sec->rho+2);
  mpz_setbit(r_range, sec->rho+1);   // r_range: 2^(rho + 1)
  mpz_add_ui(r_range, r_range, 1);   // r_range: 2^(rho + 1) + 1

  // Initialize offset for r's
  mpz_t r_shift;
  mpz_init2(r_shift, sec->rho+1);
  mpz_setbit(r_shift, sec->rho);     // r_shift: 2^rho
  mpz_sub_ui(r_shift, r_shift, 1);   // r_shift: 2^rho - 1

  mpz_t temp;
  mpz_init(temp);
  for (unsigned long int i = 0; i < key_length; i++) {
    key[i] = new mpz_t;
    mpz_init(key[i]);

    mpz_urandomm(temp, rand_state, q_range); // pick a random integer between [0, q_range)
    mpz_add(temp, temp, q_range);            // shift to [q_range, 2*q_range)

    mpz_mul(key[i], sk, temp);               // key[i]: p*q

    mpz_urandomm(temp, rand_state, r_range); // pick a random integer r between [0, r_range)
    mpz_sub(temp, temp, r_shift);            // shift to [-r_shift, r_range - r_shift)

    mpz_add(key[i], key[i], temp);           // key[i]: p*q + r
    mpz_mul_2exp(key[i], key[i], 1);         // key[i]: 2(p*q + r)

    mpz_mul_2exp(q_range, q_range, 1);       // q_range: 2*q_range
  }

  mpz_clear(temp);

  return key;
}

// Generate y-vector for the public key.
//
// y-vector is a set of big-theta rational numbers in [0, 2) with
// kappa bits of precision such that there is a sparse subset of
// y-vector of size theta such that sum of subset is approximately
// equal to (1/p mod 2).
//
// theta: sec->private_key_length
// big-theta: sec->private_key_y_vector_length
//
// NOTE: instead of using rational numbers between [0, 2) and deal with
// precision issues, we are using integers between [0, 2^kappa) and dividing
// before use.
mpz_t_arr FullyHomomorphic::generate_y_vector(const PrivateKey &sk) {
  auto y_vector_length = sec->public_key_y_vector_length;

  mpz_t x_p, sum, mod;
  mpz_t_arr y_vector = new __mpz_struct* [y_vector_length];

  mpz_init(sum);

  mpz_init2(mod, sec->kappa + 2);
  mpz_setbit(mod, sec->kappa + 1); // mod: 2^kappa + 1

  // x_p is the closest integer to 2^kappa/ssk
  generate_x_p(x_p);

  for (unsigned int i = 0; i < y_vector_length; i++) {
	y_vector[i] = new mpz_t;
	mpz_init(y_vector[i]);
	mpz_urandomb(y_vector[i], rand_state, sec->kappa); // y_vector[i]: [0, 2^kappa)
  }

  // Replace one of the elements in the y-vector with 2^kappa/ssk - (S mod 2^(kappa + 1))
  // where S is the sum of the theta element subset of y-vector to serve as an hint
  // for "post-processing" circuits.
  unsigned int rand_val = rng.GenerateWord32(0, sec->private_key_length - 1);
  auto secret_key_idx = sk[rand_val];

  for (unsigned int i = 0; i < sec->private_key_length; i++) {
    if (sk[i] != secret_key_idx)
      mpz_add(sum, sum, y_vector[sk[i]]);
  }

  // sum: sum % 2^(kappa + 1)
  mpz_mod(sum, sum, mod);

  // y_vector[secret_key_idx]: x_p - (sum % 2^(kappa + 1))
  if (mpz_cmp(x_p, sum) > 0) {
    mpz_sub(y_vector[secret_key_idx], x_p, sum);
  } else {
    mpz_sub(y_vector[secret_key_idx], x_p, sum);
    mpz_add(y_vector[secret_key_idx], y_vector[secret_key_idx], mod);
  }

  mpz_clear(x_p);
  mpz_clear(sum);
  mpz_clear(mod);

  return y_vector;
}

// x_p is the closest integer to 2^kappa/ssk
void FullyHomomorphic::generate_x_p(mpz_t x_p) {
  mpz_t remainder, half_ssk;

  mpz_init(x_p);
  mpz_init(remainder);
  mpz_init(half_ssk);

  mpz_setbit(x_p, sec->kappa);           // x_p: 2^kappa
  mpz_fdiv_qr(x_p, remainder, x_p, ssk); // x_p: 2^kappa/ssk, remainder: (2^kappa % ssk)
  mpz_fdiv_q_2exp(half_ssk, ssk, 1);     // half_ssk: ssk/2

  // If the remainder is larger than half of ssk, round x_p to the
  // next integer
  if (mpz_cmp(remainder, half_ssk) < 0)
	mpz_add_ui(x_p, x_p, 1);

  mpz_clear(remainder);
  mpz_clear(half_ssk);
}

// Assigns an integer result = p*q + r where p is the somewhatPrivateKey,
// q belongs to [0, 2^gamma/p) and r belongs [-2^rho + 1, 2^rho).
void FullyHomomorphic::choose_random_d(mpz_t result, const SomewhatPrivateKey p) {
  mpz_t temp, q_range, r_range, r_shift;

  mpz_init(temp);

  mpz_init2(q_range, sec->gamma + 1);
  mpz_setbit(q_range, sec->gamma);         // q_range: 2^gamma
  mpz_cdiv_q(q_range, q_range, p);         // q_range: 2^gamma/p

  mpz_init2(r_range, sec->rho + 2);
  mpz_setbit(r_range, sec->rho + 1);       // r_range: 2^(rho + 1)
  mpz_add_ui(r_range, r_range, 1);         // r_range: 2^(rho + 1) + 1

  mpz_init2(r_shift, sec->rho + 1);
  mpz_setbit(r_shift, sec->rho);           // r_shift: 2^(rho)
  mpz_sub_ui(r_shift, r_shift, 1);         // r_shift: 2^rho - 1

  mpz_urandomm(temp, rand_state, q_range); // pick a random integer q between [0, q_range)
  mpz_mul(result, p, temp);                // result: p*q

  mpz_urandomm(temp, rand_state, r_range); // pick a random integer r betwen [0, r_range)
  mpz_sub(temp, temp, r_shift);            // shift to [-r_shift, r_range - r_shift)

  mpz_add(result, result, temp);           // result: p*q + r

  mpz_clear(temp);
  mpz_clear(q_range);
  mpz_clear(r_range);
  mpz_clear(r_shift);
}

// Encrypt a bit by generating ciphertext (described below) and the z-vector by
// setting z[i] = ciphertext * y[i], keeping only ceil(log2(theta)) + 3 bits of precision.
void FullyHomomorphic::encrypt_bit(CipherBit &result, const PublicKey &pk, const bool value) {
  unsigned int cnt = ceil(log2(sec->theta)) + 3;
  unsigned int z_vector_length = sec->public_key_y_vector_length;
  unsigned long bitmask = (1l << (cnt + 1)) - 1;

  mpz_t temp;

  mpz_init(temp);
  mpz_init(result.old_ciphertext);
  generate_ciphertext(result.old_ciphertext, pk, value);

  result.z_vector = new unsigned long [z_vector_length];

  // z_vector[i]: the least significant 'cnt' bits of ciphertext * y_vector[i]
  for (unsigned int i = 0; i < z_vector_length; i++) {
    mpz_mul(temp, result.old_ciphertext, pk.y_vector[i]); // temp: result.old_ciphertext * y_vector[i]
    mpz_fdiv_q_2exp(temp, temp, sec->kappa - cnt);        // temp: (result.old_ciphertext * y_vector[i])/2^(kappa - precision)
    result.z_vector[i] = mpz_get_ui(temp) & bitmask;      // z_vector[i]: temp & bitmask
  }

  mpz_clear(temp);
}

// Generate ciphertext for a bit: Choose a random subset S of {1, 2, 3, ..., tau}
// and a random integer r in (-2^rho', 2^rho') and assign ciphertext as
// c = (m + 2 * r + 2 * sum) % X[0], where X[i] are the public key integers and
// sum is summation of X[i] where i belongs to set S.
void FullyHomomorphic::generate_ciphertext(mpz_t ciphertext, const PublicKey &pk, const bool value) {
  auto public_key_length = sec->public_key_old_key_length;

  mpz_t sum;
  mpz_init(sum);

  CryptoPP::byte randomness;
  for (unsigned int i = 1; i < public_key_length; i++) {
    auto counter = (i - 1) % 8;

    if (counter == 0)
      randomness = rng.GenerateByte();

    if ((randomness << counter) >> 7)
      mpz_add(sum, sum, pk.old_key[i]);
  }

  // sum: 2 * sum(X[i]) where i belongs to a random subset of {1, 2, ..., tau}.
  mpz_mul_2exp(sum, sum, 1);

  mpz_t r, upper_bound, offset;

  mpz_init(r);

  mpz_init2(upper_bound, sec->rho_ + 2);
  mpz_setbit(upper_bound, sec->rho_ + 1);                 // upper_bound: 2^(rho' + 1)
  mpz_sub_ui(upper_bound, upper_bound, 2);                // upper_bound: 2^(rho' + 1) - 2

  mpz_init2(offset, sec->rho_+1);
  mpz_setbit(offset, sec->rho_);                          // offset: 2^rho'
  mpz_sub_ui(offset, offset, 1);                          // offset: 2^rho' - 1

  mpz_urandomm(r, rand_state, upper_bound);               // r: [0, 2^(rho' + 1) - 2)
  mpz_sub(r, r, offset);                                  // r: [-2^rho' - 1, 2^rho' - 1)

  mpz_mul_2exp(r, r, 1);                                  // r: [-2^(rho' + 1) - 2, 2^(rho' + 1) - 2)

  mpz_add_ui(ciphertext, ciphertext, value);              // ciphertext: m
  mpz_add(ciphertext, ciphertext, r);                     // ciphertext: m + r
  mpz_add(ciphertext, ciphertext, sum);                   // ciphertext: m + r + sum
  mpz_correct_mod(ciphertext, ciphertext, pk.old_key[0]); // ciphertext: (m + r + sum) % X[0]

  mpz_clear(r);
  mpz_clear(sum);
  mpz_clear(upper_bound);
  mpz_clear(offset);
}

CipherBit** FullyHomomorphic::encrypt_bit_vector(const PublicKey &pk, const bool* m_vector, const unsigned long int m_vector_length) {
  CipherBit** c_vector = new CipherBit*[m_vector_length];
  CipherBit* c;
  unsigned long int c_index = 0;
  for (unsigned long int i = 0; i < m_vector_length; i++) {
    c = new CipherBit;
    encrypt_bit(*c, pk, m_vector[i]);
    c_vector[c_index] = c;
    c_index++;
  }
  return c_vector;
}

// Decrypt ciphertext, producing a bit as follows: For each element i in
// the private key, subtract z_vector[i] from the ciphertext and return
// resultant mod 2.
bool FullyHomomorphic::decrypt_bit(const CipherBit &c, const PrivateKey &sk) {
  unsigned int precision = ceil(log2(sec->theta)) + 3;

  mpz_t sum, half_sum, rounded_sum, remainder;

  mpz_init(sum);
  mpz_init(half_sum);
  mpz_init(rounded_sum);
  mpz_init(remainder);

  // sum: sum of z_vector[i] for i in private key.
  for (unsigned int i = 0; i < sec->private_key_length; i++)
    mpz_add_ui(sum, sum, c.z_vector[sk[i]]);

  mpz_cdiv_r_2exp(remainder, sum, precision);          // remainder: sum % 2^precision
  mpz_fdiv_q_2exp(rounded_sum, sum, precision);        // rounded_sum: sum / 2^precision

  mpz_fdiv_q_2exp(half_sum, sum, 1);                   // half_sum: sum / 2

  // If the remainder is less than half of the sum, round the sum up.
  // Since rounded sum must be represent the closest integer to the sum.
  if (mpz_cmp(remainder, half_sum) < 0)
    mpz_add_ui(rounded_sum, rounded_sum, 1);

  mpz_sub(rounded_sum, c.old_ciphertext, rounded_sum); // rounded_sum: ciphertext - rounded_sum

  bool decrypted_bit = mpz_odd_p(rounded_sum);         // rounded_sum: rounded_sum % 2

  mpz_clear(sum);
  mpz_clear(half_sum);
  mpz_clear(rounded_sum);
  mpz_clear(remainder);

  return decrypted_bit;
}

std::vector<bool> FullyHomomorphic::decrypt_bit_vector(const PrivateKey &sk, CipherBit** c_vector, const unsigned long int c_vector_length) {
  std::vector<bool> M(c_vector_length);

  for (unsigned long int i = 0; i < c_vector_length; i++)
    M[i] = decrypt_bit(*c_vector[i], sk);

  return M;
}

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
// coefficient vector of f and eta, rho' are security parameters.
const bool FullyHomomorphic::is_valid(const std::vector<Gate*> &output_gates) {
  unsigned long int d = 0;
  unsigned long int norm = 0;

  for (const auto &output_gate: output_gates) {
    if (output_gate->degree > d) {
      d = output_gate->degree;
      norm = output_gate->norm;
    }
  }

  return d <= (sec->eta - 4 - log2(norm)) / (sec->rho_ + 2);
}

// Evaluate the expression represented by the circuit.
CipherBit** FullyHomomorphic::evaluate(std::vector<Gate*> output_gates, CipherBit** inputs, const PublicKey &pk) {
  if (!is_valid(output_gates)) {
    std::cout << "The circuit adds too much noise! Try again with a larger lambda" << std::endl;
    exit(1);
  }

  std::stack<Gate*> evaluation_stack;
  for (auto i = output_gates.rbegin(); i != output_gates.rend(); i++)
    evaluation_stack.push((Gate*)*i);

  CipherBit** output_vector = new CipherBit*[output_gates.size()];
  unsigned long int output_index = 0;

  while (!evaluation_stack.empty()) {
    Gate* cur_gate = evaluation_stack.top();

    // If either of inputs to the current gate are not resolved,
    // push them to stack and evaluate them.
    if (!cur_gate->input1_resolved)
      evaluation_stack.push(cur_gate->input1);

    if (!cur_gate->input2_resolved)
      evaluation_stack.push(cur_gate->input2);

    if (cur_gate->input1_resolved && cur_gate->input2_resolved) {
      // If the current is an input gate, forward the ciphertext to
      // all outputs. 
      if (cur_gate->is_input())
        cur_gate->forward_ciphertext(inputs);

      // Evaluate the current gate and resolve inputs for the next
      // layer.
      cur_gate->evaluate(pk);

      evaluation_stack.pop();

      // If it is an output gate, store the cipherbit in the output
      // vector.
      if (cur_gate->gate_type == Output) {
        output_vector[output_index] = cur_gate->output_cipher_bits;
        output_index++;
      }
    }
  }

  return output_vector;
}
