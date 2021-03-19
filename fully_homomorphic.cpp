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

void FullyHomomorphic::generate_key_pair(PrivateKey &sk, PublicKey &pk) {
  cout << "--- Generating Key Pair ---" << endl;

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

  mpz_setbit(temp, sec->eta-2);
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
  cout << "Could not generate a somewhat public key!" << endl;
  cout << "Try with a different seed!" << endl;
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

bool* FullyHomomorphic::decrypt_bit_vector(const PrivateKey &sk, CipherBit** c_vector, const unsigned long int c_vector_length) {
  bool* m_vector = new bool[c_vector_length];
  unsigned long int m_index = 0;
  for (unsigned long int i = 0; i < c_vector_length; i++) {
	m_vector[m_index] = decrypt_bit(*c_vector[i], sk);
	m_index++;
  }
  return m_vector;
}

bool FullyHomomorphic::is_allowed_circuit(std::vector<Gate*> output_gates) {
  // d <= (e - 4 - (log fnorm)) / (r + 2)

  unsigned long int max_degree = 0;
  unsigned long int max_norm = 0;
  for (std::vector<Gate*>::iterator i = output_gates.begin(); i != output_gates.end(); i++) {
	if ((*i)->degree > max_degree) {
	  max_degree = (*i)->degree;
	  max_norm = (*i)->norm;
	}
	//if ((*i)->degree > (sec->eta - 4 - log2((*i)->norm)) / (sec->rho_+2))
	//return false;
  }
  //  printf("Max Degree = %lu, Max Norm = %lu\n", max_degree, max_norm);
  //  printf("Log2 Max Norm = %f\n", log2(max_norm));
  printf("max degree: %lu, max norm: %lu\n", max_degree, max_norm);
  if (max_degree > (sec->eta - 4 - log2(max_norm)) / (sec->rho_+2))
	return false;
  return true;
}

CipherBit** FullyHomomorphic::evaluate(std::vector<Gate*> output_gates, CipherBit** inputs, const PublicKey &pk) {
  if (!is_allowed_circuit(output_gates)) {
	printf("Circuit is not allowed! Giving up!\n");
	exit(1);
  }

  // TODO: Make sure that the function will be calculated properly
  std::stack<Gate*> evaluation_stack;
  for (std::vector<Gate*>::reverse_iterator i = output_gates.rbegin(); i != output_gates.rend(); i++) {
	evaluation_stack.push((Gate*)*i);
  }

  CipherBit** output_vector = new CipherBit*[output_gates.size()];
  unsigned long int output_index = 0;

  while (!evaluation_stack.empty()) {
	Gate* cur_gate = evaluation_stack.top();

	if (!cur_gate->input1_resolved) {
	  evaluation_stack.push(cur_gate->input1);
	}
	if (!cur_gate->input2_resolved) {
	  evaluation_stack.push(cur_gate->input2);
	}

	if (cur_gate->input1_resolved && cur_gate->input2_resolved) {
	  if (cur_gate->is_input())
		cur_gate->forward_ciphertext(inputs);

	  cur_gate->evaluate(pk);
	  evaluation_stack.pop();

	  if (cur_gate->gate_type == Output) {
		output_vector[output_index] = cur_gate->output_cipher_bits;
		output_index++;
	  }
	}
  }

  return output_vector;
}

void FullyHomomorphic::test_decryption_circuit(const PublicKey &pk, const PrivateKey &sk) {
  unsigned int n = ceil(log2(sec->theta)) + 3;


  std::vector<Gate*> output_gates = create_decryption_cicuit();
  if (is_allowed_circuit(output_gates)) {
	printf("Allowed circuit\n");
  } else {
	printf("NOT ALLOWED CIRCUIT!!\n");
	return;
  }
  


  bool* in = new bool[1];
  in[0] = true;
  CipherBit** encrypted_vector = encrypt_bit_vector(pk, in, 1);
  delete[] in;
  CipherBit* encrypted_bit = encrypted_vector[0];
  delete[] encrypted_vector; // TODO: POSSIBLE BUG: Does this delete the CipherBits, or just the pointers to them??
  // Note: Seems to just delete the pointers

  unsigned long int in_length = sec->gamma+sec->tau+sec->big_theta+sec->big_theta*(n+1);
  printf("in_length: %lu\n", in_length);
  CipherBit** in_vector = new CipherBit*[in_length];

  printf("Creating c_star input vector (starting at index %lu)\n", 0l);
  bool* c_star_bool_vector = new bool[sec->gamma+sec->tau];
  for (unsigned int i = 0; i < sec->gamma+sec->tau; i++) {
	c_star_bool_vector[i] = mpz_tstbit(encrypted_bit->old_ciphertext, i);
  }
  printf("(doing encryption)\n");
  CipherBit** encrypted_c_star_vector = encrypt_bit_vector(pk, c_star_bool_vector, sec->gamma+sec->tau);
  delete[] c_star_bool_vector;

  for (unsigned int i = 0; i < sec->gamma+sec->tau; i++) {
	in_vector[i] = encrypted_c_star_vector[i];
  }
  delete[] encrypted_c_star_vector;

  unsigned int look_at_index;

  printf("Creating s input vector (starting at index %lu)\n", sec->gamma+sec->tau);
  bool* s_bool_vector = new bool[sec->big_theta];
  for (unsigned long int i = 0; i < sec->big_theta; i++) {
	s_bool_vector[i] = false;
  }

  for (unsigned int i = 0; i < sec->private_key_length; i++) {
	s_bool_vector[sk[i]] = true;
	look_at_index = sk[i];
  }
  printf("s[%u] = %u\n", look_at_index, (bool) s_bool_vector[look_at_index]);

  CipherBit** encrypted_s_vector = encrypt_bit_vector(pk, s_bool_vector, sec->big_theta);
  //delete[] s_bool_vector;

  for (unsigned int i = 0; i < sec->big_theta; i++) {
	in_vector[sec->gamma+sec->tau+i] = encrypted_s_vector[i];
  }
  delete[] encrypted_s_vector;

  printf("Creating z input vector (starting at index %lu)\n", sec->gamma+sec->tau+sec->big_theta);
  bool* z_bool_vector = new bool[sec->big_theta*(n+1)];
  for (unsigned int i = 0; i < sec->big_theta; i++) {
	for (unsigned int j = 0; j < n+1; j++) {
	  z_bool_vector[i*(n+1)+j] = (encrypted_bit->z_vector[i] >> j) & 1;
	}
  }
  CipherBit** encrypted_z_vector = encrypt_bit_vector(pk, z_bool_vector, sec->big_theta*(n+1));
  //delete[] z_bool_vector;

  printf("a[i][0]'s based on orig bool vectors\n");
  int count = 0;
  for (unsigned int i = 0; i < sec->big_theta; i++) {
	if (z_bool_vector[i*(n+1)] && s_bool_vector[i]) {
	  printf("1");
	  count++;
	} else {
	  printf("0");
	}
  }
  printf(" (True count: %u)\n", count);

  for (unsigned int i = 0; i < sec->big_theta*(n+1); i++) {
	in_vector[sec->gamma+sec->tau+sec->big_theta+i] = encrypted_z_vector[i];
  }
  delete[] encrypted_z_vector;

  CipherBit** evaluated_ciphertext = evaluate(output_gates, in_vector, pk);

  bool* evaluated_plaintext = decrypt_bit_vector(sk, evaluated_ciphertext, output_gates.size());

  unsigned long int output_length = ceil(log(n+1) / log(3.0/2)) + 2;

  for (unsigned long int i = 0; i < output_length; i++) {
	printf("%u", (bool) evaluated_plaintext[i]);
  }
  printf("\n");
  for (unsigned long int i = 0; i < output_length; i++) {
	printf("%u", (bool) evaluated_plaintext[output_length + i]);
  }
  printf("\n");

  decrypt_bit(*encrypted_bit, sk);
}

std::vector<Gate*> FullyHomomorphic::create_decryption_cicuit() {
  // Assumes input will be a long vector with:
  //   c* in bits 0...(gamma+tau-1) (LSB first?)
  //   s indicator vector in bits (gamma+tau)...(gamma+tau+big_theta-1) (s0 first)
  //   zi vector in bits (gamma+tau+big_theta+i*(n+1))...(gamma+tau+big_theta+(i+1)*(n+1)-1) (LSB first) (i is 0-indexed)
  //     where n = ceil(log(theta))+3

  unsigned int n = ceil(log2(sec->theta)) + 3;

  Gate* input_zero = new Gate(InputLiteral, false, sec);
  Gate* input_one = new Gate(InputLiteral, true, sec);

  Gate** c_star = new Gate*[sec->gamma+sec->tau];
  for (unsigned long int i = 0; i < sec->gamma+sec->tau; i++) {
	//c_star[i] = new Gate(Input, *(in_vector[i]), lambda);
	c_star[i] = new Gate(Input, i, sec);
  }

  Gate** s = new Gate*[sec->big_theta];
  for (unsigned int i = 0; i < sec->big_theta; i++) {
	//s[i] = new Gate(Input, *(in_vector[gamma+tau+i]), lambda);
	s[i] = new Gate(Input, sec->gamma+sec->tau+i, sec);
  }

  Gate*** z = new Gate**[sec->big_theta];
  for (unsigned int i = 0; i < sec->big_theta; i++) {
	z[i] = new Gate*[n+1];
	for (unsigned int j = 0; j < n+1; j++) {
	  //z[i][j] = new Gate(Input, *(in_vector[gamma+tau+big_theta+i*(n+1)+j]), lambda);
	  z[i][j] = new Gate(Input, sec->gamma+sec->tau+sec->big_theta+i*(n+1)+j, sec);
	}
  }

  // a[i][j] is jth bit of a_i (0-indexed)
  Gate*** a = new Gate**[sec->big_theta];
  for (unsigned int i = 0; i < sec->big_theta; i++) {
	a[i] = new Gate*[n+1];
	for (unsigned int j = 0; j < n+1; j++) {
	  a[i][j] = new Gate(And, s[i], z[i][j], sec);
	  // s[i]->add_output(a[i][j]);
	  // z[i][j]->add_output(a[i][j]);
	}
  }

  unsigned long int w_length = log2(sec->theta+1);
  unsigned long int p_length = pow(2, w_length);
  Gate* temp_and;
  Gate**** p = new Gate***[n+1];
  for (unsigned int i = 0; i < n+1; i++) {
	p[i] = new Gate**[p_length+1];
	for (unsigned int j = 0; j < p_length+1; j++) {
	  p[i][j] = new Gate*[sec->big_theta+1];
	  if (j == 0) {
		p[i][0][0] = input_one;
	  } else {
		p[i][j][0] = input_zero;
	  }
	  for (unsigned int k = 1; k < sec->big_theta+1; k++) {
		if (j == 0) {
		  p[i][0][k] = input_one;
		} else {
		  temp_and = new Gate(And, p[i][j-1][k-1], a[k-1][i], sec);
		  // p[i][j-1][k-1]->add_output(temp_and);
		  // a[k-1][i]->add_output(temp_and);
		  p[i][j][k] = new Gate(Xor, temp_and, p[i][j][k-1], sec);
		  // temp_and->add_output(p[i][j][k]);
		  // p[i][j][k-1]->add_output(p[i][j][k]);
		}
	  }
	}
  }

  Gate*** w = new Gate**[n+1];
  for (unsigned long int i = 0; i < n+1; i++) {
	w[i] = new Gate*[w_length+1];
	unsigned long int k = 0;
	for (unsigned long int j = p_length; j > 0; j >>= 1) {
	  w[i][k++] = p[i][j][sec->big_theta];
	}
  }

  Gate*** temp;
  unsigned int cur_w_length = w_length+1;
  printf("n+1 = %u\n", n+1);
  for (unsigned int i = n+1; i > 2; i = (i/3)*2 + i%3) {
	unsigned int used_slots = 0;
	// Calculate w[3*j] + w[3*j+1] + w[3*j+2] = x + y
	// Assign x and y to next available slots in w that have already been processed
	for (unsigned int j = 0; j < i/3; j++) {
	  temp = create_3_for_2_circuit(w[3*j], w[3*j+1], w[3*j+2], cur_w_length);
	  w[used_slots++] = temp[0];
	  w[used_slots++] = temp[1];
	}
	// Move left over slots down for next iteration
	for (unsigned int j = 0; j < i%3; j++) {
	  w[used_slots] = new Gate*[cur_w_length+1];
	  for (unsigned int k = 0; k < cur_w_length; k++) {
		w[used_slots][k] = w[(i/3)*3 + j][k];
	  }
	  w[used_slots][cur_w_length] = new Gate(InputLiteral, false, sec);
	  used_slots++;
	}
	printf("used_slots: %u\n", used_slots);
	cur_w_length++;
  }
							  
  std::vector<Gate*> outputs;

  Gate* output_gate;
  for (unsigned int i = 0; i < cur_w_length; i++) {
	output_gate = new Gate(Output, w[0][i], sec);
	outputs.push_back(output_gate);
  }
  for (unsigned int i = 0; i < cur_w_length; i++) {
	output_gate = new Gate(Output, w[1][i], sec);
	outputs.push_back(output_gate);
  }
  return outputs;
}

/*
 * return[0] and return[1] are the two n+1 sized outputs
 */
Gate*** FullyHomomorphic::create_3_for_2_circuit(Gate** a, Gate** b, Gate** c, unsigned int n) {
  Gate** d = new Gate*[n+1];
  Gate** e = new Gate*[n+1];
  Gate* temp_xor;
  for (unsigned int i = 0; i < n; i++) {
	temp_xor = new Gate(Xor, a[i], b[i], sec);
	d[i] = new Gate(Xor, temp_xor, c[i], sec);
  }
  d[n] = new Gate(InputLiteral, false, sec);

  Gate* temp_and1;
  Gate* temp_and2;
  Gate* temp_and3;
  e[0] = new Gate(InputLiteral, false, sec);
  for (unsigned int i = 0; i < n; i++) {
	temp_and1 = new Gate(And, a[i], b[i], sec);
	temp_and2 = new Gate(And, b[i], c[i], sec);
	temp_and3 = new Gate(And, a[i], c[i], sec);
	temp_xor = new Gate(Xor, temp_and1, temp_and2, sec);
	e[i+1] = new Gate(Xor, temp_xor, temp_and3, sec);
  }

  Gate*** output = new Gate**[2];
  output[0] = d;
  output[1] = e;
  return output;
}

void FullyHomomorphic::store_cipher_bit(FILE* stream, CipherBit &c) {
  mpz_out_raw(stream, c.old_ciphertext);
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

/* TODO:
 * - Still have a small memory leak. I think it has to do with cipher bits not getting delete[]'d, but I get a double free when I try to...
 */
