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
// TODO: Ask others whether it is correct
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

// Generate private key, which consists of tau unique integers between [0, theta)
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

// TODO: What is somewhat public key?
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

    // The largest number X[0] must be odd
    // TODO: Document meaning of mod_result
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

// Generates gamma + 1 random integers of the form 2*(p*q[i] + r[i])
// where p is the secret key, q lies in [2^(gamma + i - 1)/p, 2^(gamma + i)/p)
// and r lies in [-2^rho - 1, 2^rho + 2)
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

mpz_t_arr FullyHomomorphic::generate_y_vector(const PrivateKey &sk) {
  // TODO: What's x_p?
  mpz_t x_p, remainder, half_ssk;

  mpz_init(x_p);
  mpz_init(remainder);
  mpz_init(half_ssk);

  mpz_setbit(x_p, sec->kappa);           // x_p: 2^kappa
  mpz_fdiv_qr(x_p, remainder, x_p, ssk); // x_p: 2^kappa/ssk, remainder: (2^kappa % ssk)
  mpz_fdiv_q_2exp(half_ssk, ssk, 1);     // half_ssk: ssk/2

  // TODO: What does this check represent?
  if (mpz_cmp(remainder, half_ssk) < 0)
	mpz_add_ui(x_p, x_p, 1);

  mpz_t_arr u_vector = new __mpz_struct* [sec->public_key_y_vector_length];
  generate_u_vector(u_vector, x_p, sk);

  mpz_clear(x_p);
  mpz_clear(remainder);
  mpz_clear(half_ssk);

  return u_vector;
}

void FullyHomomorphic::generate_u_vector(mpz_t_arr result, mpz_t x_p, unsigned int* S) {
  mpz_t sum_u_in_s;
  mpz_init(sum_u_in_s);

  unsigned int final_s = rng.GenerateWord32(0, sec->private_key_length-1);
  for (unsigned int i = 0; i < sec->public_key_y_vector_length; i++) {
	result[i] = new mpz_t;
	mpz_init(result[i]);
	mpz_urandomb(result[i], rand_state, sec->kappa);
  }

  // Sum up all but the last u_i where i is in S
  for (unsigned int i = 0; i < sec->private_key_length; i++) {
	if (i == final_s)
	  continue;
	mpz_add(sum_u_in_s, sum_u_in_s, result[S[i]]);
  }

  mpz_t modulus;
  mpz_init2(modulus, sec->kappa+2);
  mpz_setbit(modulus, sec->kappa+1);

  mpz_mod(sum_u_in_s, sum_u_in_s, modulus); // Should replace this with a bitmask if it's faster...
  if (mpz_cmp(x_p, sum_u_in_s) > 0) {
	mpz_sub(result[S[final_s]], x_p, sum_u_in_s);
  } else {
	mpz_sub(result[S[final_s]], x_p, sum_u_in_s);
	mpz_add(result[S[final_s]], result[S[final_s]], modulus);
  }

  mpz_clear(sum_u_in_s);
  mpz_clear(modulus);
}

void FullyHomomorphic::choose_random_d(mpz_t result, const SomewhatPrivateKey p) {
  mpz_t temp;
  mpz_init(temp);

  mpz_t range;
  mpz_init2(range, sec->gamma+1);
  mpz_setbit(range, sec->gamma); // 2^gamma
  mpz_cdiv_q(range, range, p); // (2^gamma)/p

  mpz_urandomm(temp, rand_state, range); // pick a q
  mpz_clear(range);

  mpz_mul(result, p, temp); // p*q

  mpz_init2(range, sec->rho+2);
  mpz_setbit(range, sec->rho+1); // 2^(rho+1)
  mpz_add_ui(range, range, 1); // 2^(rho+1) + 1

  mpz_urandomm(temp, rand_state, range); // pick a r
  mpz_clear(range);

  mpz_t shift;
  mpz_init2(shift, sec->rho+1);
  mpz_setbit(shift, sec->rho); // 2^(rho)
  mpz_sub_ui(shift, shift, 1); // 2^rho - 1
  mpz_sub(temp, temp, shift); // Now r is in range [-2^rho + 1, 2^rho)
  mpz_clear(shift);

  mpz_add(result, result, temp); // p*q + r
  mpz_clear(temp);
}

/* ENCRYPTION */
void FullyHomomorphic::old_encrypt_bit(mpz_t result, const PublicKey &pk, const bool m) {
  mpz_t sum;
  mpz_init(sum);

  CryptoPP::byte randomness = rng.GenerateByte();
  unsigned int randomness_counter = 0; // Current bit of randomness being used

  for (unsigned int i = 1; i < sec->public_key_old_key_length; i++) {
	if (randomness_counter == 8) {
	  // grab more randomness
	  randomness = rng.GenerateByte();
	  randomness_counter = 0;
	}
	if ((randomness << randomness_counter) >> 7) {
	  mpz_add(sum, sum, pk.old_key[i]);
	}
	randomness_counter++;
  }

  mpz_mul_2exp(sum, sum, 1); // multiply by 2

  mpz_t r;
  mpz_init(r);

  mpz_t upper_bound;
  mpz_init2(upper_bound, sec->rho_+2);
  mpz_setbit(upper_bound, sec->rho_+1);
  mpz_sub_ui(upper_bound, upper_bound, 2);

  mpz_urandomm(r, rand_state, upper_bound);
  mpz_clear(upper_bound);

  mpz_t offset;
  mpz_init2(offset, sec->rho_+1);
  mpz_setbit(offset, sec->rho_);
  mpz_sub_ui(offset, offset, 1);

  mpz_sub(r, r, offset);
  mpz_clear(offset);
  // r should now be in the exclusive range (-2^rho', 2^rho')

  mpz_mul_2exp(r, r, 1); // multiply by 2

  mpz_add_ui(result, result, m);
  mpz_add(result, result, r);
  mpz_add(result, result, sum);
  mpz_correct_mod(result, result, pk.old_key[0]);

  mpz_clear(r);
  mpz_clear(sum);
}

void FullyHomomorphic::encrypt_bit(CipherBit &result, const PublicKey &pk, const bool m) {
  mpz_init(result.old_ciphertext);
  old_encrypt_bit(result.old_ciphertext, pk, m);

  unsigned int precision = ceil(log2(sec->theta)) + 3;

  result.z_vector = new unsigned long [sec->public_key_y_vector_length];

  unsigned long bitmask = (1l << (precision+1)) - 1;

  mpz_t temp;
  mpz_init(temp);
  // unsigned int __gmp_n;
  for (unsigned int i = 0; i < sec->public_key_y_vector_length; i++) {
	mpz_mul(temp, result.old_ciphertext, pk.y_vector[i]);
	mpz_fdiv_q_2exp(temp, temp, sec->kappa-precision);
	result.z_vector[i] = mpz_get_ui(temp) & bitmask;
  }
  mpz_clear(temp);
}

/* DECRYPTION */
bool FullyHomomorphic::decrypt_bit(const CipherBit &c, const PrivateKey &sk) {
  mpz_t sum;
  mpz_init(sum);

  for (unsigned int i = 0; i < sec->private_key_length; i++) {
	mpz_add_ui(sum, sum, c.z_vector[sk[i]]);
  }

  mpz_t rounded_sum;
  mpz_init(rounded_sum);
  mpz_t remainder;
  mpz_init(remainder);
  unsigned int precision = ceil(log2(sec->theta)) + 3;
  // It's interesting that this needed to be ceiling division... I wonder if the
  // rounding above in key generation needs to be as well...
  mpz_cdiv_r_2exp(remainder, sum, precision);
  mpz_fdiv_q_2exp(rounded_sum, sum, precision);

  mpz_t half_sum;
  mpz_init(half_sum);
  mpz_fdiv_q_2exp(half_sum, sum, 1);
  if (mpz_cmp(remainder, half_sum) < 0) {
	mpz_add_ui(rounded_sum, rounded_sum, 1); // fix "rounding" to round up
  }
  mpz_clear(half_sum);
  mpz_clear(remainder);

  // printf("rounded sum: ");
  // mpz_out_str(NULL, 10, rounded_sum);
  // printf("\n");
  // printf("c*: ");
  // mpz_out_str(NULL, 10, c.old_ciphertext);
  // printf("\n");

  mpz_sub(rounded_sum, c.old_ciphertext, rounded_sum);
  // I think this should really be mpz_odd_p, but this seems to give the correct answer... Investigate later
  int return_val = mpz_odd_p(rounded_sum);

  mpz_clear(sum);
  mpz_clear(rounded_sum);
  return return_val;
}

bool old_decrypt_bit(mpz_t c, mpz_t sk) {
  mpz_t temp;
  mpz_init(temp);
  mpz_correct_mod(temp, c, sk);
  int return_val = mpz_odd_p(temp);
  mpz_clear(temp);
  return return_val;
}

void FullyHomomorphic::clear_cipher_bit(CipherBit &c) {
  mpz_clear(c.old_ciphertext);
  delete[] c.z_vector;
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
	//clear_cipher_bit(c);
  }
  return c_vector;
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
