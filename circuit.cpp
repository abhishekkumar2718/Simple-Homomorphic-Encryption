#include "circuit.h"

void Gate::initialize_output_cipher_bits() {
  output_cipher_bits = new CipherBit;
  mpz_init(output_cipher_bits->old_ciphertext);
}

// Input gate
Gate::Gate(GateType gate_type, unsigned long input_index, SecuritySettings *sec) : sec(sec), gate_type(gate_type), input_index(input_index) {
  initialize_output_cipher_bits();

  input1_resolved = true;
  input2_resolved = true;

  degree = 1;
  norm = 1;
}

// Input Literal gate
Gate::Gate(GateType gate_type, bool input, SecuritySettings *sec) : sec(sec), gate_type(gate_type) {
  initialize_output_cipher_bits();

  input1_resolved = true;
  input2_resolved = true;

  mpz_set_ui(output_cipher_bits->old_ciphertext, input);

  auto z_vector_length = sec->public_key_y_vector_length;
  output_cipher_bits->z_vector = new unsigned long[z_vector_length];
  for (unsigned int i = 0; i < z_vector_length; i++)
	output_cipher_bits->z_vector[i] = 0;

  degree = 0;
  norm = input;
}

// Output gate
Gate::Gate(GateType gate_type, Gate *input, SecuritySettings *sec) : sec(sec), gate_type(gate_type), input1(input) {
  initialize_output_cipher_bits();

  input1_resolved = false;
  input2_resolved = true;

  degree = input->degree;
  norm = input->norm;
  input->add_output_gate(this);
}

// Logic gate
Gate::Gate(GateType gate_type, Gate *input1, Gate *input2, SecuritySettings *sec) : sec(sec), gate_type(gate_type), input1(input1), input2(input2) {
  initialize_output_cipher_bits();

  input1_resolved = false;
  input2_resolved = false;

  input1->add_output_gate(this);
  input2->add_output_gate(this);

  // TODO: Figure out how addition and multiplication of polynomial affects
  // the L1 norm.
  if (gate_type == And) {
	degree = input1->degree + input2->degree;
	norm = max(input1->norm, input2->norm);
  } else {
	degree = max(input1->degree, input2->degree);
	norm = input1->norm + input2->norm;
  }
}

void Gate::evaluate(const PublicKey &pk) {
  if (!input1_resolved || !input2_resolved)
      throw new std::runtime_error("This gate isn't ready to be evaluated!");

  if (gate_type == Output) {
    output_cipher_bits = input1->output_cipher_bits;
  } else if (gate_type == And || gate_type == Xor) {
    if (gate_type == And)
      mpz_mul(output_cipher_bits->old_ciphertext, input1->output_cipher_bits->old_ciphertext, input2->output_cipher_bits->old_ciphertext);
    else
      mpz_add(output_cipher_bits->old_ciphertext, input1->output_cipher_bits->old_ciphertext, input2->output_cipher_bits->old_ciphertext);

    if (is_ciphertext_greater_than_public_key_integers())
      mod_reduce(pk);

    calc_z_vector(pk);
  }

  resolve_output_gates();
}

// If the ciphertext is larger than the public key integers, reduce it by taking remainders
// TODO: Needs more clarification
void Gate::mod_reduce(const PublicKey &pk) {
  for (int i = sec->gamma; i >= 0; i--)
    mpz_mod(output_cipher_bits->old_ciphertext, output_cipher_bits->old_ciphertext, pk.old_key_extra[i]);
}

// TODO: This duplicates code in fully_homomorphic.cpp. Split this out into possibly a CipherBit class
void Gate::calc_z_vector(const PublicKey &pk) {
  unsigned int precision = ceil(log2(sec->theta)) + 3;
  unsigned long bitmask = (1l << (precision + 1)) - 1;
  auto z_vector_length = sec->public_key_y_vector_length;

  output_cipher_bits->z_vector = new unsigned long[z_vector_length];

  mpz_t temp;
  mpz_init(temp);
  for (unsigned int i = 0; i < z_vector_length; i++) {
	mpz_mul(temp, output_cipher_bits->old_ciphertext, pk.y_vector[i]);
	mpz_fdiv_q_2exp(temp, temp, sec->kappa-precision);
	output_cipher_bits->z_vector[i] = mpz_get_ui(temp) & bitmask;
  }
  mpz_clear(temp);
}

// Forward the ciphertext, Z-vector from one of the input gates
void Gate::forward_ciphertext(CipherBit** inputs) {
  auto input = inputs[input_index];

  mpz_set(output_cipher_bits->old_ciphertext, input->old_ciphertext);

  auto z_vector_length = sec->public_key_y_vector_length;
  output_cipher_bits->z_vector = new unsigned long[z_vector_length];
  for (unsigned int i = 0; i < z_vector_length; i++)
	output_cipher_bits->z_vector[i] = input->z_vector[i];
}

// For each of output gates, resolve their input status
void Gate::resolve_output_gates() {
  for (auto &output_gate: outputs) {
    if (output_gate->input1 == this) 
      output_gate->input1_resolved = true;

    if (output_gate->input2 == this)
      output_gate->input2_resolved = true;
  }
}

void Gate::add_output_gate(Gate *output_gate) {
  outputs.push_back(output_gate);
}

const bool Gate::is_ciphertext_greater_than_public_key_integers() {
    // public_key_size = 2 ^ bit-length of integers in the public key
    mpz_t public_key_size;
    mpz_init2(public_key_size, sec->gamma + 1);
    mpz_setbit(public_key_size, sec->gamma);

    bool result = (mpz_cmp(output_cipher_bits->old_ciphertext, public_key_size) > 0);

    mpz_clear(public_key_size);

    return result;
}
