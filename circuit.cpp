#include "circuit.h"
#include <algorithm>

// Input gate
Gate::Gate(GateType gate_type, unsigned long input_index, SecuritySettings *sec) : sec(sec), gate_type(gate_type), input_index(input_index) {
  input1_resolved = true;
  input2_resolved = true;

  degree = 1;
  norm = 1;

  output_cipher_bits = new CipherBit;
  output_cipher_bits->initialize_ciphertext();
}

// Input Literal gate
Gate::Gate(GateType gate_type, bool input, SecuritySettings *sec) : sec(sec), gate_type(gate_type) {
  input1_resolved = true;
  input2_resolved = true;

  degree = 0;
  norm = input;

  output_cipher_bits = new CipherBit;
  output_cipher_bits->initialize_ciphertext();

  mpz_set_ui(output_cipher_bits->old_ciphertext, input);

  auto z_vector_length = sec->public_key_y_vector_length;
  output_cipher_bits->initialize_z_vector(z_vector_length);
  for (unsigned int i = 0; i < z_vector_length; i++)
    output_cipher_bits->z_vector[i] = 0;
}

// Output gate
Gate::Gate(GateType gate_type, Gate *input, SecuritySettings *sec) : sec(sec), gate_type(gate_type), input1(input) {
  input1_resolved = false;
  input2_resolved = true;

  degree = input->degree;
  norm = input->norm;

  input->add_output_gate(this);

  output_cipher_bits = new CipherBit;
  output_cipher_bits->initialize_ciphertext();
}

// Logic gate
Gate::Gate(GateType gate_type, Gate *input1, Gate *input2, SecuritySettings *sec) : sec(sec), gate_type(gate_type), input1(input1), input2(input2) {
  input1_resolved = false;
  input2_resolved = false;

  input1->add_output_gate(this);
  input2->add_output_gate(this);

  // TODO: Figure out how addition and multiplication of polynomial affects
  // the L1 norm.
  if (gate_type == And) {
	degree = input1->degree + input2->degree;
	norm = std::max(input1->norm, input2->norm);
  } else {
	degree = std::max(input1->degree, input2->degree);
	norm = input1->norm + input2->norm;
  }

  output_cipher_bits = new CipherBit;
  output_cipher_bits->initialize_ciphertext();
}

//  Evaluate the gate (as a part of larger circuit)
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

    // If the ciphertext is greater than public key integers, reduce
    // it by taking remainders
    //
    // TODO: Add better description
    if (output_cipher_bits->greater_than_base_2(sec->gamma))
      output_cipher_bits->reduce_by_public_key(*sec, pk);

    output_cipher_bits->calculate_z_vector(*sec, pk);
  }

  resolve_output_gates();
}

// Forward the ciphertext, Z-vector from one of the input gates
void Gate::forward_ciphertext(CipherBit** inputs) {
  auto input = inputs[input_index];

  mpz_set(output_cipher_bits->old_ciphertext, input->old_ciphertext);

  auto z_vector_length = sec->public_key_y_vector_length;
  output_cipher_bits->initialize_z_vector(z_vector_length);
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
