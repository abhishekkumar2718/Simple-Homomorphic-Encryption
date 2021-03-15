#ifndef CIRCUIT_H
#define CIRCUIT_H

#include "type_defs.h"
#include "security_settings.h"
#include "utilities.h"
#include <vector>
#include <stdexcept>
#include <cmath>


enum GateTypeEnum {And, Xor, Input, InputLiteral, Output};
typedef enum GateTypeEnum GateType;

class Gate {
  private:
    SecuritySettings *sec;
    void initialize_output_cipher_bits();

    // TODO: Refactor
    void calc_z_vector(const PublicKey &pk);

    // Add output gate to the vector of output gates
    void add_output_gate(Gate *output_gate);

    // For each of output gates, resolve their input status
    void resolve_output_gates();

    const bool is_ciphertext_greater_than_public_key_integers();

    // If the ciphertext is larger than the public key integers,
    // reduce by taking remaninders
    void mod_reduce(const PublicKey &pk);
  public:
    GateType gate_type;
    unsigned int id;
    unsigned long input_index;
    Gate *input1, *input2;                 // Pointer to the input gates
    bool input1_resolved, input2_resolved; // Is the output of Input i computed?
    CipherBit* output_cipher_bits;
    std::vector<Gate*> outputs;

    // Degree of the polynomial.
    // Adds up culmatively through multiple layers of gates.
    unsigned long int degree;

    // L1-Norm - sum of absolute values of the coefficients of the polynomial.
    // Adds up culmatively through multiple layers of gates.
    unsigned long int norm;

    // Input gates
    //Gate(GateType gate_type, CipherBit* value, unsigned long lambda);
    Gate(GateType gate_type, unsigned long input_index, SecuritySettings *sec);

    // Input Literal gates
    Gate(GateType gate_type, bool input, SecuritySettings *sec);

    // Output gates
    Gate(GateType gate_type, Gate *input, SecuritySettings *sec);

    // Logic gates
    Gate(GateType gate_type, Gate *input1, Gate *input2, SecuritySettings *sec);

    void evaluate(const PublicKey &pk);

    const bool is_input() {return gate_type == Input;}

    // Forward ciphertext, Z-vector from one of the input gates
    void forward_ciphertext(CipherBit** inputs);
};

#endif //CIRCUIT_H
