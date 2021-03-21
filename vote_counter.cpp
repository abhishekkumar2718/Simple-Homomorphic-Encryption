#include "vote_counter.h"

VoteCounter::VoteCounter(unsigned int num_candidates) : num_votes(0), num_candidates(num_candidates) {
  sec = new SecuritySettings(4); // lambda: 4

  fh = new FullyHomomorphic(sec);
  fh->generate_key_pair(sk, pk);

  std::cout << *sec << std::endl;
}

void VoteCounter::get_votes() {
  std::vector<CipherBit*> encrypted_votes;

  while (true) {
    unsigned int vote;

    std::cout << "Please enter a vote (1 - " << num_candidates <<"), or 0 to terminate: ";
    std::cin >> vote;
    std::cout << std::endl;

    if (vote < 0 || vote > num_candidates) {
      std::cout << "Invalid vote, please try again!" << std::endl;
      continue;
    } else if (vote == 0)
      break;

    num_votes++;

    for (unsigned int i = 0; i < num_candidates; i++) {
      CipherBit *encrypted_bit = new CipherBit;

      fh->encrypt_bit(*encrypted_bit, pk, (i == vote - 1));
      encrypted_votes.push_back(encrypted_bit);

      std::cout << *encrypted_bit << std::endl;
    }
  }

  votes = new CipherBit*[encrypted_votes.size()];
  for (unsigned int i = 0; i < encrypted_votes.size(); i++)
    votes[i] = encrypted_votes[i];
}

void VoteCounter::verify_votes() {
  std::cout << "--- Verifying Votes ---" << std::endl;

  bool failed = false;
  for (unsigned int i = 0; i < num_votes; i++) {
    if (verify_vote(i))
      std::cout << "Vote " << i + 1 << " verified" << std::endl;
    else {
      std::cout << "Vote " << i + 1 << " failed to verify!" << std::endl;
      failed = true;
    }
  }

  if (!failed)
    std::cout << "All votes verified" << std::endl;
}

bool VoteCounter::verify_vote(unsigned int vote_id) {
  unsigned long int w_length = log2(num_candidates);
  unsigned long int p_length = pow(2, w_length);

  Gate *input_zero = new Gate(InputLiteral, false, sec);
  Gate *input_one = new Gate(InputLiteral, true, sec);

  Gate ***p = new Gate**[num_candidates + 1];

  // Sum cipherbits for every candidate by a voter.
  for (unsigned int i = 0; i <= num_candidates; i++) {
    p[i] = new Gate*[p_length + 1];
    p[i][0] = input_one;
  }

  for (unsigned int j = 1; j <= p_length; j++)
    p[0][j] = input_zero;

  for (unsigned long int i = 1; i <= num_candidates; i++) {
    Gate *input = new Gate(Input, vote_id * num_candidates + i - 1, sec);

    for (unsigned int j = 1; j <= p_length; j++) {
      Gate *temporary_gate;

      temporary_gate = new Gate(And, p[i - 1][j - 1], input, sec);
      p[i][j] = new Gate(Xor, temporary_gate, p[i - 1][j], sec);
    }
  }

  std::vector<Gate*> output_gates;
  for (unsigned long int i = p_length; i > 0; i >>= 1) {
    Gate *output = new Gate(Output, p[num_candidates][i], sec);
    output_gates.push_back(output);
  }

  CipherBit **encrypted_results = fh->evaluate(output_gates, votes, pk);

  // Since exactly one of the cipherbits should be set,
  // should be of the form 0 0 0 0 ... 1
  auto decrypted_bits = fh->decrypt_bit_vector(sk, encrypted_results, w_length + 1);

  for (unsigned int i = 0; i < w_length; i++)
    if (decrypted_bits[i]) return false;

  if (!decrypted_bits[w_length]) return false;

  return true;
}

void VoteCounter::count_votes() {
  std::cout << "--- Counting Votes ---" << std::endl;

  unsigned long int w_length = log2(num_votes);
  unsigned long int p_length = pow(2, w_length);

  Gate *input_one = new Gate(InputLiteral, true, sec);
  Gate *input_zero = new Gate(InputLiteral, false, sec);

  Gate*** candidate_total = new Gate**[num_candidates];

  // Sum cipherbits in a candidate-major fashion
  for (unsigned int candidate = 0; candidate < num_candidates; candidate++) {
    Gate*** p = new Gate**[num_votes + 1];

    for (unsigned int i = 0; i <= num_votes; i++) {
      p[i] = new Gate*[p_length + 1];
      p[i][0] = input_one;
    }

    for (unsigned int j = 1; j <= p_length; j++)
      p[0][j] = input_zero;

    for (unsigned long int i = 1; i <= num_votes; i++) {
      Gate *input = new Gate(Input, (i - 1)*num_candidates + candidate, sec);

      for (unsigned int j = 1; j <= p_length; j++) {
        Gate *temporary_gate = new Gate(And, p[i - 1][j - 1], input, sec);
        p[i][j] = new Gate(Xor, temporary_gate, p[i - 1][j], sec);
      }
    }

    candidate_total[candidate] = new Gate*[w_length + 1];

    for (unsigned long int i = p_length, j = 0; i > 0; i >>= 1, j++)
      candidate_total[candidate][j] = p[num_votes][i];
  }

  Gate* output;
  std::vector<Gate*> output_gates;
  for (unsigned int candidate = 0; candidate < num_candidates; candidate++) {
    for (unsigned long int i = 0; i <= w_length; i++) {
      output = new Gate(Output, candidate_total[candidate][i], sec);
      output_gates.push_back(output);
    }
  }

  CipherBit** encrypted_results = fh->evaluate(output_gates, votes, pk);

  auto decrypted_bits = fh->decrypt_bit_vector(sk, encrypted_results, num_candidates*(w_length  + 1));

  for (unsigned int c = 0; c < num_candidates; c++) {
    auto base = c * (w_length + 1);

    std::cout << "Candidate " << c + 1 << ": ";
    for (unsigned int i = 0; i < w_length + 1; i++)
      std::cout << decrypted_bits[base + i] << " ";
    std::cout << std::endl;
  }
}
