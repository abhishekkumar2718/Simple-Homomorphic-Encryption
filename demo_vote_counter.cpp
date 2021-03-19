#include "demo_vote_counter.h"

bool DemoVoteCounter::verify_vote(unsigned int vote_id) {
  unsigned long int w_length = log2(num_candidates);
  unsigned long int p_length = pow(2, w_length);

  Gate *input, *temp_and;

  Gate *input_zero = new Gate(InputLiteral, false, sec);
  Gate *input_one = new Gate(InputLiteral, true, sec);

  Gate ***p = new Gate**[num_candidates + 1];

  for (unsigned long int i = 0; i < num_candidates + 1; i++) { //row
    p[i] = new Gate*[p_length + 1];
    p[i][0] = input_one;

    if (i > 0)
      input = new Gate(Input, vote_id * num_candidates + i - 1, sec);

    for (unsigned int j = 1; j < p_length+1; j++) { //col
      if (i == 0)
        p[0][j] = input_zero;
      else {
        temp_and = new Gate(And, p[i - 1][j - 1], input, sec);
        p[i][j] = new Gate(Xor, temp_and, p[i - 1][j], sec);
      }
    }
  }

  std::vector<Gate*> output_gates;
  for (unsigned long int i = p_length; i > 0; i >>= 1) {
    Gate *output = new Gate(Output, p[num_candidates][i], sec);
    output_gates.push_back(output);
  }

  CipherBit **encrypted_results = fh->evaluate(output_gates, votes, pk);

  auto decrypted_bits = fh->decrypt_bit_vector(sk, encrypted_results, w_length + 1);

  for (unsigned int i = 0; i < w_length; i++) {
    if (decrypted_bits[i]) return false;
  }

  return true;
}

DemoVoteCounter::DemoVoteCounter(unsigned int num_candidates) : num_votes(0), num_candidates(num_candidates) {
  sec = new SecuritySettings(4); // lambda: 4

  fh = new FullyHomomorphic(sec);
  fh->generate_key_pair(sk, pk);

  cout << *sec << endl;
}

void DemoVoteCounter::get_votes() {
  std::vector<CipherBit*> encrypted_votes;

  while (true) {
    unsigned int vote;

    std::cout << "Please enter a vote (1 - " << num_candidates <<"), or 0 to terminate: ";
    std::cin >> vote;

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

void DemoVoteCounter::verify_votes() {
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

void DemoVoteCounter::count_votes() {
  printf("Counting votes\n");
  Gate* input_zero = new Gate(InputLiteral, false, sec);
  Gate* input_one = new Gate(InputLiteral, true, sec);

  Gate* input;
  unsigned long int w_length = log2(num_votes);
  unsigned long int p_length = pow(2, w_length);
  Gate* temp_and;
  Gate*** candidate_total = new Gate**[num_candidates];
  for (unsigned int candidate = 0; candidate < num_candidates; candidate++) {
	Gate*** p = new Gate**[num_votes+1];
	for (unsigned long int i = 0; i < num_votes+1; i++) { //row
	  p[i] = new Gate*[p_length+1];
	  p[i][0] = input_one;
	  if (i > 0) {
		input = new Gate(Input, (i-1)*num_candidates + candidate, sec);
	  }
	  for (unsigned int j = 1; j < p_length+1; j++) { //col
		if (i == 0) {
		  p[0][j] = input_zero;
		} else {
		  temp_and = new Gate(And, p[i-1][j-1], input, sec);
		  p[i][j] = new Gate(Xor, temp_and, p[i-1][j], sec);
		}
	  }
	}
	candidate_total[candidate] = new Gate*[w_length+1];
	int cur_index = 0;
	for (unsigned long int i = p_length; i > 0; i >>= 1) {
	  candidate_total[candidate][cur_index++] = p[num_votes][i];
	}
  }

  Gate* output;
  std::vector<Gate*> output_gates;
  for (unsigned int candidate = 0; candidate < num_candidates; candidate++) {
	for (unsigned long int i = 0; i < w_length+1; i++) {
	  output = new Gate(Output, candidate_total[candidate][i], sec);
	  output_gates.push_back(output);
	}
  }

  CipherBit** encrypted_results = fh->evaluate(output_gates, votes, pk);

  auto decrypted_bits = fh->decrypt_bit_vector(sk, encrypted_results, num_candidates*(w_length  + 1));

  for (unsigned int c = 0; c < num_candidates; c++) {
    auto base = c * (w_length + 1);

    for (unsigned int i = 0; i < w_length + 1; i++)
      std::cout << decrypted_bits[base + i] << " ";
    std::cout << std::endl;
  }
}

int main(int argc, char** argv) {
  if (argc != 2) {
    std::cout << "Takes one parameter, the number of candidates in the election" << std:: endl;
    exit(1);
  }

  unsigned int num_candidates = atoi(argv[1]);

  DemoVoteCounter demo(num_candidates);
  demo.get_votes();
  demo.verify_votes();
  demo.count_votes();

}
