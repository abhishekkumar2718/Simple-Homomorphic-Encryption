#include "vote_counter.h"
#include <iostream>

int main(int argc, char** argv) {
  if (argc != 2) {
    std::cout << "Takes one parameter, the number of candidates in the election" << std::endl;
    exit(1);
  }

  unsigned int num_candidates = atoi(argv[1]);

  VoteCounter vote_counter(num_candidates);
  vote_counter.get_votes();
  vote_counter.verify_votes();
  vote_counter.count_votes();

  return 0;
}
