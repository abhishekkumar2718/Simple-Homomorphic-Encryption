#ifndef VOTE_COUNTER_H
#define VOTE_COUNTER_H

#include "fully_homomorphic.h"

class VoteCounter {
  private:
    SecuritySettings* sec;
    FullyHomomorphic* fh;

    CipherBit **votes;

    PrivateKey sk;
    PublicKey pk;

    unsigned int num_votes, num_candidates;

    bool verify_vote(unsigned int vote_id);
  public:
    VoteCounter(unsigned int num_candidates);

    void get_votes();
    void verify_votes();
    void count_votes();
};

#endif // VOTE_COUNTER_H
