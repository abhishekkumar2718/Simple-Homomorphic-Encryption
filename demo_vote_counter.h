#include "fully_homomorphic.h"

class DemoVoteCounter {
  private:
    SecuritySettings* sec;
    FullyHomomorphic* fh;

    CipherBit **votes;

    PrivateKey sk;
    PublicKey pk;

    unsigned int num_votes, num_candidates;

    bool verify_vote(unsigned int vote_id);
  public:
    DemoVoteCounter(unsigned int num_candidates);

    void get_votes();
    void verify_votes();
    void count_votes();
};
