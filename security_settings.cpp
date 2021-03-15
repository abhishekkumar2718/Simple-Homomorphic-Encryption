#include "security_settings.h"

SecuritySettings::SecuritySettings(unsigned long int lambda) : lambda(lambda) {
  gamma = lambda*lambda*lambda*lambda*lambda;
  eta = lambda*lambda * ( ceil( log2( lambda*lambda ) ) );
  rho = lambda;
  rho_ = 2*lambda;
  tau = gamma + lambda;
  kappa = gamma*eta/rho_; // WARNING: This may need to be ceiling instead of floor
  theta = lambda;
  big_theta = kappa*lambda;

  private_key_length = theta;
  public_key_old_key_length = tau+1;
  public_key_y_vector_length = big_theta;
}

ostream& operator<<(ostream& os, const SecuritySettings& security) {
  os << "Security Parameters" << endl;
  os << "Bit-length of integers in public key (gamma): " << security.gamma << endl;
  os << "Bit-length of secret key (eta): " << security.eta << endl;
  os << "Bit-length of noise (rho): " << security.rho << endl;
  os << "Bit-length of secondary noise parameter (rho'): " << security.rho_ << endl;
  os << "Number of integers in public key (tau): " << security.tau << endl;
  os << "Bits of precision of indicator (kappa): " << security.kappa << endl;
  os << "Private key length (theta): " << security.theta << endl;
  os << "Public Key Indicator Vector Length (big-theta): " << security.big_theta << endl;

  return os;
}
