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

std::ostream& operator<<(std::ostream& os, const SecuritySettings& security) {
  os << "--- Security Parameters ---" << std::endl;
  os << "Lambda: " << security.lambda << std::endl;
  os << "Bit-length of integers in public key (gamma): " << security.gamma << std::endl;
  os << "Bit-length of secret key (eta): " << security.eta << std::endl;
  os << "Bit-length of noise (rho): " << security.rho << std::endl;
  os << "Bit-length of secondary noise parameter (rho'): " << security.rho_ << std::endl;
  os << "Number of integers in public key (tau): " << security.tau << std::endl;
  os << "Bits of precision of indicator (kappa): " << security.kappa << std::endl;
  os << "Private key length (theta): " << security.theta << std::endl;
  os << "Public Key Indicator Vector Length (big-theta): " << security.big_theta << std::endl;

  return os;
}
