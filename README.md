# Fully Homomorphic Encryption over the Integers

## Abstract

We construct a simple fully homomorphic encryption scheme, using only
elementary modular arithematic. We use Gentry's technique to construct
a fully homomorphic scheme from a "bootstrappable" somewhat scheme.
However, instead of using ideal lattices over a polynomial ring, our
bootstrappable encryption scheme merely uses addition and multiplication
over the intgeres. The main appeal of our scheme is the conceptual simplicity.

We reduce the security of our scheme to finding an approximate integer gcd i.e.,
given a list of integers that are near multiples of a hidden integer, output the
hidden integer.

## Use

- Install CryptoPP, GNU Multiple Precision Arithematic Library and GNU make.

- Build the executable using `make`.

- Run the executable using `./fully_homomorphic <number of candidates>`

## Submitted by

- Abhishek Kumar (181CO201)
- Keerti Chaudhary (181CO226)
- Yerramaddu Jahnavi (181CO260)
