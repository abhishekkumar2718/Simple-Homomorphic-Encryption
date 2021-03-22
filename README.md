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

---

Questions:


- What is the goal of the paper?

> To implement fully homomorphic encryption on integers using simple operations
> like addition, multiplication.

- Why did you choose this paper?

> Homomorphic encryption as a topic is an interesting field with many
> applications like secure multi-party computations and machine learning
> without privacy concerns.

- What is a fully homomorphic encryption scheme?

> A scheme E (key gen, encrypt, decrypt, evaluate) is fully homomorphic
> if for any arbitarilty evaluation polynomial, evaluating ciphertexts
> and decrypting the result is equivalent to evaluating the
> corresponding plaintexts.

- How to build a fully homomorphic encryption scheme from a somewhat
  homomorphic encryption scheme?

> We can convert the decryption algorithm to a circuit and passing the
> circuit a noisy ciphertext and an encrypted version of the private
> key, we get a different ciphertext of the same plaintext but without
> noise.

- What is the underlying security problem?

> Our implementation depends on finding an approximate integer gcd that
> is, given a list of intgers that are near multiples of a hidden
> integer, output the hidden integer.
