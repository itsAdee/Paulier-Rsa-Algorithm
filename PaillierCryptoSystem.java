import java.math.*;
import java.util.*;

public class PaillierCryptoSystem {
    /* Public Key: (n, nsquare) Private Key: (lambda, g) */

    /*
     * p and q are two large primes. lambda = lcm(p-1, q-1) = (p-1)*(q-1)/gcd(p-1,
     * q-1).
     */
    private BigInteger p, q, lambda;

    /* n = p*q, where p and q are two large primes. */
    public BigInteger n;

    /* nsquare = n*n */
    public BigInteger nsquare;

    /* a random integer in Z*_{n^2} where gcd (L(g^lambda mod n^2), n) = 1. */
    private BigInteger g;

    /* number of bits of modulus */
    private int bitLength;

    /*
     * bitLengthVal: number of bits of modulus
     * certainty: The probability that the new BigInteger represents a
     * prime number will exceed (1 - 2^(-certainty)). The
     * execution time of this constructor is proportional to the
     * value of this parameter.
     */
    public PaillierCryptoSystem(int bitLengthVal, int certainty) {
        KeyGeneration(bitLengthVal, certainty);
    }

    public PaillierCryptoSystem() {
        KeyGeneration(512, 64);
    }

    public void KeyGeneration(int bitLengthVal, int certainty) {
        bitLength = bitLengthVal;
        /*
         * Constructs two randomly generated positive BigIntegers that are probably
         * prime, with the specified bitLength and certainty.
         */
        p = new BigInteger(bitLength / 2, certainty, new Random());
        q = new BigInteger(bitLength / 2, certainty, new Random());

        n = p.multiply(q);
        nsquare = n.multiply(n);

        g = new BigInteger("2");
        lambda = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE)).divide(
                p.subtract(BigInteger.ONE).gcd(q.subtract(BigInteger.ONE)));
    }

    /*
     * Encrypts plaintext m. ciphertext c = g^m * r^n mod n^2. This function
     * automatically generates random input r (to help with encryption).
     */
    public BigInteger Encryption(BigInteger m) {
        BigInteger r = new BigInteger(bitLength, new Random());
        return g.modPow(m, nsquare).multiply(r.modPow(n, nsquare)).mod(nsquare);
    }

    /*
     * Decrypts ciphertext c. plaintext m = L(c^lambda mod n^2) * u mod n,
     * where u = (L(g^lambda mod n^2))^(-1) mod n.
     */
    private BigInteger Decryption(BigInteger c) {
        BigInteger u = g.modPow(lambda, nsquare).subtract(BigInteger.ONE).divide(n).modInverse(n);
        return c.modPow(lambda, nsquare).subtract(BigInteger.ONE).divide(n).multiply(u).mod(n);
    }

    /* Calculates the homomorphic sum of multiple ciphertexts. */
    public BigInteger DecryptSum(BigInteger... encryptedSalaries) {
        if (encryptedSalaries.length <= 1) {
            throw new IllegalArgumentException("Need at least two encrypted salaries to calculate sum.");
        }
        BigInteger product_esalaries = new BigInteger("1");
        for (BigInteger encryptedSalary : encryptedSalaries) {
            product_esalaries = product_esalaries.multiply(encryptedSalary);
        }
        product_esalaries = product_esalaries.mod(nsquare);
        return Decryption(product_esalaries);
    }
}