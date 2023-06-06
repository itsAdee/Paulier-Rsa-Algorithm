import java.math.BigInteger;
import java.util.HashMap;
import java.util.Random;

// Bidder class
class Bidder {
    // attributes
    String name;
    int bid;

    // constructor
    public Bidder(String name, int bid) {
        this.name = name;
        this.bid = bid;
    }

    // methods
    // encryptBid method is used to encrypt the bid of the bidder using the public
    // key of the auctioneer
    public byte[] encryptBid(BigInteger[] publickey) {
        BigInteger e = publickey[0];
        BigInteger N = publickey[1];
        BigInteger bid = new BigInteger(Integer.toString(this.bid));
        BigInteger encryptedBid = bid.modPow(e, N);
        // return the encrypted bid
        return encryptedBid.toByteArray();
    }

}

// Account class
class Auctioneer {
    // attributes
    // rsa_algo is an object of the RSA class which is used to generate the public
    // key as well as the private key
    // encryptedBids is a HashMap which stores the encrypted bid of the bidders
    RSA rsa_algo;
    HashMap<String, byte[]> encryptedBids;

    // constructor
    public Auctioneer() {
        rsa_algo = new RSA();
        encryptedBids = new HashMap<String, byte[]>();
    }

    // methods
    // AnnounceWinner method is used to decrypt the encrypted bid of the bidders and
    // announce the winner
    public String[] AnnounceWinner() {
        // maxBid is used to store the maximum bid
        int maxBid = 0;
        // winner is used to store the name of the winner
        String winner = "";
        // iterate over the encryptedBids HashMap and decrypt the encrypted bid of the
        // bidders
        for (String bidderName : encryptedBids.keySet()) {
            byte[] encryptedBid = encryptedBids.get(bidderName);
            // convert the encrypted bid to BigInteger
            BigInteger bid = new BigInteger(encryptedBid);
            // decrypt the encrypted bid of the bidder
            BigInteger decryptedBid = bid.modPow(rsa_algo.d, rsa_algo.N);
            // check if the decrypted bid is greater than the maxBid
            if (decryptedBid.intValue() > maxBid) {
                maxBid = decryptedBid.intValue();
                winner = bidderName;
            }
        }
        String[] result = { winner, Integer.toString(maxBid) };
        return result;
    }

}

class FairBiddingProtocol {
    public static void main(String[] args) {
        System.out.println("---Forum---\n");
        Auctioneer auctioneer = new Auctioneer();
        BigInteger[] AuctionPublicKey = auctioneer.rsa_algo.getPublicKey();
        System.out.println("Auctioneer's Public Key: (" + AuctionPublicKey[0] + ",\n" + AuctionPublicKey[1] + ")\n");

        System.out.println("---Bidding Started---\n");
        Bidder bidder1 = new Bidder("Bidder1", 100);
        Bidder bidder2 = new Bidder("Bidder2", 800000);
        Bidder bidder3 = new Bidder("Bidder3", 300);

        byte[] encryptedBid1 = bidder1.encryptBid(AuctionPublicKey);
        byte[] encryptedBid2 = bidder2.encryptBid(AuctionPublicKey);
        byte[] encryptedBid3 = bidder3.encryptBid(AuctionPublicKey);

        auctioneer.encryptedBids.put(bidder1.name, encryptedBid1);
        auctioneer.encryptedBids.put(bidder2.name, encryptedBid2);
        auctioneer.encryptedBids.put(bidder3.name, encryptedBid3);
        System.out.println("---Bidding Ended---\n");

        System.out.println("---Compiling Results---\n");
        String[] winner = auctioneer.AnnounceWinner();
        System.out.println("Winner: " + winner[0] + " Bid Amount: " + winner[1]);
    }

}

// RSA cryptosystem
class RSA {
    // attributes
    public BigInteger p;
    public BigInteger q;
    public BigInteger N;
    public BigInteger phi;
    public BigInteger e;
    public BigInteger d;
    public int bitlength = 1024;

    // constructor
    public RSA() {
        // generating random prime numbers
        Random r = new Random();
        p = BigInteger.probablePrime(bitlength, r);
        // check if the generated prime number is prime or not
        while (true) {
            if (isPrime(p)) {
                break;
            } else {
                p = BigInteger.probablePrime(bitlength, r);
            }
        }
        // generating second random prime number
        q = BigInteger.probablePrime(bitlength, r);
        // check if the generated prime number is prime or not
        while (true) {
            if (isPrime(q)) {
                break;
            } else {
                q = BigInteger.probablePrime(bitlength, r);
            }
        }
        // multiply the two prime numbers to get the value of N
        N = p.multiply(q);
        // calculate the value of phi
        phi = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));
        // generate the value of e
        e = BigInteger.probablePrime(bitlength / 2, r);
        // check if the generated value of e is co-prime with phi
        while (true) {
            if (Gcd(e, phi)) {
                break;
            } else {
                e = e.add(BigInteger.ONE);
            }
        }
        // calculate the value of d
        d = e.modInverse(phi);

    }

    // methods
    // Gcd method is used to check if the value of e is co-prime with phi
    public boolean Gcd(BigInteger e, BigInteger phi) {
        if (e.gcd(phi).equals(BigInteger.ONE)) {
            return true;
        } else {
            return false;
        }
    }

    // isPrime method is used to check if the generated prime number is prime or not
    public boolean isPrime(BigInteger n) {
        if (n.isProbablePrime(1)) {
            return true;
        } else {
            return false;
        }
    }

    // encrypt method is used to encrypt the message using the public key
    public byte[] encrypt(byte[] message) {
        return (new BigInteger(message)).modPow(e, N).toByteArray();
    }

    // decrypt method is used to decrypt the message using the private key
    public byte[] decrypt(byte[] message) {
        return (new BigInteger(message)).modPow(d, N).toByteArray();
    }

    // getPublicKey method is used to return the public key of the auctioneer
    public BigInteger[] getPublicKey() {
        BigInteger[] publickey = new BigInteger[2];
        publickey[0] = e;
        publickey[1] = N;
        return publickey;
    }

    public BigInteger getN() {
        return N;
    }
}