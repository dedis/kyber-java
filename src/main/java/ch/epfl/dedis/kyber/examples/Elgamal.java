package ch.epfl.dedis.kyber.examples;

import ch.epfl.dedis.kyber.EdPoint;
import ch.epfl.dedis.kyber.Group;
import ch.epfl.dedis.kyber.EdScalar;

import java.security.SecureRandom;

class CipherText {
    public EdPoint K, C;
    public byte[] remainder;

    public CipherText(EdPoint K, EdPoint C, byte[] remainder) {
        this.C = C;                     // message blinded with secret
        this.K = K;                     // ephemeral DH public key
        this.remainder = remainder;     // message left after embedding the maximum possible length in a edwards Point
    }
}

public class Elgamal {
    public static CipherText ElgamalEncrypt(Group group, EdPoint pubkey, byte[] message) {
        EdPoint M = group.Point();
        M.Embed(message, new SecureRandom());
        int max = M.EmbedLen();
        if (max > message.length) {
            max = message.length;
        }
        byte[] remainder = new byte[message.length - max];
        for (int i = 0; i < message.length - max; i++) {
            remainder[i] = message[i + max];
        }
        EdScalar k = group.Scalar();                                //private key
        k.Pick(new SecureRandom());
        EdPoint K = group.Point().Mul(k, null);                   //public key
        EdPoint S = group.Point().Mul(k, pubkey);                   //shared secret
        EdPoint C = group.Point().Add(S, M);                        //message added with the secret
        return new CipherText(K, C, remainder);
    }

    public static byte[] ElgamalDecrypt(Group group, EdScalar privkey, EdPoint K, EdPoint C) throws IllegalArgumentException {
        // ElGamal-decrypt the ciphertext (K,C) to reproduce the message.

        EdPoint S = group.Point().Mul(privkey, K);  // regenerate shared secret
        EdPoint M = group.Point().Sub(C, S);        // use to un-blind the message

        try {
            byte[] m = M.Data();                    // extract the embedded data
            return m;
        }
        catch (IllegalArgumentException E) {
            throw E;
        }
    }
}
