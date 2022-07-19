package ch.epfl.dedis.kyber.examples;

import ch.epfl.dedis.kyber.Group;
import ch.epfl.dedis.kyber.Point;
import ch.epfl.dedis.kyber.Scalar;
import ch.epfl.dedis.kyber.Suite;
import ch.epfl.dedis.kyber.curve.ed25519.SuiteEd25519;
import javafx.util.Pair;

import java.security.SecureRandom;

class cipherText
{
    public Point K, C;
    public byte[] remainder;
    public cipherText(Point K, Point C, byte[] remainder){
        this.C = C;
        this.K = K;
        this.remainder = remainder;
    }
}

public class Elgamal {
    public static cipherText ElgamalEncrypt(Group group, Point pubkey, byte[] message) {
        Point M = group.Point();
        M.Embed(message, new SecureRandom());
        int max = M.EmbedLen();
        if(max > message.length)
            max = message.length;
        byte[] remainder = new byte[message.length - max];
        for(int i = 0; i < message.length - max; i++){
            remainder[i] = message[i + max];
        }
        Scalar k = group.Scalar();                              //private key
        k.Pick(new SecureRandom());
        Point K = group.Point().Mul(k, null);                //public key
        Point S = group.Point().Mul(k, pubkey);                 //shared secret
        Point C = group.Point().Add(S, M);                                             //message added with the secret
        return new cipherText(K,C,remainder);
    }

    public static Pair<byte[], Exception> ElgamalDecrypt(Group group, Scalar privkey, Point K, Point C) {
        Point S = group.Point().Mul(privkey, K);
        Point M = group.Point().Sub(C, S);
        Pair<byte[], Exception> m = M.Data();
        return m;
    }
}
