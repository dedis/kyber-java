package ch.epfl.dedis.kyber.examples;

import ch.epfl.dedis.kyber.EdPoint;
import ch.epfl.dedis.kyber.EdScalar;
import ch.epfl.dedis.kyber.Suite;
import ch.epfl.dedis.kyber.curve.ed25519.SuiteEd25519;
import org.junit.Test;

import java.security.SecureRandom;
import java.util.Arrays;

public class ElgamalTest {

    @Test
    public void exampleElgamal() {
        Suite suite = SuiteEd25519.NewSHA256Ed25519();
        EdScalar priv = suite.Scalar();
        priv.Pick(new SecureRandom());
        EdPoint pub = suite.Point();
        pub.Mul(priv, null);
        byte[] m = ("The quick brown fox").getBytes();
        CipherText ct = Elgamal.ElgamalEncrypt(suite, pub, m);
        try {
            byte[] decrypted_m = Elgamal.ElgamalDecrypt(suite, priv, ct.K, ct.C);
            assert (Arrays.equals(m, decrypted_m));
        }
        catch (IllegalArgumentException E) {
            System.out.println(E);
            assert (false);
        }
    }
}
