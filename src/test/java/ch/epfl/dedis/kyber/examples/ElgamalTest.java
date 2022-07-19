package ch.epfl.dedis.kyber.examples;

import ch.epfl.dedis.kyber.Point;
import ch.epfl.dedis.kyber.Scalar;
import ch.epfl.dedis.kyber.Suite;
import ch.epfl.dedis.kyber.curve.ed25519.SuiteEd25519;
import javafx.util.Pair;
import org.junit.Test;

import java.security.SecureRandom;
import java.util.Arrays;

public class ElgamalTest {

    @Test
    public void exampleElgamal() {
        Suite suite = SuiteEd25519.NewSHA256Ed25519();
        Scalar priv = suite.Scalar();
        priv.Pick(new SecureRandom());
        Point pub = suite.Point();
        pub.Mul(priv, null);
        byte[] m = ("The quick brown fox").getBytes();
        cipherText ct = Elgamal.ElgamalEncrypt(suite, pub, m);
        Pair<byte[], Exception> ret = Elgamal.ElgamalDecrypt(suite, priv, ct.K, ct.C);
        assert(ret.getValue() == null);
        byte[] decrypted_m = ret.getKey();
        assert(Arrays.equals(m, decrypted_m));
    }
}
