package ch.epfl.dedis.kyber.curve.ed25519;

import ch.epfl.dedis.kyber.EdScalar;
import ch.epfl.dedis.kyber.Suite;
import ch.epfl.dedis.kyber.utils.key.Pair;
import org.testng.annotations.Test;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class CurveTest {

    public static Suite tsuite = SuiteEd25519.NewSHA256Ed25519();

    @Test
    public void KeyGenerationTests() {
        Pair p1 = Pair.NewKeyPair(tsuite);
        Pair p2 = Pair.NewKeyPair(tsuite);
        assert (!p1.Private.Equal(p2.Private));
    }

    @Test
    public void SameKeyGenerationTests() throws NoSuchAlgorithmException {
        byte[] seed = new byte[]{10};
        SecureRandom sr1 = SecureRandom.getInstance("SHA1PRNG");
        sr1.setSeed(seed);
        SecureRandom sr2 = SecureRandom.getInstance("SHA1PRNG");
        sr2.setSeed(seed);
        Pair p1 = Pair.NewKeyPair(new SuiteEd25519(sr1));
        Pair p2 = Pair.NewKeyPair(new SuiteEd25519(sr2));
        assert (p1.Private.Equal(p2.Private));
    }

    @Test
    public void NewKey() throws NoSuchAlgorithmException {
        SecureRandom sr = tsuite.RandomStream();
        Curve cr = new Curve();
        for (int i = 0; i < 1000000; i++) {
            EdScalar s = cr.NewKey(sr);
            try {
                byte[] bytes = s.MarshalBinary();
                assert ((bytes[0] & 7) == 0);
            }
            catch (Exception E) {
                System.err.println(E);
                assert (false);          // intentionally failing the assertion to indicate that an error has occurred
            }
        }
    }
}
