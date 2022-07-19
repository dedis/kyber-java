package ch.epfl.dedis.kyber.curve.ed25519;

import ch.epfl.dedis.kyber.Scalar;
import ch.epfl.dedis.kyber.Suite;
import ch.epfl.dedis.kyber.utils.key.pair;
import javafx.util.Pair;
import org.junit.Test;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class CurveTest {

    public static Suite tsuite = SuiteEd25519.NewSHA256Ed25519();

    @Test
    public void KeyGenerationTests() {
        pair p1 = pair.NewKeyPair(tsuite);
        pair p2 = pair.NewKeyPair(tsuite);
        assert(!p1.Private.Equal(p2.Private));
    }

    @Test
    public void SameKeyGenerationTests() throws NoSuchAlgorithmException {
        byte[] seed = new byte[]{10};
        SecureRandom sr1 = SecureRandom.getInstance("SHA1PRNG");
        sr1.setSeed(seed);
        SecureRandom sr2 = SecureRandom.getInstance("SHA1PRNG");
        sr2.setSeed(seed);
        pair p1 = pair.NewKeyPair(new SuiteEd25519(sr1));
        pair p2 = pair.NewKeyPair(new SuiteEd25519(sr2));
        assert(p1.Private.Equal(p2.Private));
    }

    @Test
    public void NewKey() throws NoSuchAlgorithmException {
        SecureRandom sr = tsuite.RandomStream();
        curve cr = new curve();
        for (int i = 0; i < 1000000; i++) {
            Scalar s = cr.NewKey(sr);
            Pair<byte[], Exception> p = s.MarshalBinary();
            byte[] bytes = p.getKey();
            assert((bytes[0] & 7) == 0);
        }
    }
}
