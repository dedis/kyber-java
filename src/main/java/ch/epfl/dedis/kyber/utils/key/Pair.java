package ch.epfl.dedis.kyber.utils.key;

import ch.epfl.dedis.kyber.EdPoint;
import ch.epfl.dedis.kyber.EdScalar;
import ch.epfl.dedis.kyber.Suite;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class Pair {
    public EdPoint Public;
    public EdScalar Private;

    public static Pair NewKeyPair(Suite suite) {
        Pair kp = new Pair();
        try {
            kp.Gen(suite);
        }
        catch (Exception E) {
            return null;
        }
        return kp;
    }

    public void Gen(Suite suite) throws NoSuchAlgorithmException {
        SecureRandom r = suite.RandomStream();
        Generator gen = (Generator) suite;
        this.Private = gen.NewKey(r);
        this.Public = suite.Point().Mul(this.Private, null);
    }
}
