package ch.epfl.dedis.kyber.utils.key;

import ch.epfl.dedis.kyber.Point;
import ch.epfl.dedis.kyber.Scalar;
import ch.epfl.dedis.kyber.Suite;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class pair {
    public Point Public;
    public Scalar Private;

    public static pair NewKeyPair(Suite suite) {
        pair kp = new pair();
        try{ kp.Gen(suite); }
        catch (Exception E) { return null; }
        return kp;
    }

    public void Gen(Suite suite) throws NoSuchAlgorithmException {
        SecureRandom r = suite.RandomStream();
        Generator gen = (Generator) suite;
        this.Private = gen.NewKey(r);
        this.Public = suite.Point().Mul(this.Private, null);
    }
}
