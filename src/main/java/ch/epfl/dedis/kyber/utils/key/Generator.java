package ch.epfl.dedis.kyber.utils.key;

import ch.epfl.dedis.kyber.Scalar;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public interface Generator {
    public Scalar NewKey(SecureRandom r) throws NoSuchAlgorithmException;
}
