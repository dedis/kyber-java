package ch.epfl.dedis.kyber.utils.key;

import ch.epfl.dedis.kyber.EdScalar;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public interface Generator {
    public EdScalar NewKey(SecureRandom r) throws NoSuchAlgorithmException;
}
