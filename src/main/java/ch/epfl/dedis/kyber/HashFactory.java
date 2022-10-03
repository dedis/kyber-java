package ch.epfl.dedis.kyber;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public interface HashFactory {
    // Provides an instance of java MessageDigest based upon the hashing algorithm used by the curve
    public MessageDigest Hash() throws NoSuchAlgorithmException;
}
