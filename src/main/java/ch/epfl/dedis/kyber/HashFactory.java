package ch.epfl.dedis.kyber;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public interface HashFactory{
    public MessageDigest Hash() throws NoSuchAlgorithmException;
}
