package ch.epfl.dedis.kyber.curve.ed25519;

import ch.epfl.dedis.kyber.Group;
import ch.epfl.dedis.kyber.Point;
import ch.epfl.dedis.kyber.Scalar;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;

public class curve implements Group {
    public String String(){
        return "Ed25519";
    }

    public int ScalarLen(){
        return 32;
    }

    public Scalar Scalar(){
        return new scalar();
    }

    public int PointLen(){
        return 32;
    }

    public Point Point(){
        return new point();
    }

    public Scalar NewKeyAndSeedWithInput(byte[] buffer) throws NoSuchAlgorithmException {
        MessageDigest dig = MessageDigest.getInstance("SHA-512");
        byte[] digest =  dig.digest(buffer);
        digest[0] &= 0xf8;
        digest[31] &= 0xf;

        Scalar secret = this.Scalar();
        byte[] data = new byte[32];
        for(int i = 0; i < 32; i++)
            data[i] = digest[i];
        secret.setBytes(data);
        return secret;
    }

    public Scalar NewKeyAndSeed(SecureRandom r) throws NoSuchAlgorithmException {
        byte[] buffer = new byte[32];
        r.nextBytes(buffer);
        return this.NewKeyAndSeedWithInput(buffer);
    }

    public Scalar NewKey(SecureRandom stream) throws NoSuchAlgorithmException {
        Scalar secret= this.NewKeyAndSeed(stream);
        return secret;
    }
}
