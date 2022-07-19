package ch.epfl.dedis.kyber.curve.ed25519;

import ch.epfl.dedis.kyber.Point;
import ch.epfl.dedis.kyber.Scalar;
import ch.epfl.dedis.kyber.Suite;
import ch.epfl.dedis.kyber.XOF;
import ch.epfl.dedis.kyber.utils.key.Generator;
import ch.epfl.dedis.kyber.xof.blake2xb;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class SuiteEd25519 extends curve implements Suite, Generator {
    SecureRandom r;

    public SuiteEd25519() {
        r = null;
    }

    public SuiteEd25519(SecureRandom r){
        this.r = r;
    }

    public MessageDigest Hash() throws NoSuchAlgorithmException {
        return MessageDigest.getInstance("SHA-256");
    }

    public SecureRandom RandomStream() {
        if (this.r != null) {
            return this.r;
        }
        return new SecureRandom();
    }


    public static SuiteEd25519 NewSHA256Ed25519() {
        return new SuiteEd25519();
    }

    public static SuiteEd25519 NewSHA256Ed25519WithRand(SecureRandom r) {
        return new SuiteEd25519(r);
    }

    @Override
    public XOF XOF(byte[] seed) {
        return  new blake2xb(seed);
    }
}
