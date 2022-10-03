package ch.epfl.dedis.kyber.curve.ed25519;

import ch.epfl.dedis.kyber.Suite;
import ch.epfl.dedis.kyber.XOF;
import ch.epfl.dedis.kyber.utils.key.Generator;
import ch.epfl.dedis.kyber.xof.Blake2xb;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

// SuiteEd25519 implements some basic functionalities such as Group, HashFactory,
// and XOFFactory.
public class SuiteEd25519 extends Curve implements Suite, Generator {
    SecureRandom r;

    public SuiteEd25519() {
        r = null;
    }


    public SuiteEd25519(SecureRandom r) {
        this.r = r;
    }

    //NewBlakeSHA256Ed25519 returns a cipher suite based on
    // Blake2xb XOF, SHA-256, and the Ed25519 curve.
    // It produces cryptographically random numbers via package crypto/rand.
    public static SuiteEd25519 NewSHA256Ed25519() {
        return new SuiteEd25519();
    }

    // NewBlakeSHA256Ed25519WithRand returns a cipher suite based on
    // Blake2xb XOF, SHA-256, and the Ed25519 curve.
    // It produces cryptographically random numbers via the provided SecureRandom instance r.
    public static SuiteEd25519 NewSHA256Ed25519WithRand(SecureRandom r) {
        return new SuiteEd25519(r);
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

    @Override
    public XOF XOF(byte[] seed) {
        return new Blake2xb(seed);
    }
}
