package ch.epfl.dedis.kyber.curve.ed25519;

import ch.epfl.dedis.kyber.EdScalar;
import ch.epfl.dedis.kyber.Group;
import ch.epfl.dedis.kyber.EdPoint;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

/**
 * Curve represents the Ed25519 group.
 * There are no parameters and no initialization is required
 * because it supports only this one specific curve.
 */
public class Curve implements Group {

    // Return the name of the curve, "Ed25519".
    public String String() {
        return "Ed25519";
    }

    /**
     * ScalarLen returns 32, the size in bytes of an encoded Scalar
     * for the Ed25519 curve.
     */

    public int ScalarLen() {
        return 32;
    }

    /**
     * Scalar creates a new Scalar for the prime-order subgroup of the Ed25519 curve.
     * The scalars in this package implement kyber.Scalar's SetBytes
     * method, interpreting the bytes as a little-endian integer, in order to remain
     * compatible with other Ed25519 implementations, and with the standard implementation
     * of the EdDSA signature.
     */
    public EdScalar Scalar() {
        return new Scalar();
    }

    // PointLen returns 32, the size in bytes of an encoded Point on the Ed25519 curve.
    public int PointLen() {
        return 32;
    }

    // Point creates a new Point on the Ed25519 curve.
    public EdPoint Point() {
        return new Point();
    }

    /**
     * NewKeyAndSeedWithInput returns a formatted Ed25519 key (avoid subgroup attack by
     * requiring it to be a multiple of 8). It also returns the input and the digest used
     * to generate the key.
     */

    public EdScalar NewKeyAndSeedWithInput(byte[] buffer) throws NoSuchAlgorithmException {
        MessageDigest dig = MessageDigest.getInstance("SHA-512");
        byte[] digest = dig.digest(buffer);
        digest[0] &= 0xf8;
        digest[31] &= 0xf;

        /** In here the 31st byte has been done AND 16 just to bring the secret key chosen below the group order i.e. l
         * in which the highest priority byte is 16. Doing the normal procedure of unsetting the highest priority bit and
         * setting the highest priority bit leads to errors when the secret is passed to the filippo library which expects
         * all the scalars to be below l.
         */

        EdScalar secret = this.Scalar();
        byte[] data = new byte[32];
        System.arraycopy(digest, 0, data, 0, 32);
        secret.setBytes(data);
        return secret;
    }

    /**
     * NewKeyAndSeed returns a formatted Ed25519 key (avoid subgroup attack by requiring
     * it to be a multiple of 8). It also returns the seed and the input used to generate
     * the key.
     */
    public EdScalar NewKeyAndSeed(SecureRandom r) throws NoSuchAlgorithmException {
        byte[] buffer = new byte[32];
        r.nextBytes(buffer);
        return this.NewKeyAndSeedWithInput(buffer);
    }

    /**
     * NewKey returns a formatted Ed25519 key (avoiding subgroup attack by requiring
     * it to be a multiple of 8). NewKey implements the kyber/util/key.Generator interface.
     */
    public EdScalar NewKey(SecureRandom stream) throws NoSuchAlgorithmException {
        EdScalar secret = this.NewKeyAndSeed(stream);
        return secret;
    }
}
