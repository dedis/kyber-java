package ch.epfl.dedis.kyber;

import java.security.SecureRandom;

// Point represents an element of a public-key cryptographic Group.
// For example,
// this is a number modulo the prime P in a DSA-style Schnorr group,
// or an (x, y) point on an elliptic curve.
// A Point can contain a Diffie-Hellman public key, an ElGamal ciphertext, etc.
public interface EdPoint extends Marshaling {
    // Equality test for two Points derived from the same Group.
    public boolean Equal(EdPoint p);

    // Null sets the receiver to the neutral identity element.
    public EdPoint Null();

    // Base sets the receiver to this group's standard base point.
    public EdPoint Base();

    // Pick sets the receiver to a fresh random or pseudo-random Point.
    public EdPoint Pick(SecureRandom rand);

    // Set sets the receiver equal to another Point p.
    public EdPoint Set(EdPoint p);

    // Clone clones the underlying point.
    public EdPoint Clone() throws CloneNotSupportedException;

    // Maximum number of bytes that can be embedded in a single
    // group element via Pick().
    public int EmbedLen();

    // Embed encodes a limited amount of specified data in the
    // Point, using r as a source of cryptographically secure
    // random data.  Implementations only embed the first EmbedLen
    // bytes of the given data.
    public EdPoint Embed(byte[] data, SecureRandom rand) throws IllegalArgumentException;

    // Extract data embedded in a point chosen via Embed().
    // Returns an error if doesn't represent valid embedded data.
    public byte[] Data() throws IllegalArgumentException;

    // Add points so that their scalars add homomorphically.
    public EdPoint Add(EdPoint a, EdPoint b);

    // Subtract points so that their scalars subtract homomorphically.
    public EdPoint Sub(EdPoint a, EdPoint b);

    // Set to the negation of point a.
    public EdPoint Neg(EdPoint a);

    // Multiply point p by the scalar s.
    // If p == nil, multiply with the standard base point Base().
    public EdPoint Mul(EdScalar s, EdPoint p);
}
