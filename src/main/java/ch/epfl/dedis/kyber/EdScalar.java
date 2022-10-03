package ch.epfl.dedis.kyber;

import java.security.SecureRandom;

// Scalar represents a scalar value by which
// a Point (group element) may be encrypted to produce another Point.
// This is an exponent in DSA-style groups,
// in which security is based on the Discrete Logarithm assumption,
// and a scalar multiplier in elliptic curve groups.
public interface EdScalar extends Marshaling {
    // Equality test for two Scalars derived from the same Group.
    public boolean Equal(EdScalar s);

    // Set sets the receiver equal to another Scalar a.
    public EdScalar Set(EdScalar s);

    // Clone creates a new Scalar with the same value.
    public EdScalar Clone() throws CloneNotSupportedException;

    // SetInt64 sets the receiver to a small integer value.
    public EdScalar SetInt64(long v);

    // Set to the additive identity (0).
    public EdScalar Zero();

    // Set to the modular sum of scalars a and b.
    public EdScalar Add(EdScalar a, EdScalar b);

    // Set to the modular difference a - b.
    public EdScalar Sub(EdScalar a, EdScalar b);

    // Set to the modular negation of scalar a.
    public EdScalar Neg(EdScalar a);

    // Set to the multiplicative identity (1).
    public EdScalar One();

    // Set to the modular product of scalars a and b.
    public EdScalar Mul(EdScalar a, EdScalar b);

    // Set to the modular division of scalar a by scalar b.
    public EdScalar Div(EdScalar a, EdScalar b);

    // Set to the modular inverse of scalar a.
    public EdScalar Inv(EdScalar a);

    // Set to a fresh random or pseudo-random scalar.
    public EdScalar Pick(SecureRandom rand);

    // SetBytes sets the scalar from a byte-slice,
    // reducing if necessary to the appropriate modulus.
    // The endianess of the byte-slice is determined by the
    // implementation.
    public EdScalar setBytes(byte[] bytes);
}
