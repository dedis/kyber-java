package ch.epfl.dedis.kyber;

// Group interface represents a mathematical group
// usable for Diffie-Hellman key exchange, ElGamal encryption,
// and the related body of public-key cryptographic algorithms
// and zero-knowledge proof methods.
// The Group interface is designed in particular to be a generic front-end
// to both traditional DSA-style modular arithmetic groups
// and ECDSA-style elliptic curves:
// the caller of this interface's methods
// need not know or care which specific mathematical construction
// underlies the interface.
//
// The Group interface is essentially just a "constructor" interface
// enabling the caller to generate the two particular types of objects
// relevant to DSA-style public-key cryptography;
// we call these objects Points and Scalars.
// The caller must explicitly initialize or set a new Point or Scalar object
// to some value before using it as an input to some other operation
// involving Point and/or Scalar objects.
//
// It is expected that any implementation of this interface
// should satisfy suitable hardness assumptions for the applicable group:
// e.g., that it is cryptographically hard for an adversary to
// take an encrypted Point and the known generator it was based on,
// and derive the Scalar with which the Point was encrypted.
// Any implementation is also expected to satisfy
// the standard homomorphism properties that Diffie-Hellman
// and the associated body of public-key cryptography are based on.
public interface Group {
    public String String();

    // Max length of scalars in bytes
    public int ScalarLen();

    // Create new scalar
    public EdScalar Scalar();

    // Max length of point in bytes
    public int PointLen();

    // Create new point
    public EdPoint Point();
}
