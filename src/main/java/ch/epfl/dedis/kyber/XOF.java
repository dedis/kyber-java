package ch.epfl.dedis.kyber;

// An XOF is an extendable output function, which is a cryptographic
// primitive that can take arbitrary input in the same way a hash
// function does, and then create a stream of output, up to a limit
// determined by the size of the internal state of the hash function
// the underlies the XOF.
//
// When XORKeyStream is called with zeros for the source, an XOF
// also acts as a PRNG. If it is seeded with an appropriate amount
// of keying material, it is a cryptographically secure source of random
// bits.
public interface XOF {
    // Reseed makes an XOF writeable again after it has been read from
    // by sampling a key from it's output and initializing a fresh XOF implementation
    // with that key.
    public void Reseed();

    // Clone returns a copy of the XOF in its current state.
    public XOF Clone();
}
