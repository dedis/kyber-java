package ch.epfl.dedis.kyber;

// An XOFFactory is an interface that can be mixed in to local suite definitions.
public interface XOFFactory {
    // XOF creates a new XOF, feeding seed to it via it's Write method. If seed
    // is nil or []byte{}, the XOF is left unseeded, it will produce a fixed, predictable
    // stream of bits (Caution: this behavior is useful for testing but fatal for
    // production use).
    public XOF XOF(byte[] seed);
}
