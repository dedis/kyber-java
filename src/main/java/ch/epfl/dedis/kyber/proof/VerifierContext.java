package ch.epfl.dedis.kyber.proof;

public interface VerifierContext {
    public Exception Get(Object message);
    public Exception PubRand(Object... message);
}
