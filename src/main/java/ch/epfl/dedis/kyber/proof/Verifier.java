package ch.epfl.dedis.kyber.proof;

public interface Verifier {
    public Exception verify(VerifierContext ctx);
}
