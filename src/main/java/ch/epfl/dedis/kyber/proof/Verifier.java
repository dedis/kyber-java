package ch.epfl.dedis.kyber.proof;

// Verifier represents the verifier role in an arbitrary Sigma-protocol.
// A verifier is a higher-order function that takes a VerifierContext,
// runs the protocol while making calls to VerifierContext methods as needed,
// and returns nil on success or an error once the protocol run concludes.
public interface Verifier {
    public void verify(VerifierContext ctx);
}
