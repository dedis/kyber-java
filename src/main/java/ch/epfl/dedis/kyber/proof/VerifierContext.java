package ch.epfl.dedis.kyber.proof;

// VerifierContext represents the kyber.environment
// required by the verifier in a Sigma protocol.
//
// The verifier calls Get() to obtain the prover's message data,
// interspersed with calls to PubRand() to obtain challenge data.
// Note that the challenge itself comes from the VerifierContext,
// not from the verifier itself as in the traditional Sigma-protocol model.
// By separating challenge production from proof verification logic,
// we obtain the flexibility to use a single Verifier function
// in both non-interactive proofs (e.g., via HashProve)
// and in interactive proofs (e.g., via DeniableProver).
public interface VerifierContext {
    public void Get(Object message);        // Receive message from prover
    public void PubRand(Object... message); // Get public randomness
}
