package ch.epfl.dedis.kyber.proof;

// Prover represents the prover role in an arbitrary Sigma-protocol.
// A prover is simply a higher-order function that takes a ProverContext,
// runs the protocol while making calls to the ProverContext methods as needed,
// and returns nil on success or an error once the protocol run concludes.
// The resulting proof is embodied in the interactions with the ProverContext,
// but HashProve() may be used to encode the proof into a non-interactive proof
// using a hash function via the Fiat-Shamir heuristic.
public interface Prover {
    public void prove(ProverContext ctx);
}
