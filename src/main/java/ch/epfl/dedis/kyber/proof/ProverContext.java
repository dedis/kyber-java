package ch.epfl.dedis.kyber.proof;

// ProverContext represents the kyber.environment
// required by the prover in a Sigma protocol.
//
// In a basic 3-step Sigma protocol such as a standard digital signature,
// the prover first calls Put() one or more times
// to send commitment information to the verifier,
// then calls PubRand() to obtain a public random challenge from the verifier,
// and finally makes further calls to Put() to respond to the challenge.
//
// The prover may also call PriRand() at any time
// to obtain any private randomness needed in the proof.
// The prover should obtain secret randomness only from this source,
// so that the prover may be run deterministically if desired.
//
// More sophisticated Sigma protocols requiring more than 3 steps,
// such as the Neff shuffle, may also use this interface;
// in this case the prover simply calls PubRand() multiple times.
//
public interface ProverContext {
    public void Put(Object message);        // Send message to verifier

    public void PubRand(Object... message); // Get public randomness

    public void PriRand(Object... message); // Get private randomness
}
