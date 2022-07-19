package ch.epfl.dedis.kyber.proof;

import ch.epfl.dedis.kyber.*;

import java.util.Map;

public interface Predicate {

    // Create a Prover proving the statement this Predicate represents.
    public Prover Prover(Suite suite, Map<String, Scalar> secrets,
                       Map<String, Point> points, Map<Predicate, Integer> choice);

    // Create a Verifier for the statement this Predicate represents.
    public Verifier Verifier(Suite suite, Map<String, Point> points);

    // Produce a human-readable string representation of the predicate.
    public String String();

    // precedence-sensitive helper stringifier.
    public String precString(int prec);

    // prover/verifier: enumerate the variables named in a predicate
    public void enumVars(proof prf);

    // prover: recursively produce all commitments
    public Exception commit(proof prf, Scalar w, Scalar[] v);

    // prover: given challenge, recursively produce all responses
    public Exception respond(proof prf, Scalar c, Scalar[] r);

    // verifier: get all the commitments required in this predicate,
    // and fill the r slice with empty secrets for responses needed.
    public Exception getCommits(proof prf, Scalar[] r);

    // verifier: check all commitments against challenges and responses
    public Exception verify(proof prf, Scalar c, Scalar[] r);
}
