package ch.epfl.dedis.kyber.proof;

import ch.epfl.dedis.kyber.*;

import java.util.Map;

/*
A Predicate is a composable logic expression in a knowledge proof system,
representing a "knowledge specification set" in Camenisch/Stadler terminology.
Atomic predicates in this system are statements of the form P=x1*B1+...+xn+Bn,
indicating the prover knows secrets x1,...,xn that make the statement true,
where P and B1,...,Bn are public points known to the verifier.
These atomic Rep (representation) predicates may be combined
with logical And and Or combinators to form composite statements.
Predicate objects, once created, are immutable and safe to share
or reuse for any number of proofs and verifications.
After constructing a Predicate using the Rep, And, and Or functions below,
the caller invokes Prover() to create a Sigma-protocol prover.
Prover() requires maps defining the values of both the Scalar variables
and the public Point variables that the Predicate refers to.
If the statement contains logical Or operators, the caller must also pass
a map containing branch choices for each Or predicate
in the "proof-obligated path" down through the Or predicates.
See the examples provded for the Or function for more details.
Similarly, the caller may invoke Verifier() to create
a Sigma-protocol verifier for the predicate.
The caller must pass a map defining the values
of the public Point variables that the proof refers to.
The verifier need not be provided any secrets or branch choices, of course.
(If the verifier needed those then they wouldn't be secret, would they?)
Currently we require that all Or operators be above all And operators
in the expression - i.e., Or-of-And combinations are allowed,
but no And-of-Or predicates.
We could rewrite expressions into this form as Camenisch/Stadler suggest,
but that could run a risk of unexpected exponential blowup in the worst case.
We could avoid this risk by not rewriting the expression tree,
but instead generating Pedersen commits for variables that need to "cross"
from one OR-domain to another non-mutually-exclusive one.
For now we simply require expressions to be in the appropriate form.
*/
public interface Predicate {

    // Create a Prover proving the statement this Predicate represents.
    public Prover Prover(Suite suite, Map<String, EdScalar> secrets,
                         Map<String, EdPoint> points, Map<Predicate, Integer> choice);

    // Create a Verifier for the statement this Predicate represents.
    public Verifier Verifier(Suite suite, Map<String, EdPoint> points);

    // Produce a human-readable string representation of the predicate.
    public String String();

    // precedence-sensitive helper stringifier.
    public String precString(int prec);

    // prover/verifier: enumerate the variables named in a predicate
    public void enumVars(Proof prf);

    // prover: recursively produce all commitments
    public void commit(Proof prf, EdScalar w, EdScalar[] v) throws IllegalArgumentException;

    // prover: given challenge, recursively produce all responses
    public void respond(Proof prf, EdScalar c, EdScalar[] r);

    // verifier: get all the commitments required in this predicate,
    // and fill the r slice with empty secrets for responses needed.
    public void getCommits(Proof prf, EdScalar[] r);

    // verifier: check all commitments against challenges and responses
    public void verify(Proof prf, EdScalar c, EdScalar[] r) throws IllegalArgumentException;
}
