package ch.epfl.dedis.kyber.proof;

public interface Prover {
    public Exception prove(ProverContext ctx);
}
