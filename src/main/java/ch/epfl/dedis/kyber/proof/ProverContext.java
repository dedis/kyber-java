package ch.epfl.dedis.kyber.proof;

public interface ProverContext {
    public Exception Put(Object message);
    public Exception PubRand(Object... message);
    public Exception PriRand(Object... message);
}
