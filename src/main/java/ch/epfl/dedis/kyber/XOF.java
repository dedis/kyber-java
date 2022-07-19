package ch.epfl.dedis.kyber;

public interface XOF {
    public void Reseed();
    public XOF Clone();
}
