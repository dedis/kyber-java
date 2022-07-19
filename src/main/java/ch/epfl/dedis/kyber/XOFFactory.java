package ch.epfl.dedis.kyber;

public interface XOFFactory {
    public XOF XOF(byte[] seed);
}
