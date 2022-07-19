package ch.epfl.dedis.kyber;

import java.nio.Buffer;
import java.security.SecureRandom;
import java.util.Random;

public interface Scalar extends Marshaling{
    public boolean Equal(Scalar s);
    public Scalar Set(Scalar s);
    public Scalar Clone() throws CloneNotSupportedException;
    public Scalar SetInt64(long v);
    public Scalar Zero();
    public Scalar Add(Scalar a, Scalar b);
    public Scalar Sub(Scalar a, Scalar b);
    public Scalar Neg(Scalar a);
    public Scalar One();
    public Scalar Mul(Scalar a, Scalar b);
    public Scalar Div(Scalar a, Scalar b);
    public Scalar Inv(Scalar a);
    public Scalar Pick(SecureRandom rand);
    public Scalar setBytes(byte[] bytes);
}
