package ch.epfl.dedis.kyber;

import javafx.util.Pair;
import java.security.SecureRandom;

public interface Point extends Marshaling {
    public boolean Equal(Point p);
    public Point Null();
    public Point Base();
    public Point Pick(SecureRandom rand);
    public Point Set(Point p);
    public Point Clone() throws CloneNotSupportedException;
    public int EmbedLen();
    public Point Embed(byte[] data, SecureRandom rand);
    public Pair<byte[], Exception> Data();
    public Point Add(Point a, Point b);
    public Point Sub(Point a, Point b);
    public Point Neg(Point a);
    public Point Mul(Scalar s, Point p);
}
