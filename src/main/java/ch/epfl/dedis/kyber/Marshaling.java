package ch.epfl.dedis.kyber;

import javafx.util.Pair;

import java.io.*;
import java.nio.Buffer;

public interface Marshaling {
    public Pair<byte[], Exception> MarshalBinary();
    public Exception UnmarshalBinary(byte[] data);
    public String String();
    public int MarshalSize();
    public Pair<Integer, Exception> MarshalTo(ObjectOutputStream w);
    public Pair<Integer, Exception> UnmarshalFrom(ObjectInputStream r);
}
