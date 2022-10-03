package ch.epfl.dedis.kyber;

import cafe.cryptography.curve25519.InvalidEncodingException;
import java.io.*;

/*
Marshaling is a basic interface representing fixed-length (or known-length)
cryptographic objects or structures having a built-in binary encoding.
Implementors must ensure that calls to these methods do not modify
the underlying object so that other users of the object can access
it concurrently.
*/
public interface Marshaling {
    // Marshal the state of the current object into a byte array
    public byte[] MarshalBinary() throws IllegalArgumentException;

    // Create a new object with state as described by the given byte array
    public void UnmarshalBinary(byte[] data) throws InvalidEncodingException, IllegalArgumentException;

    // String returns the human readable string representation of the object.
    public String String();

    // Encoded length of this object in bytes.
    public int MarshalSize();

    // Encode the contents of this object and write it to an io.Writer.
    public int MarshalTo(ObjectOutputStream w) throws IllegalArgumentException, IOException;

    // Decode the content of this object by reading from an io.Reader.
    // If r is an XOF, it uses r to pick a valid object pseudo-randomly,
    // which may entail reading more than Len bytes due to retries.
    public int UnmarshalFrom(ObjectInputStream r) throws InvalidEncodingException, IllegalArgumentException, IOException;
}
