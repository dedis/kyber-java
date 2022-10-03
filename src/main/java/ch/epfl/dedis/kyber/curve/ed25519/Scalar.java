package ch.epfl.dedis.kyber.curve.ed25519;

import ch.epfl.dedis.kyber.EdScalar;
import com.google.common.io.CountingOutputStream;
import com.google.common.primitives.Longs;
import org.apache.commons.lang3.ArrayUtils;

import java.io.*;
import java.math.BigInteger;
import java.security.SecureRandom;

// This code is a port of the public domain, "ref10" implementation of ed25519
// from SUPERCOP. More information at https://bench.cr.yp.to/supercop.html.

// The scalars are GF(2^252 + 27742317777372353535851937790883648493).
public class Scalar implements EdScalar, Cloneable {

    public static final BigInteger l = new BigInteger("7237005577332262213973186563042994240857116359379907606001950938285454250989");
    public static final BigInteger lminus = new BigInteger("7237005577332262213973186563042994240857116359379907606001950938285454250988");
    private static final byte[] ZERO = new byte[]{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    private static final byte[] ONE = new byte[]{1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    public cafe.cryptography.curve25519.Scalar scalar_pt;

    public Scalar() {
        scalar_pt = cafe.cryptography.curve25519.Scalar.fromBytesModOrder(ZERO);
    }

    @Override
    public byte[] MarshalBinary() throws IllegalArgumentException {
        try {
            byte[] data = this.scalar_pt.toByteArray();
            return data;
        }
        catch (IllegalArgumentException E) {
            throw new IllegalArgumentException("Invalid Scalar Representation");
        }
    }

    @Override
    public void UnmarshalBinary(byte[] data) throws IllegalArgumentException {
        if (data.length != 32 || (((data[31] >> 7) & 0x01) != 0)) {
            throw new IllegalArgumentException("Invalid scalar representation");
        }
        try {
            this.scalar_pt = cafe.cryptography.curve25519.Scalar.fromBytesModOrder(data);
        }
        catch (IllegalArgumentException E) {
            throw E;
        }
    }

    @Override
    public String String() {
        try {
            byte[] data = this.MarshalBinary();
            String string_rep = new String(data);
            return string_rep;
        }
        catch (Exception E) {
            System.err.println(E);
            return null;
        }
    }

    @Override
    public int MarshalSize() {
        return 32;
    }

    @Override
    public int MarshalTo(ObjectOutputStream w) throws IllegalArgumentException, IOException {
        byte[] data;
        CountingOutputStream out = new CountingOutputStream(w);
        try {
            data = this.MarshalBinary();
            out.write(data);
        }
        catch (IllegalArgumentException E) {
            throw E;
        }
        catch (IOException E) {
            throw new IOException("Output Stream Malfunction");
        }

        return (int) out.getCount();
    }

    @Override
    public int UnmarshalFrom(ObjectInputStream r) throws IllegalArgumentException, IOException {
        byte[] data = new byte[32];

        try {
            r.readFully(data);
            this.UnmarshalBinary(data);
            return 32;
        }
        catch (IllegalArgumentException E) {
            throw E;
        }
        catch (IOException E) {
            throw new IOException("Input Stream Malfunction");
        }
    }

    @Override
    public boolean Equal(EdScalar a) {
        Scalar s = (Scalar) a;
        int equality = this.scalar_pt.ctEquals(s.scalar_pt);
        return equality == 1;
    }

    @Override
    public EdScalar Set(EdScalar a) {
        Scalar s = (Scalar) a;
        this.scalar_pt = s.scalar_pt.add(cafe.cryptography.curve25519.Scalar.ZERO);
        return this;
    }

    @Override
    public EdScalar Clone() throws CloneNotSupportedException {
        Scalar scalar_clone = (Scalar) super.clone();
        return scalar_clone;
    }

    public EdScalar SetInt64(long v) {
        byte[] data = new byte[32];
        byte[] _data = Longs.toByteArray(v);
        for (int i = 0; i < 24; i++)
            data[i] = 0;
        for (int i = 24; i < 32; i++)
            data[i] = _data[i - 24];
        ArrayUtils.reverse(data);
        try {
            this.UnmarshalBinary(data);
        }
        catch (Exception E) {
            System.err.println(E);
        }
        return this;
    }

    @Override
    public EdScalar Zero() {
        this.scalar_pt = cafe.cryptography.curve25519.Scalar.fromBytesModOrder(ZERO);
        return this;
    }

    @Override
    public EdScalar Add(EdScalar a, EdScalar b) {
        Scalar s1 = (Scalar) a;
        Scalar s2 = (Scalar) b;
        this.scalar_pt = s1.scalar_pt.add(s2.scalar_pt);
        return this;
    }

    @Override
    public EdScalar Sub(EdScalar a, EdScalar b) {
        Scalar s1 = (Scalar) a;
        Scalar s2 = (Scalar) b;
        this.scalar_pt = s1.scalar_pt.subtract(s2.scalar_pt);
        return this;
    }

    @Override
    public EdScalar Neg(EdScalar a) {
        Scalar s = (Scalar) a;
        this.scalar_pt = cafe.cryptography.curve25519.Scalar.ZERO.subtract(s.scalar_pt);
        return this;
    }

    @Override
    public EdScalar One() {
        this.scalar_pt = cafe.cryptography.curve25519.Scalar.fromBytesModOrder(ONE);
        return this;
    }

    @Override
    public EdScalar Mul(EdScalar a, EdScalar b) {
        Scalar s1 = (Scalar) a;
        Scalar s2 = (Scalar) b;
        this.scalar_pt = s1.scalar_pt.multiply(s2.scalar_pt);
        return this;
    }

    @Override
    public EdScalar Div(EdScalar a, EdScalar b) {
        Scalar s1 = (Scalar) a;
        Scalar s2 = (Scalar) b;
        this.scalar_pt = s1.scalar_pt.divide(s2.scalar_pt);
        return this;
    }

    @Override
    public EdScalar Inv(EdScalar a) {
        Scalar s = (Scalar) a;
        this.scalar_pt = s.scalar_pt.invert();
        return this;
    }

    @Override
    public EdScalar Pick(SecureRandom rand) {
        int len = l.bitLength();
        byte[] check = new byte[32];
        // Fill the scalar with a random byte array
        BigInteger res = new BigInteger(len, rand);

        while (true) {
            // If the value of res exceeds l then its value will be mod l.
            if (res.compareTo(l) >= 0) {
                res = res.mod(l);
            }
            byte[] data = new byte[32];
            byte[] _data = res.toByteArray();

            // If the length of the byte string of the scalar is not 32 then pad it with zeroes.
            if (_data.length == 32) {
                data = _data;
            }
            else {
                int l = _data.length;
                for (int i = 0; i < 32 - l; i++) {
                    data[i] = 0;
                }
                for (int i = 32 - l; i < 32; i++) {
                    data[i] = _data[i - 32 + l];
                }
            }
            ArrayUtils.reverse(data);
            try {
                this.UnmarshalBinary(data); // Try to decode this byte string to a valid scalar
                break;
            }
            catch (Exception E) {
                continue;   // Failed try again.
            }
        }
        return this;
    }

    @Override
    public EdScalar setBytes(byte[] bytes) {
        if (bytes.length != 32 || (((bytes[31] >> 7) & 0x01) != 0)) {
            throw new IllegalArgumentException("Invalid scalar representation");
        }
        this.scalar_pt = cafe.cryptography.curve25519.Scalar.fromBytesModOrder(bytes);
        return this;
    }
}
