package ch.epfl.dedis.kyber.curve.ed25519;

import cafe.cryptography.curve25519.EdwardsBasepointTable;
import ch.epfl.dedis.kyber.Scalar;
import com.google.common.io.CountingOutputStream;
import com.google.common.primitives.Longs;
import org.apache.commons.lang3.ArrayUtils;
import javafx.util.Pair;

import java.io.*;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;

public class scalar implements Scalar, Cloneable {

    public cafe.cryptography.curve25519.Scalar scalar_pt;

    private static final byte[] ZERO = new byte[] { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    private static final byte[] ONE = new byte[] { 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    public static final BigInteger l = new BigInteger("7237005577332262213973186563042994240857116359379907606001950938285454250989");
    public static final BigInteger lminus = new BigInteger("7237005577332262213973186563042994240857116359379907606001950938285454250988");

    public scalar(){
        scalar_pt = cafe.cryptography.curve25519.Scalar.fromBytesModOrder(ZERO);
    }

    @Override
    public Pair<byte[], Exception> MarshalBinary() {
        try {
            byte[] data = this.scalar_pt.toByteArray();
            return new Pair<>(data, null);
        }
        catch (Exception E) {
            return new Pair<>(null, E);
        }
    }

    @Override
    public Exception UnmarshalBinary(byte[] data) {
        if (data.length != 32 || (((data[31] >> 7) & 0x01) != 0)) {
            return new IllegalArgumentException("Invalid scalar representation");
        }
        try {
            this.scalar_pt = cafe.cryptography.curve25519.Scalar.fromBytesModOrder(data);
            return null;
        }
        catch (Exception E) {
            return E;
        }
    }

    @Override
    public String String() {
        Pair<byte[], Exception> s = this.MarshalBinary();
        Exception err = s.getValue();
        if (err != null) {
            System.err.println(err);
            return null;
        }
        else {
            String string_rep = new String(s.getKey());
            return string_rep;
        }
    }

    @Override
    public int MarshalSize() {
        return 32;
    }

    @Override
    public Pair<Integer, Exception> MarshalTo(ObjectOutputStream w) {
        Pair<byte[], Exception> p = this.MarshalBinary();
        Exception err = p.getValue();
        if (err != null) {
            return new Pair<>(0,err);
        }
        byte[] data = p.getKey();
        CountingOutputStream out = new CountingOutputStream(w);
        try {
            out.write(data);
        }
        catch (IOException E) {
            return new Pair<>((int)out.getCount(), null);
        }
        catch (Exception E) {
            return new Pair<>((int)out.getCount(), E);
        }
        return new Pair<>((int)out.getCount(), null);
    }

    @Override
    public Pair<Integer, Exception> UnmarshalFrom(ObjectInputStream r) {
        byte[] data = new byte[32];
        try {
            r.readFully(data);
        }
        catch(IOException E) {
            Exception err = this.UnmarshalBinary(data);
            return new Pair<>(32, err);
        }
        catch(Exception E) {
            return new Pair<>(0, E);
        }
        Exception err = this.UnmarshalBinary(data);
        return new Pair<>(32, err);
    }

    @Override
    public boolean Equal(Scalar a) {
        scalar s = (scalar) a;
        int equality = this.scalar_pt.ctEquals(s.scalar_pt);
        return equality == 1;
    }

    @Override
    public Scalar Set(Scalar a) {
        scalar s = (scalar) a;
        this.scalar_pt = s.scalar_pt.add(cafe.cryptography.curve25519.Scalar.ZERO);
        return this;
    }

    @Override
    public Scalar Clone() throws CloneNotSupportedException{
        scalar scalar_clone = (scalar) super.clone();
        return scalar_clone;
    }

    public Scalar SetInt64(long v) {
        byte[] data = new byte[32];
        byte[] _data = Longs.toByteArray(v);
        for(int i = 0; i < 24; i++)
            data[i] = 0;
        for(int i = 24; i < 32; i++)
            data[i] = _data[i - 24];
        ArrayUtils.reverse(data);
        Exception E = this.UnmarshalBinary(data);
        if (E != null)
            System.err.println(E);
        return this;
    }

    @Override
    public Scalar Zero() {
        this.scalar_pt = cafe.cryptography.curve25519.Scalar.fromBytesModOrder(ZERO);
        return this;
    }

    @Override
    public Scalar Add(Scalar a, Scalar b) {
        scalar s1 = (scalar) a;
        scalar s2 = (scalar) b;
        this.scalar_pt = s1.scalar_pt.add(s2.scalar_pt);
        return this;
    }

    @Override
    public Scalar Sub(Scalar a, Scalar b) {
        scalar s1 = (scalar) a;
        scalar s2 = (scalar) b;
        this.scalar_pt = s1.scalar_pt.subtract(s2.scalar_pt);
        return this;
    }

    @Override
    public Scalar Neg(Scalar a) {
        scalar s = (scalar) a;
        this.scalar_pt = cafe.cryptography.curve25519.Scalar.ZERO.subtract(s.scalar_pt);
        return this;
    }

    @Override
    public Scalar One() {
        this.scalar_pt = cafe.cryptography.curve25519.Scalar.fromBytesModOrder(ONE);
        return this;
    }

    @Override
    public Scalar Mul(Scalar a, Scalar b) {
        scalar s1 = (scalar) a;
        scalar s2 = (scalar) b;
        this.scalar_pt = s1.scalar_pt.multiply(s2.scalar_pt);
        return this;
    }

    @Override
    public Scalar Div(Scalar a, Scalar b) {
        scalar s1 = (scalar) a;
        scalar s2 = (scalar) b;
        this.scalar_pt = s1.scalar_pt.divide(s2.scalar_pt);
        return this;
    }

    @Override
    public Scalar Inv(Scalar a) {
        scalar s = (scalar) a;
        this.scalar_pt = s.scalar_pt.invert();
        return this;
    }

    @Override
    public Scalar Pick(SecureRandom rand) {
        int len = l.bitLength();
        byte[] check = new byte[32];
        BigInteger res = new BigInteger(len, rand);
        while(true) {
            if (res.compareTo(l) >= 0) {
                //TODO: get this checked for the uniformity and all
                res = res.mod(l);
            }
            byte[] data = new byte[32];
            byte[] _data = res.toByteArray();
            if(_data.length == 32)
                data = _data;
            else {
                int l = _data.length;
                for(int i = 0; i < 32 - l; i++) {
                    data[i] = 0;
                }
                for(int i = 32 - l; i < 32; i++) {
                    data[i] = _data[i - 32 + l];
                }
            }
            ArrayUtils.reverse(data);
            Exception E = this.UnmarshalBinary(data);
            if (E == null)
                break;
        }
        return this;
    }

    @Override
    public Scalar setBytes(byte[] bytes) {
        if (bytes.length != 32 || (((bytes[31] >> 7) & 0x01) != 0)) {
            throw new IllegalArgumentException("Invalid scalar representation");
        }
        this.scalar_pt = cafe.cryptography.curve25519.Scalar.fromBytesModOrder(bytes);
        return this;
    }
}
