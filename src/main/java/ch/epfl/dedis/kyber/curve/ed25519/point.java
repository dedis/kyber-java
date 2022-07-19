package ch.epfl.dedis.kyber.curve.ed25519;

import cafe.cryptography.curve25519.EdwardsBasepointTable;
import ch.epfl.dedis.kyber.Point;
import ch.epfl.dedis.kyber.Scalar;
import cafe.cryptography.curve25519.EdwardsPoint;
import cafe.cryptography.curve25519.CompressedEdwardsY;
import cafe.cryptography.curve25519.Constants;

import ch.epfl.dedis.kyber.utils.Utils;
import com.google.common.io.CountingOutputStream;
import javafx.util.Pair;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.SecureRandom;

public class point implements Point, Cloneable {

    private EdwardsPoint point_pt;

    private static final SecureRandom scRandom = new SecureRandom();
    public static final Scalar cofactor = (new scalar()).SetInt64(8);
    public static final point nullPoint = new point();
    public static final Scalar primeOrderScalar = (new scalar()).setBytes(Utils.bigIntToLittleEndianBytes(scalar.l));
    public static final EdwardsBasepointTable bp = Constants.ED25519_BASEPOINT_TABLE;

    public point(){
        point_pt = EdwardsPoint.IDENTITY;
    }

    @Override
    public Pair<byte[], Exception> MarshalBinary() {
        byte[] data;
        try {
            data = this.point_pt.compress().toByteArray();
            return new Pair<>(data, null);
        }
        catch (Exception E) {
            return new Pair<>(null, E);
        }
    }

    @Override
    public Exception UnmarshalBinary(byte[] data) {
        try {
            this.point_pt = new CompressedEdwardsY(data).decompress();
            return null;
        }
        catch(Exception E) {
            return E;
        }
    }

    @Override
    public String String() {
        Pair<byte[], Exception> p = this.MarshalBinary();
        Exception err = p.getValue();
        if (err != null) {
            System.err.println(err);
            return null;
        }
        String ans = new String(p.getKey());
        return ans;
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
    public boolean Equal(Point a) {
        point p = (point) a;
        int res = this.point_pt.ctEquals(p.point_pt);
        return res == 1;
    }

    @Override
    public Point Null() {
        this.point_pt = EdwardsPoint.IDENTITY;
        return this;
    }

    @Override
    public Point Base() {
        this.point_pt = Constants.ED25519_BASEPOINT;
        return this;
    }

    @Override
    public Point Pick(SecureRandom rand) {
        this.Embed(null, rand);
        return this;
    }

    @Override
    public Point Set(Point a) {
        //TODO: See if the additive identity has been chosen correctly
        point p = (point) a;
        this.point_pt = EdwardsPoint.IDENTITY.add(p.point_pt);
        return this;
    }

    @Override
    public Point Clone() throws CloneNotSupportedException {
        point point_clone = (point) super.clone();
        return point_clone;
    }

    @Override
    public int EmbedLen() {
        return (255 - 8 - 8) / 8;
    }

    @Override
    public Point Embed(byte[] data, SecureRandom rand) {
        int dl = this.EmbedLen();
        int data_len;
        if(data == null)
            data_len = 0;
        else
            data_len = data.length;
        if (data_len > dl ) {
            throw new Error("Invalid data length");
        }
        if (dl > data_len) {
            dl = data_len;
        }

        while(true) {
            byte[] bytes = new byte[32];
            rand.nextBytes(bytes);

            if (data != null) {
                bytes[0] = (byte) dl;
                System.arraycopy(data, 0, bytes, 1, dl);
            }

            Exception err = this.UnmarshalBinary(bytes);
            if (err != null) {
                continue;
            }

            if (data == null) {
                this.Mul(cofactor, this);
                if(this.Equal(nullPoint))
                    continue;
                return this;
            }

            Point q = new point();
            q.Mul(primeOrderScalar, this);
            if (q.Equal(nullPoint))
                return this;
            continue;
        }
    }

    @Override
    public Pair<byte[], Exception> Data() {
        Pair<byte[], Exception> p = this.MarshalBinary();
        byte[] data = p.getKey();
        int dl = (int) data[0];
        if (dl > this.EmbedLen()) {
            return new Pair<>(null, new Exception("Invalid embedded data length"));
        }
        byte[] embeddedData = new byte[dl];
        for(int i = 0; i < dl; i++) {
            embeddedData[i] = data[1 + i];
        }
        return new Pair<>(embeddedData, null);
    }

    @Override
    public Point Add(Point a, Point b) {
        point p1 = (point) a;
        point p2 = (point) b;
        this.point_pt = p1.point_pt.add(p2.point_pt);
        return this;
    }

    @Override
    public Point Sub(Point a, Point b) {
        point p1 = (point) a;
        point p2 = (point) b;
        this.point_pt = p1.point_pt.subtract(p2.point_pt);
        return this;
    }

    @Override
    public Point Neg(Point a) {
        point p = (point) a;
        this.point_pt = p.point_pt.negate();
        return this;
    }

    @Override
    public Point Mul(Scalar a, Point b) {
        scalar s = (scalar) a;
        if(b == null) {
            this.point_pt = this.bp.multiply(s.scalar_pt);
        }
        else {
            point p = (point) b;
            this.point_pt = p.point_pt.multiply(s.scalar_pt);
        }
        return this;
    }
}
