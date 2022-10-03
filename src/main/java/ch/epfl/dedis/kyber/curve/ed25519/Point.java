package ch.epfl.dedis.kyber.curve.ed25519;

import cafe.cryptography.curve25519.*;
import cafe.cryptography.curve25519.InvalidEncodingException;
import ch.epfl.dedis.kyber.EdPoint;
import ch.epfl.dedis.kyber.EdScalar;

import ch.epfl.dedis.kyber.utils.Utils;
import com.google.common.io.CountingOutputStream;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.SecureRandom;

// Package edwards25519 provides an optimized Go implementation of a
// Twisted Edwards curve that is isomorphic to Curve25519. For details see:
// http://ed25519.cr.yp.to/.
//
// This code is based on Adam Langley's Go port of the public domain,
// "ref10" implementation of the ed25519 signing scheme in C from SUPERCOP.
// It was generalized and extended to support full kyber.Group arithmetic
// by the DEDIS lab at Yale and EPFL.
//
// Due to the field element and group arithmetic optimizations
// described in the Ed25519 paper, this implementation generally
// performs extremely well, typically comparable to native C
// implementations.  The tradeoff is that this code is completely
// specialized to a single curve.
public class Point implements EdPoint, Cloneable {

    public static final EdScalar cofactor = (new Scalar()).SetInt64(8);
    public static final Point nullPoint = new Point();
    public static final EdScalar primeOrderScalar = (new Scalar()).setBytes(Utils.bigIntToLittleEndianBytes(Scalar.l));
    public static final EdwardsBasepointTable bp = Constants.ED25519_BASEPOINT_TABLE;
    private static final SecureRandom scRandom = new SecureRandom();
    private EdwardsPoint point_pt;

    public Point() {
        point_pt = EdwardsPoint.IDENTITY;
    }

    @Override
    public byte[] MarshalBinary() throws IllegalArgumentException {
        byte[] data;
        try {
            data = this.point_pt.compress().toByteArray();
            return data;
        }
        catch (IllegalArgumentException E) {
            throw new IllegalArgumentException("Invalid Point Representationf");
        }
    }

    @Override
    public void UnmarshalBinary(byte[] data) throws InvalidEncodingException {
        try {
            this.point_pt = new CompressedEdwardsY(data).decompress();
        }
        catch (InvalidEncodingException E) {
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
        catch (IllegalArgumentException E) {
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
            throw new IOException("Output Stream malfunction");
        }

        return (int) out.getCount();
    }

    @Override
    public int UnmarshalFrom(ObjectInputStream r) throws InvalidEncodingException, IOException {
        byte[] data = new byte[32];

        try {
            r.readFully(data);
            this.UnmarshalBinary(data);
            return 32;
        }
        catch (InvalidEncodingException E) {
            throw E;
        }
        catch (IOException E) {
            throw new IOException("Input Stream malfunction");
        }
    }

    @Override
    public boolean Equal(EdPoint a) {
        Point p = (Point) a;
        int res = this.point_pt.ctEquals(p.point_pt);
        return res == 1;
    }

    @Override
    public EdPoint Null() {
        this.point_pt = EdwardsPoint.IDENTITY;
        return this;
    }

    @Override
    public EdPoint Base() {
        this.point_pt = Constants.ED25519_BASEPOINT;
        return this;
    }

    @Override
    public EdPoint Pick(SecureRandom rand) {
        this.Embed(null, rand);
        return this;
    }

    @Override
    public EdPoint Set(EdPoint a) {
        Point p = (Point) a;
        this.point_pt = EdwardsPoint.IDENTITY.add(p.point_pt);
        return this;
    }

    @Override
    public EdPoint Clone() throws CloneNotSupportedException {
        Point point_clone = (Point) super.clone();
        return point_clone;
    }

    @Override
    public int EmbedLen() {
        // Reserve the most-significant 8 bits for pseudo-randomness.
        // Reserve the least-significant 8 bits for embedded data length.
        // (Hopefully it's unlikely we'll need >=2048-bit curves soon.)
        return (255 - 8 - 8) / 8;
    }

    @Override
    public EdPoint Embed(byte[] data, SecureRandom rand) throws IllegalArgumentException {
        // Number of bytes to embed
        int dl = this.EmbedLen();
        int data_len;

        if (data == null) {
            data_len = 0;
        }
        else {
            data_len = data.length;
        }
        if (data_len > dl) {
            throw new IllegalArgumentException("Invalid data length");
        }
        if (dl > data_len) {
            dl = data_len;
        }

        while (true) {
            // Pick a random point, with optional embedded data
            byte[] bytes = new byte[32];
            rand.nextBytes(bytes);

            if (data != null) {
                bytes[0] = (byte) dl;                            // Encode length in low 8 bits
                System.arraycopy(data, 0, bytes, 1, dl);    // Copy in data to embed
            }

            try {
                this.UnmarshalBinary(bytes); // Try to decode
            }
            catch (Exception E) {
                continue;   // invalid point, retry
            }

            // If we're using the full group,
            // we just need any point on the curve, so we're done.
            //		if c.full {
            //			return P,data[dl:]
            //		}

            // We're using the prime-order subgroup,
            // so we need to make sure the point is in that subencoding.
            // If we're not trying to embed data,
            // we can convert our point into one in the subgroup
            // simply by multiplying it by the cofactor.
            if (data == null) {
                this.Mul(cofactor, this);   // multiply by cofactor
                if (this.Equal(nullPoint)) {
                    continue;   // unlucky; try again
                }
                return this;    // success
            }

            // Since we need the point's y-coordinate to hold our data,
            // we must simply check if the point is in the subgroup
            // and retry point generation until it is.
            EdPoint q = new Point();
            q.Mul(primeOrderScalar, this);
            if (q.Equal(nullPoint)) {
                return this;
            }
        }
    }

    @Override
    public byte[] Data() throws IllegalArgumentException {
        try {
            byte[] data = this.MarshalBinary();
            int dl = (int) data[0];
            if (dl > this.EmbedLen()) {
                throw new IllegalArgumentException("Invalid embedded data length");
            }
            byte[] embeddedData = new byte[dl];
            for (int i = 0; i < dl; i++) {
                embeddedData[i] = data[1 + i];
            }
            return embeddedData;
        }
        catch (IllegalArgumentException E) {
            throw E;
        }
    }

    @Override
    public EdPoint Add(EdPoint a, EdPoint b) {
        Point p1 = (Point) a;
        Point p2 = (Point) b;
        this.point_pt = p1.point_pt.add(p2.point_pt);
        return this;
    }

    @Override
    public EdPoint Sub(EdPoint a, EdPoint b) {
        Point p1 = (Point) a;
        Point p2 = (Point) b;
        this.point_pt = p1.point_pt.subtract(p2.point_pt);
        return this;
    }

    // Neg finds the negative of point A.
    // For Edwards curves, the negative of (x,y) is (-x,y).
    @Override
    public EdPoint Neg(EdPoint a) {
        Point p = (Point) a;
        this.point_pt = p.point_pt.negate();
        return this;
    }

    // Mul multiplies point p by scalar s using the repeated doubling method.
    @Override
    public EdPoint Mul(EdScalar a, EdPoint b) {
        Scalar s = (Scalar) a;
        if (b == null) {
            this.point_pt = this.bp.multiply(s.scalar_pt);
        }
        else {
            Point p = (Point) b;
            this.point_pt = p.point_pt.multiply(s.scalar_pt);
        }
        return this;
    }
}
