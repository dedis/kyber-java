package ch.epfl.dedis.kyber.curve.ed25519;

import ch.epfl.dedis.kyber.EdPoint;
import ch.epfl.dedis.kyber.EdScalar;
import org.bouncycastle.util.encoders.Hex;
import org.junit.Test;

import java.io.*;
import java.security.SecureRandom;
import java.util.Arrays;

public class PointTest {
    static final EdScalar A_SCALAR = (new Scalar()).setBytes(
            Hex.decode("1a0e978a90f6622d3747023f8ad8264da758aa1b88e040d1589e7b7f2376ef09"));
    static final EdScalar two = (new Scalar()).setBytes(
            Hex.decode("0200000000000000000000000000000000000000000000000000000000000000"));
    static EdPoint X = new Point().Pick(new SecureRandom());

    @Test
    public void addAndSub() {
        EdPoint a = new Point();
        a.Pick(new SecureRandom());
        EdPoint b = new Point();
        b.Pick(new SecureRandom());
        EdPoint a_plus_b = (new Point()).Add(a, b);
        EdPoint a_minus_b = (new Point()).Sub(a, b);
        EdPoint double_a = (new Point()).Add(a, a);
        EdPoint res = new Point();
        assert (res.Add(a_plus_b, a_minus_b).Equal(double_a));
    }

    @Test
    public void embedAndData() {
        SecureRandom r = new SecureRandom();
        EdPoint a = new Point();
        a.Pick(r);
        byte[] data = new byte[29];
        r.nextBytes(data);
        a.Embed(data, r);
        try {
            byte[] bytes = a.Data();
            assert (Arrays.equals(bytes, data));
        }
        catch (Exception E) {
            System.err.println(E);
            assert (false);
        }
    }

    @Test
    public void serializeDeserialize() throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(baos);
        int num_bytes = 0;
        try {
            num_bytes = X.MarshalTo(oos);
        }
        catch (Exception E) {
            System.err.println(E);
            assert (false);
        }

        assert (num_bytes == 32);
        oos.close();
        ByteArrayInputStream bais = new ByteArrayInputStream(baos.toByteArray());
        ObjectInputStream ois = new ObjectInputStream(bais);
        EdPoint p = new Point();

        try {
            num_bytes = p.UnmarshalFrom(ois);
        }
        catch (Exception E) {
            System.err.println(E);
            assert (false);
        }

        assert (num_bytes == 32);
        assert (p.Equal(X));
    }

    @Test
    public void cloningPreventsMutability() throws CloneNotSupportedException {
        EdPoint a1 = new Point();
        EdPoint a2 = a1.Clone();
        assert (a1.Equal(a2));
        a1.Set(X);
        assert (!a1.Equal(a2));
    }

    @Test
    public void multiplication() {
        EdPoint A_TIMES_BASEPOINT = new Point();
        try {
            A_TIMES_BASEPOINT.UnmarshalBinary(
                    Hex.decode("ea27e26053df1b5956f14d5dec3c34c384a269b74cc3803ea8e2e7c9425e40a5"));
        }
        catch (Exception E) {
            System.err.println(E);
            assert (false);
        }
        EdScalar a = (new Scalar()).setBytes(
                Hex.decode("d072f8dd9c07fa7bc8d22a4b325d26301ee9202f6db89aa7c3731529e37e437c"));
        EdPoint A = new Point();
        try {
            A.UnmarshalBinary(
                    Hex.decode("d4cf8595571830644bd14af416954d09ab7159751ad9e0f7a6cbd92379e71a66"));
        }
        catch (Exception E) {
            System.err.println(E);
            assert (false);
        }

        // Checking base point multiplication
        EdPoint res = (new Point()).Mul(A_SCALAR, null);
        assert (res.Equal(A_TIMES_BASEPOINT));

        // Checking normal multiplicaton
        // 2*a*B = 2*A, where B is the basepoint
        a.Mul(a, two);
        res = res.Mul(a, null);
        EdPoint _res = (new Point()).Mul(two, A);
        assert (res.Equal(_res));
    }

    @Test
    public void pointSet() {
        EdPoint A = new Point();
        try {
            A.UnmarshalBinary(
                    Hex.decode("d4cf8595571830644bd14af416954d09ab7159751ad9e0f7a6cbd92379e71a66"));
        }
        catch (Exception E) {
            System.err.println(E);
            assert (false);
        }

        EdPoint X = (new Point()).Set(A);
        assert (X.Equal(A));
    }
}
