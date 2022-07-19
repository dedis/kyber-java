package ch.epfl.dedis.kyber.curve.ed25519;

import ch.epfl.dedis.kyber.Point;
import ch.epfl.dedis.kyber.Scalar;
import ch.epfl.dedis.kyber.utils.Utils;
import javafx.util.Pair;
import org.junit.Test;
import java.io.*;
import java.security.SecureRandom;
import java.util.Arrays;

public class PointTest {
    static Point X = new point().Pick(new SecureRandom());
    static final Scalar A_SCALAR = (new scalar()).setBytes(
            Utils.hexToBytes("1a0e978a90f6622d3747023f8ad8264da758aa1b88e040d1589e7b7f2376ef09"));
    static final Scalar two = (new scalar()).setBytes(
            Utils.hexToBytes("0200000000000000000000000000000000000000000000000000000000000000"));

    @Test
    public void addAndSub() {
        Point a = new point();
        a.Pick(new SecureRandom());
        Point b = new point();
        b.Pick(new SecureRandom());
        Pair<byte[], Exception> p = a.MarshalBinary();
        Point a_plus_b = (new point()).Add(a,b);
        Point a_minus_b = (new point()).Sub(a,b);
        Point double_a = (new point()).Add(a,a);
        Point res = new point();
        assert(res.Add(a_plus_b, a_minus_b).Equal(double_a));
    }

    @Test
    public void embedAndData() {
        SecureRandom r = new SecureRandom();
        Point a = new point();
        a.Pick(r);
        byte[] data = new byte[29];
        r.nextBytes(data);
        a.Embed(data, r);
        Pair<byte[], Exception> p = a.Data();
        assert(p.getValue() == null);
        assert(Arrays.equals(p.getKey(), data));
    }

    @Test
    public void serializeDeserialize() throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(baos);
        Pair<Integer, Exception> p = X.MarshalTo(oos);
        //System.out.println(X.String());
        oos.close();
        ByteArrayInputStream bais = new ByteArrayInputStream(baos.toByteArray());
        ObjectInputStream ois = new ObjectInputStream(bais);
        Point s = new point();
        p = s.UnmarshalFrom(ois);
        //TODO: is this type of string expected?
        //System.out.println(s.String());
        assert(s.Equal(X));
    }

    @Test
    public void cloningPreventsMutability() throws CloneNotSupportedException {
        Point a1 = new point();
        Point a2 = a1.Clone();
        assert(a1.Equal(a2));
        a1.Set(X);
        assert(!a1.Equal(a2));
    }

    @Test
    public void multiplication() {
        Point A_TIMES_BASEPOINT = new point();
        Exception err = A_TIMES_BASEPOINT.UnmarshalBinary(
                Utils.hexToBytes("ea27e26053df1b5956f14d5dec3c34c384a269b74cc3803ea8e2e7c9425e40a5"));
        assert(err == null);
        Scalar a = (new scalar()).setBytes(
                Utils.hexToBytes("d072f8dd9c07fa7bc8d22a4b325d26301ee9202f6db89aa7c3731529e37e437c"));
        Point A = new point();
        err = A.UnmarshalBinary(
                Utils.hexToBytes("d4cf8595571830644bd14af416954d09ab7159751ad9e0f7a6cbd92379e71a66"));
        assert(err == null);

        // Checking base point multiplication
        Point res = (new point()).Mul(A_SCALAR, null);
        assert(res.Equal(A_TIMES_BASEPOINT));

        // Checking normal multiplicaton
        // 2*a*B = 2*A, where B is the basepoint
        a.Mul(a, two);
        res = res.Mul(a, null);
        Point _res = (new point()).Mul(two, A);
        assert(res.Equal(_res));
    }

    @Test
    public void pointSet() {
        Point A = new point();
        Exception err = A.UnmarshalBinary(
                Utils.hexToBytes("d4cf8595571830644bd14af416954d09ab7159751ad9e0f7a6cbd92379e71a66"));
        assert(err == null);

        Point X = (new point()).Set(A);
        assert(X.Equal(A));
    }
}
