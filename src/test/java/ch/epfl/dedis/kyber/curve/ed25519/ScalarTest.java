package ch.epfl.dedis.kyber.curve.ed25519;

import ch.epfl.dedis.kyber.Scalar;
import ch.epfl.dedis.kyber.utils.Utils;
import javafx.util.Pair;
import org.junit.Test;
import java.io.*;
import java.security.SecureRandom;

import static org.junit.Assert.*;

public class ScalarTest {

    static final Scalar X = (new scalar()).setBytes(Utils.hexToBytes("4e5ab4345d4708845913b4641bc27d5252a585101bcc4244d449f4a879d9f204"));
    static final Scalar Y = (new scalar()).setBytes(Utils.hexToBytes("907633fe1c4b66a4a28d2dd7678386c353d0de5455d4fc9de8ef7ac31f35bb05"));
    static final Scalar XINV = (new scalar()).setBytes(Utils.hexToBytes("1cdc17fce0e9a5bbd9247e56bb016347bbba31edd5a9bb96d50bcd7a3f962a0f"));
    static final Scalar X_TIMES_Y = (new scalar()).setBytes(Utils.hexToBytes("6c3374a1894f62210aaa2fe186a6f92ce0aa75c2779581c295fc08179a73940c"));

    @Test
    public void checkValidByteArray() {
        byte[] s = new byte[32];
        s[31] = 0x7f;
        Scalar sc = (new scalar()).setBytes(s);
    }

    @Test(expected = IllegalArgumentException.class)
    public void checkInvalidByteArray() {
        byte[] s = new byte[32];
        s[31] = (byte) 0x80;
        Scalar sc = (new scalar()).setBytes(s);
    }

    @Test
    public void setBytesPreventsMutability() {
        Scalar a1 = new scalar();
        Scalar a2 = new scalar();
        assert(a1.Equal(a2));
        Pair<byte[], Exception> p = a1.MarshalBinary();
        byte[] b = p.getKey();
        Exception e = p.getValue();
        assertNull(e);
        b[0] = 4;
        assert(a1.Equal(a2));
    }

    @Test
    public void cloningPreventsMutability() throws CloneNotSupportedException {
        Scalar a1 = new scalar();
        Scalar a2 = a1.Clone();
        assert(a1.Equal(a2));
        a1.Set(X);
        assert(!a1.Equal(a2));
    }

    @Test
    public void addAndSub() {
        Scalar a = new scalar();
        a.Pick(new SecureRandom());
        Scalar b = new scalar();
        b.Pick(new SecureRandom());
        Scalar a_plus_b = (new scalar()).Add(a,b);
        Scalar a_minus_b = (new scalar()).Sub(a,b);
        Scalar double_a = (new scalar()).Add(a,a);
        Scalar res = new scalar();
        assert(res.Add(a_plus_b, a_minus_b).Equal(double_a));
    }

    @Test
    public void multiply() {
        Scalar ans_mul1 = new scalar();
        Scalar ans_mul2 = new scalar();
        assert(ans_mul1.Mul(X, Y).Equal(X_TIMES_Y));
        assert(ans_mul2.Mul(X_TIMES_Y, XINV).Equal(Y));
    }

    @Test
    public void inverse() {
        Scalar inv_ans = new scalar();
        assert(inv_ans.Inv(X).Equal(XINV));
    }

    @Test
    public void divide() {
        Scalar ans_div = new scalar();
        Scalar ans_mul = new scalar();
        assert(ans_div.Div(Y, X).Equal(ans_mul.Mul(Y, XINV)));
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
        Scalar s = new scalar();
        p = s.UnmarshalFrom(ois);
        //TODO: is this type of string expected?
        //System.out.println(s.String());
        assert(s.Equal(X));
    }

}
