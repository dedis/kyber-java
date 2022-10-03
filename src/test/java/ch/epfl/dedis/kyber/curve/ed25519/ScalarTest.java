package ch.epfl.dedis.kyber.curve.ed25519;

import ch.epfl.dedis.kyber.EdScalar;
import org.bouncycastle.util.encoders.Hex;
import org.junit.Test;

import java.io.*;
import java.security.SecureRandom;

public class ScalarTest {

    static final EdScalar X = (new Scalar()).setBytes(Hex.decode("4e5ab4345d4708845913b4641bc27d5252a585101bcc4244d449f4a879d9f204"));
    static final EdScalar Y = (new Scalar()).setBytes(Hex.decode("907633fe1c4b66a4a28d2dd7678386c353d0de5455d4fc9de8ef7ac31f35bb05"));
    static final EdScalar XINV = (new Scalar()).setBytes(Hex.decode("1cdc17fce0e9a5bbd9247e56bb016347bbba31edd5a9bb96d50bcd7a3f962a0f"));
    static final EdScalar X_TIMES_Y = (new Scalar()).setBytes(Hex.decode("6c3374a1894f62210aaa2fe186a6f92ce0aa75c2779581c295fc08179a73940c"));

    @Test
    public void checkValidByteArray() {
        byte[] s = new byte[32];
        s[31] = 0x7f;
        EdScalar sc = (new Scalar()).setBytes(s);
    }

    @Test(expected = IllegalArgumentException.class)
    public void checkInvalidByteArray() {
        byte[] s = new byte[32];
        s[31] = (byte) 0x80;
        EdScalar sc = (new Scalar()).setBytes(s);
    }

    @Test
    public void setBytesPreventsMutability() {
        EdScalar a1 = new Scalar();
        EdScalar a2 = new Scalar();
        assert (a1.Equal(a2));

        try {
            byte[] b = a1.MarshalBinary();
            b[0] = 4;
            assert (a1.Equal(a2));
        }
        catch (Exception E) {
            System.err.println(E);
            assert (false);
        }
    }

    @Test
    public void cloningPreventsMutability() throws CloneNotSupportedException {
        EdScalar a1 = new Scalar();
        EdScalar a2 = a1.Clone();
        assert (a1.Equal(a2));
        a1.Set(X);
        assert (!a1.Equal(a2));
    }

    @Test
    public void addAndSub() {
        EdScalar a = new Scalar();
        a.Pick(new SecureRandom());
        EdScalar b = new Scalar();
        b.Pick(new SecureRandom());
        EdScalar a_plus_b = (new Scalar()).Add(a, b);
        EdScalar a_minus_b = (new Scalar()).Sub(a, b);
        EdScalar double_a = (new Scalar()).Add(a, a);
        EdScalar res = new Scalar();
        assert (res.Add(a_plus_b, a_minus_b).Equal(double_a));
    }

    @Test
    public void multiply() {
        EdScalar ans_mul1 = new Scalar();
        EdScalar ans_mul2 = new Scalar();
        assert (ans_mul1.Mul(X, Y).Equal(X_TIMES_Y));
        assert (ans_mul2.Mul(X_TIMES_Y, XINV).Equal(Y));
    }

    @Test
    public void inverse() {
        EdScalar inv_ans = new Scalar();
        assert (inv_ans.Inv(X).Equal(XINV));
    }

    @Test
    public void divide() {
        EdScalar ans_div = new Scalar();
        EdScalar ans_mul = new Scalar();
        assert (ans_div.Div(Y, X).Equal(ans_mul.Mul(Y, XINV)));
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
        EdScalar s = new Scalar();

        try {
            num_bytes = s.UnmarshalFrom(ois);
        }
        catch (Exception E) {
            System.err.println(E);
            assert (false);
        }

        assert (num_bytes == 32);
        assert (s.Equal(X));
    }

}
