package ch.epfl.dedis.kyber.curve.ed25519.benchmarks;

import ch.epfl.dedis.kyber.EdPoint;
import ch.epfl.dedis.kyber.EdScalar;
import ch.epfl.dedis.kyber.curve.ed25519.Point;
import ch.epfl.dedis.kyber.curve.ed25519.Scalar;
import org.openjdk.jmh.annotations.*;

import java.security.SecureRandom;
import java.util.concurrent.TimeUnit;

@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.NANOSECONDS)
@Warmup(iterations = 5, time = 1, timeUnit = TimeUnit.SECONDS)
@Measurement(iterations = 5, time = 2, timeUnit = TimeUnit.SECONDS)
@Fork(1)
@State(Scope.Benchmark)
public class Ed25519Bench {

    private EdScalar s1, s2;
    private EdPoint p1, p2;
    private byte[] s1b, p1b;

    @Setup
    public void prepare() throws Exception {
        this.s1 = (new Scalar()).Pick(new SecureRandom());
        this.s2 = (new Scalar()).Pick(new SecureRandom());
        this.s1b = this.s1.MarshalBinary();
        this.p1 = (new Point()).Pick(new SecureRandom());
        this.p2 = (new Point()).Pick(new SecureRandom());
        this.p1b = this.p1.MarshalBinary();
    }

    @Benchmark
    public void scalarAdd() {
        this.s1.Add(this.s1, this.s2);
    }

    @Benchmark
    public void scalarSub() {
        this.s1.Sub(this.s1, this.s2);
    }

    @Benchmark
    public void scalarNeg() {
        this.s1.Neg(this.s1);
    }

    @Benchmark
    public void scalarMul() {
        this.s1.Mul(this.s1, this.s2);
    }

    @Benchmark
    public void scalarDiv() {
        this.s1.Div(this.s1, this.s2);
    }

    @Benchmark
    public void scalarInv() {
        this.s1.Inv(this.s1);
    }

    @Benchmark
    public void scalarPick() {
        this.s1.Pick(new SecureRandom());
    }

    @Benchmark
    public void scalarEncode() throws Exception {
        this.s1.MarshalBinary();
    }

    @Benchmark
    public void scalarDecode() throws Exception {
        this.s1.UnmarshalBinary(s1b);
    }

    @Benchmark
    public void pointAdd() {
        this.p1.Add(this.p1, this.p2);
    }

    @Benchmark
    public void pointSub() {
        this.p1.Sub(this.p1, this.p2);
    }

    @Benchmark
    public void pointNeg() {
        this.p1.Neg(this.p1);
    }

    @Benchmark
    public void pointMul() {
        this.p1.Mul(this.s1, this.p2);
    }

    @Benchmark
    public void pointBaseMul() {
        this.p1.Mul(this.s1, null);
    }

    @Benchmark
    public void pointPick() {
        this.p1.Pick(new SecureRandom());
    }

    @Benchmark
    public void pointEncode() throws Exception {
        this.p1.MarshalBinary();
    }

    @Benchmark
    public void pointDecode() throws Exception {
        this.p1.UnmarshalBinary(p1b);
    }
}
