package ch.epfl.dedis.kyber.xof;

import ch.epfl.dedis.kyber.XOF;
import javafx.util.Pair;
import org.kocakosm.jblake2.Blake2b;

// Package blake2xb provides an implementation of kyber.XOF based on the
// Blake2xb construction.
public class Blake2xb implements XOF, Cloneable {
    public Blake2b impl;
    // key is here to not make excess garbage during repeated calls
    // to XORKeyStream.
    public byte[] key;

    public Blake2xb() {
        this.impl = new Blake2b(64);
    }

    public Blake2xb(byte[] seed) {
        this.impl = new Blake2b(64);
        byte[] seed1, seed2;
        if (seed.length > 64) {
            seed1 = new byte[64];
            System.arraycopy(seed, 0, seed1, 0, 64);
            seed2 = new byte[seed.length - 64];
            System.arraycopy(seed, 64, seed2, 0, seed.length - 64);
            this.impl.update(seed1);
            this.impl.update(seed2);
        }
        else {
            this.impl.update(seed);
        }
    }

    public Pair<Integer, Exception> Write(byte[] src) {
        try {
            this.impl.update(src);
            return new Pair<>(src.length, null);
        }
        catch (Exception E) {
            return new Pair<>(0, E);
        }
    }

    public Pair<Integer, Exception> Read(byte[] dst) {
        try {
            dst = this.impl.digest();
            return new Pair<>(dst.length, null);
        }
        catch (Exception E) {
            return new Pair<>(0, E);
        }
    }

    @Override
    public void Reseed() {
        this.key = new byte[128];
        this.Read(this.key);
        Blake2xb y = new Blake2xb(this.key);
        this.impl = y.impl;
    }

    @Override
    public XOF Clone() {
        Blake2xb cl = new Blake2xb();
        cl.impl = this.impl.copy();
        cl.key = this.key;
        return cl;
    }
}
