package ch.epfl.dedis.kyber.proof;

import ch.epfl.dedis.kyber.Suite;
import ch.epfl.dedis.kyber.XOF;

import java.nio.charset.StandardCharsets;

// Hash-based noninteractive Sigma-protocol prover context
public class HashProver {
    public Suite suite;
    public byte[] proof, msg;
    public XOF pubrand;

    public HashProver(Suite suite, String protoName) {
        this.suite = suite;
        this.pubrand = suite.XOF(protoName.getBytes(StandardCharsets.UTF_8));
    }
}
