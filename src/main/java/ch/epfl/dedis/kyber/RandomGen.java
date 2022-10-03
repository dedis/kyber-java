package ch.epfl.dedis.kyber;

import java.security.SecureRandom;

public interface RandomGen {
    // RandomStream returns a SecureRandom that produces a
    // cryptographically random key stream. The stream must
    // tolerate being used in multiple functionalities.
    public SecureRandom RandomStream();
}
