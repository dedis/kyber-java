package ch.epfl.dedis.kyber.utils;

import org.apache.commons.lang3.ArrayUtils;

import java.math.BigInteger;

/**
 * This utility class has been taken from https://github.com/cryptography-cafe/curve25519-elisabeth
 */
public class Utils {
    /**
     * Converts a hex string to bytes. The string may contain whitespace for
     * readability.
     *
     * @param s the hex string to be converted.
     * @return the byte[]
     */
    public static byte[] hexToBytes(String s) {
        // Strip any internal whitespace
        s = s.replaceAll(" ", "");

        // Now parse as hex
        int len = s.length();
        if (len % 2 != 0) {
            throw new IllegalArgumentException("Hex string must have an even length");
        }
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4) + Character.digit(s.charAt(i + 1), 16));
        }
        return data;
    }

    public static byte[] bigIntToLittleEndianBytes(BigInteger I) {
        byte[] data = I.toByteArray();
        ArrayUtils.reverse(data);
        return data;
    }
}