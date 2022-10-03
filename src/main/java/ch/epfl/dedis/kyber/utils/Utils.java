package ch.epfl.dedis.kyber.utils;

import org.apache.commons.lang3.ArrayUtils;

import java.math.BigInteger;

public class Utils {

    public static byte[] bigIntToLittleEndianBytes(BigInteger I) {
        byte[] data = I.toByteArray();
        ArrayUtils.reverse(data);
        return data;
    }
}