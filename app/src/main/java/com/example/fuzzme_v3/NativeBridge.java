package com.example.fuzzme_v3;

public class NativeBridge {
    static {
        System.loadLibrary("fuzzme_v3");
    }

    // Note: we pass char[] to native (no Strings)
    public static native boolean checkCredentials(char[] user, char[] pass, int realUlen, int realPlen);


    // Flag methods
    public static native void decryptFlagIntoBuffer(char[] buffer);

    // Get flag length for buffer allocation
    public static native int getFlagLength();

    // Secure wipe
    public static native void wipeFlagBuffer(char[] buffer);

    // Helper method that manages buffer lifecycle
    public static char[] getAndWipeFlag() {
        int length = getFlagLength();
        if (length <= 0) return null;

        char[] buffer = new char[length];
        decryptFlagIntoBuffer(buffer);
        return buffer;
    }
}
