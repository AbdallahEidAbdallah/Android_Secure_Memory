
#include <jni.h>
#include <cstring>
#include <cstdlib>
#include <unistd.h>
#include <sys/mman.h>

// ========== SECURE UTILITY FUNCTIONS ==========

/**
 * Securely zeroes memory to prevent data recovery
 * Uses volatile to prevent compiler optimization
 * @param ptr Pointer to memory to zero
 * @param len Number of bytes to zero
 */
static void secure_memzero(void *ptr, size_t len) {
    if (!ptr || len == 0) return;

    // Use volatile pointer to prevent compiler from optimizing away the writes
    volatile unsigned char *p = (volatile unsigned char *) ptr;

    // Write zeros to each byte
    while (len--) *p++ = 0;

    // Memory barrier: ensures writes complete before continuing
    // Prevents reordering and ensures zeros are actually written
    __asm__ __volatile__("" : : "r"(ptr) : "memory");
}

// ========== CREDENTIAL STORAGE ==========

// Encrypted credentials stored in memory (XOR encryption for simplicity)
// XOR with 0x5A transforms "admin" (ASCII) to these bytes
// In production, use proper encryption like AES-256
static const unsigned char ENC_USER[] = {0x3B, 0x3E, 0x37, 0x33, 0x34}; // "username" ^ 0x5A
static const unsigned char ENC_PASS[] = {0x3B, 0x3E, 0x37, 0x33, 0x34}; // "password" ^ 0x5A
static const unsigned char XOR_KEY = 0x5A;  // Simple XOR key

// ========== CREDENTIAL CHECKING FUNCTION ==========

/**
 * JNI function to check user credentials
 * Called from Java: NativeBridge.checkCredentials()
 * Returns JNI_TRUE if credentials match, JNI_FALSE otherwise
 *
 * SECURITY NOTES:
 * - Locks memory to prevent swapping to disk
 * - Wipes all sensitive data after use
 * - Minimizes data exposure time
 * - Handles all error cases securely
 */
extern "C" JNIEXPORT jboolean JNICALL
Java_com_example_fuzzme_1v3_NativeBridge_checkCredentials(
        JNIEnv *env, jclass clazz,
        jcharArray juser, jcharArray jpass,
        jint userLen, jint passLen) {

    // === STEP 1: LOCK MEMORY ===
    // Allocate and lock memory to prevent sensitive data from being paged to disk
    // This is a best-effort security measure
    void *locked_mem = malloc(1024);
    if (locked_mem) {
        mlock(locked_mem, 1024);  // Lock pages in RAM
    }

    // === STEP 2: GET JAVA ARRAY DATA ===
    // Get direct pointers to Java char arrays (no copying if possible)
    // NULL as second parameter: get pointer, don't make copy if possible
    jchar *userChars = env->GetCharArrayElements(juser, NULL);
    jchar *passChars = env->GetCharArrayElements(jpass, NULL);

    // Check for allocation failures
    if (!userChars || !passChars) {
        // Release arrays with JNI_ABORT: don't copy changes back
        if (userChars) env->ReleaseCharArrayElements(juser, userChars, JNI_ABORT);
        if (passChars) env->ReleaseCharArrayElements(jpass, passChars, JNI_ABORT);
        if (locked_mem) {
            secure_memzero(locked_mem, 1024);
            free(locked_mem);
        }
        return JNI_FALSE;
    }

    // === STEP 3: CONVERT jchar TO unsigned char ===
    // jchar is 16-bit (Unicode), but we need 8-bit for comparison
    // Create temporary buffers for the comparison
    unsigned char *userBytes = (unsigned char *) malloc(userLen);
    unsigned char *passBytes = (unsigned char *) malloc(passLen);

    if (!userBytes || !passBytes) {
        // Cleanup on allocation failure
        free(userBytes);
        free(passBytes);
        env->ReleaseCharArrayElements(juser, userChars, JNI_ABORT);
        env->ReleaseCharArrayElements(jpass, passChars, JNI_ABORT);
        if (locked_mem) {
            secure_memzero(locked_mem, 1024);
            free(locked_mem);
        }
        return JNI_FALSE;
    }

    // Copy and convert jchar (16-bit) to unsigned char (8-bit)
    // We only use the lower byte (assumes ASCII/Latin-1 characters)
    for (int i = 0; i < userLen; i++) userBytes[i] = (unsigned char) userChars[i];
    for (int i = 0; i < passLen; i++) passBytes[i] = (unsigned char) passChars[i];

    // === STEP 4: DECRYPT STORED CREDENTIALS ===
    // Decrypt the stored credentials for comparison
    // Using stack arrays for automatic cleanup
    unsigned char decryptedUser[sizeof(ENC_USER)];
    unsigned char decryptedPass[sizeof(ENC_PASS)];

    // Simple XOR decryption (in production, use proper authenticated encryption)
    for (size_t i = 0; i < sizeof(ENC_USER); i++) decryptedUser[i] = ENC_USER[i] ^ XOR_KEY;
    for (size_t i = 0; i < sizeof(ENC_PASS); i++) decryptedPass[i] = ENC_PASS[i] ^ XOR_KEY;

    // === STEP 5: COMPARE CREDENTIALS ===
    // Use constant-time comparison to prevent timing attacks
    bool match = false;
    if (userLen == sizeof(ENC_USER) && passLen == sizeof(ENC_PASS)) {
        // memcmp is not constant-time! In production, use constant-time comparison
        match = (memcmp(userBytes, decryptedUser, userLen) == 0) &&
                (memcmp(passBytes, decryptedPass, passLen) == 0);
    }

    // === STEP 6: SECURE CLEANUP - MOST IMPORTANT PART! ===
    // All sensitive data must be wiped before returning

    // 6a: Wipe decrypted credentials from stack
    secure_memzero(decryptedUser, sizeof(decryptedUser));
    secure_memzero(decryptedPass, sizeof(decryptedPass));

    // 6b: Wipe and free temporary buffers
    secure_memzero(userBytes, userLen);
    secure_memzero(passBytes, passLen);
    free(userBytes);
    free(passBytes);

    // 6c: Wipe and release Java arrays
    // JNI_ABORT: don't copy the zeros back to Java (we already wiped in Java)
    secure_memzero(userChars, userLen * sizeof(jchar));
    secure_memzero(passChars, passLen * sizeof(jchar));
    env->ReleaseCharArrayElements(juser, userChars, JNI_ABORT);
    env->ReleaseCharArrayElements(jpass, passChars, JNI_ABORT);

    // 6d: Wipe and free locked memory
    if (locked_mem) {
        secure_memzero(locked_mem, 1024);
        free(locked_mem);
    }

    return match ? JNI_TRUE : JNI_FALSE;
}

// ========== FLAG METHODS (SEPARATE IMPLEMENTATION) ==========

// Encrypted flag stored in memory
// XOR-encrypted with key 0x5A
// Actual encrypted bytes (in production, use proper encryption)
static const unsigned char ENC_FLAG[] = {
        0x1C, 0x16, 0x1B, 0x1D, 0x21, 0x09, 0x09, 0x09, 0x2F, 0x2A, 0x3F, 0x28, 0x05,
        0x09, 0x3F, 0x39, 0x28, 0x3F, 0x2E, 0x05, 0x1C, 0x36, 0x3B, 0x3D, 0x27
};

static const size_t FLAG_LEN = sizeof(ENC_FLAG);
static const unsigned char FLAG_KEY = 0x5A;

/**
 * Get flag length for buffer allocation in Java
 * Allows Java to allocate correct buffer size before decryption
 *
 * @return Length of the encrypted flag in bytes
 */
extern "C" JNIEXPORT jint JNICALL
Java_com_example_fuzzme_1v3_NativeBridge_getFlagLength(
        JNIEnv *env, jclass clazz) {
    // Return as jint (Java int)
    return (jint) FLAG_LEN;
}

/**
 * Decrypt flag into EXISTING Java buffer
 * Java must allocate buffer with correct size first
 * Uses minimal temporary storage and wipes immediately
 *
 * @param jbuffer Java char array to receive decrypted flag
 */
extern "C" JNIEXPORT void JNICALL
Java_com_example_fuzzme_1v3_NativeBridge_decryptFlagIntoBuffer(
        JNIEnv *env, jclass clazz, jcharArray jbuffer) {

    // Null check
    if (!jbuffer) {
        // In production, throw exception
        return;
    }

    // Get direct pointer to Java array
    jchar *buffer = env->GetCharArrayElements(jbuffer, NULL);
    if (!buffer) {
        return;
    }

    // Check buffer size
    jsize bufferSize = env->GetArrayLength(jbuffer);
    if (bufferSize < FLAG_LEN) {
        // Buffer too small - abort without copying
        env->ReleaseCharArrayElements(jbuffer, buffer, JNI_ABORT);
        return;
    }

    // === LOCK MEMORY FOR SENSITIVE OPERATION ===
    void *lockedMem = malloc(1024);
    if (lockedMem) {
        mlock(lockedMem, 1024);  // Prevent swapping
    }

    // === CREATE TEMPORARY DECRYPTION BUFFER ===
    // Decrypt into temporary buffer first, then copy to Java
    // This prevents exposing decrypted data in Java buffer if decryption fails
    char *tempDecrypt = (char *) malloc(FLAG_LEN);
    if (!tempDecrypt) {
        // Cleanup on allocation failure
        if (lockedMem) {
            munlock(lockedMem, 1024);
            free(lockedMem);
        }
        env->ReleaseCharArrayElements(jbuffer, buffer, JNI_ABORT);
        return;
    }

    // === PERFORM DECRYPTION ===
    // XOR decryption (simple example - use proper encryption in production)
    for (size_t i = 0; i < FLAG_LEN; i++) {
        tempDecrypt[i] = ENC_FLAG[i] ^ FLAG_KEY;
    }

    // === COPY TO JAVA BUFFER ===
    // Convert char to jchar (8-bit to 16-bit)
    for (size_t i = 0; i < FLAG_LEN; i++) {
        buffer[i] = (jchar) tempDecrypt[i];
    }

    // === CRITICAL: IMMEDIATELY WIPE TEMPORARY BUFFER ===
    // The decrypted flag should exist in memory for minimal time
    secure_memzero(tempDecrypt, FLAG_LEN);
    free(tempDecrypt);

    // === CLEANUP LOCKED MEMORY ===
    if (lockedMem) {
        secure_memzero(lockedMem, 1024);
        munlock(lockedMem, 1024);  // Unlock before freeing
        free(lockedMem);
    }

    // === RELEASE JAVA ARRAY ===
    // Mode 0: copy changes back to Java
    // The decrypted flag is now in the Java buffer
    env->ReleaseCharArrayElements(jbuffer, buffer, 0);
}

/**
 * SECURE WIPE - Java calls this to wipe flag buffer using native secure wipe
 * Provides stronger wiping than Java's Arrays.fill()
 *
 * @param jbuffer Java char array to wipe
 */
extern "C" JNIEXPORT void JNICALL
Java_com_example_fuzzme_1v3_NativeBridge_wipeFlagBuffer(
        JNIEnv *env, jclass clazz, jcharArray jbuffer) {

    if (!jbuffer) return;

    // Get direct pointer to Java array
    jchar *buffer = env->GetCharArrayElements(jbuffer, NULL);
    if (!buffer) return;

    // Get array length
    jsize length = env->GetArrayLength(jbuffer);

    // Secure wipe using native implementation
    // More reliable than Java for preventing compiler optimization
    secure_memzero(buffer, length * sizeof(jchar));

    // Release with JNI_ABORT: don't copy zeros back to Java
    // Java already wiped its copy, we just wiped the native copy
    env->ReleaseCharArrayElements(jbuffer, buffer, JNI_ABORT);
}