package com.example.fuzzme_v3;

import androidx.appcompat.app.AppCompatActivity;

import android.content.Intent;
import android.os.Bundle;
import android.util.Log;
import android.widget.Button;
import android.widget.Toast;

import com.example.fuzzme_v3.SecureEditText;

import java.security.SecureRandom;
import java.util.Arrays;

// Main login activity with secure credential handling
// Uses custom SecureEditText to prevent sensitive data exposure
public class MainActivity extends AppCompatActivity {

    // Custom secure text input fields - store data as char[] not String
    private SecureEditText secureUsername, securePassword;
    // UI buttons
    private Button btnLogin, btnClear;
    // Secure random generator for wiping sensitive arrays
    private final SecureRandom secureRandom = new SecureRandom();

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        // Inflate the layout from XML
        setContentView(R.layout.activity_main);

        // Initialize UI components by finding them in the layout
        secureUsername = findViewById(R.id.etUser);
        securePassword = findViewById(R.id.etPassword);
        btnLogin = findViewById(R.id.btnLogin);
        btnClear = findViewById(R.id.btnClear);

        // Set hints (non-sensitive text, so using String is safe)
        secureUsername.setHint("Username");
        securePassword.setHint("Password");

        // Set up click listeners for buttons
        btnLogin.setOnClickListener(v -> doLogin());   // Login button
        btnClear.setOnClickListener(v -> clearAll());  // Clear button
    }

    /**
     * Performs secure login with credential validation
     * Uses direct buffer access to avoid copying sensitive data
     */
    private void doLogin() {
        // Step 1: Get buffer lengths first (without exposing actual data)
        int userLen = secureUsername.getBufferLength();
        int passLen = securePassword.getBufferLength();

        // Validate that both fields have content
        if (userLen == 0 || passLen == 0) {
            showToast("Please enter both fields");
            return; // Exit early if fields are empty
        }

        // Step 2: Get direct buffer references - CRITICAL FOR SECURITY
        // These are direct references to the internal char[] buffers, NOT copies
        // This avoids creating additional copies of sensitive data
        char[] userBuffer = secureUsername.getSecureBufferDirect();
        char[] passBuffer = securePassword.getSecureBufferDirect();

        // Step 3: Call native code for credential validation
        // NativeBridge receives the actual buffers (no copying on Java side)
        boolean ok = NativeBridge.checkCredentials(
                userBuffer, passBuffer,    // Direct buffer references
                userLen, passLen           // Actual data lengths
        );

        // Step 4: SECURE WIPING of the original buffers
        // Wipe immediately after native call to minimize exposure time
        secureWipeArray(userBuffer, userLen);  // Wipe username buffer
        secureWipeArray(passBuffer, passLen);  // Wipe password buffer

        // Step 5: Clear the secure buffers in the views as well
        // This ensures the UI components don't retain the data
        secureUsername.clearSecureBuffer();
        securePassword.clearSecureBuffer();

        // Step 6: Handle login result
        if (ok) {
            showToast("Login Successful!");
            // Navigate to secret activity on successful login
            startActivity(new Intent(this, SecretActivity.class));
        } else {
            showToast("Invalid credentials");
        }
    }

    /**
     * Securely wipes a character array by overwriting with random data then zeros
     *
     * @param array  The character array to wipe
     * @param length Number of characters to wipe (may be less than array length)
     */
    private void secureWipeArray(char[] array, int length) {
        // Safety checks
        if (array == null || length <= 0) return;

        // Log for debugging (shows length but not content)
        Log.d("SECURE_WIPE", "Wiping array of length: " + length);

        // Create random bytes array (2 bytes per char since char is 16-bit)
        byte[] randomBytes = new byte[length * 2];
        // Fill with cryptographically secure random data
        secureRandom.nextBytes(randomBytes);

        // Overwrite each character with random data
        // Only wipe 'length' characters (not entire array if it's larger)
        for (int i = 0; i < length; i++) {
            int byteIdx = i * 2;
            // Combine two random bytes into a character
            array[i] = (char) ((randomBytes[byteIdx] << 8) |
                    (randomBytes[byteIdx + 1] & 0xFF));
        }

        // Final zero pass: overwrite with all zeros
        // Using the length parameter to only wipe the used portion
        Arrays.fill(array, 0, length, '\0');

        // Also wipe the random bytes array (defense in depth)
        Arrays.fill(randomBytes, (byte) 0);

        // Note: The array reference still exists, but its contents are now zeros
        // The actual memory might still contain data until garbage collected/overwritten
    }

    /**
     * Clears all input fields (user-initiated)
     */
    private void clearAll() {
        // Clear both username and password fields
        secureUsername.clearSecureBuffer();
        securePassword.clearSecureBuffer();
        showToast("All inputs cleared");
    }

    /**
     * Helper method to show toast messages
     *
     * @param message The message to display (non-sensitive)
     */
    private void showToast(CharSequence message) {
        Toast.makeText(this, message, Toast.LENGTH_SHORT).show();
    }

    /**
     * Called when activity loses foreground focus
     * Additional security measure to clear buffers when app goes to background
     */
    @Override
    protected void onPause() {
        super.onPause();
        // Only clear if activity is finishing (being destroyed)
        // This prevents clearing during configuration changes like rotation
        if (isFinishing()) {
            secureUsername.clearSecureBuffer();
            securePassword.clearSecureBuffer();
            Log.d("MEM_SEC", "Buffers cleared on pause");
        }
    }
}