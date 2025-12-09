package com.example.fuzzme_v3;

import androidx.appcompat.app.AppCompatActivity;

import android.os.Bundle;
import android.os.Handler;
import android.util.Log;
import android.widget.Button;

import java.security.SecureRandom;
import java.util.Arrays;

// Activity for securely displaying a sensitive flag with automatic hiding
public class SecretActivity extends AppCompatActivity {
    // Custom view that securely displays text without creating Strings
    private SecureTextView flagView;
    // Buttons for user interaction
    private Button btnShow5Sec, btnHideFlag;

    // Handler for scheduling delayed tasks (auto-hide after 5 seconds)
    private final Handler handler = new Handler();
    // Secure random generator for wiping sensitive arrays
    private final SecureRandom secureRandom = new SecureRandom();
    // Runnable task for auto-hiding the flag
    private Runnable hideFlagTask;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        // Set the layout from XML
        setContentView(R.layout.activity_secret);

        // Initialize UI components
        flagView = findViewById(R.id.flagTextView);
        btnShow5Sec = findViewById(R.id.btnShow5Sec);
        btnHideFlag = findViewById(R.id.btnHideFlag);

        // Set up button click listeners
        setupClickListeners();
    }

    /**
     * Configures click listeners for the buttons
     */
    private void setupClickListeners() {
        // "Show for 5 seconds" button
        btnShow5Sec.setOnClickListener(v -> {
            // Show the flag immediately
            showFlag();

            // Cancel any previously scheduled hide task to avoid multiple timers
            if (hideFlagTask != null) {
                handler.removeCallbacks(hideFlagTask);
            }

            // Create new hide task and schedule it for 5 seconds from now
            hideFlagTask = this::hideFlag;
            handler.postDelayed(hideFlagTask, 5000); // 5000ms = 5 seconds
        });

        // "Hide Flag" button (immediate hide)
        btnHideFlag.setOnClickListener(v -> hideFlag());
    }

    /**
     * Retrieves and displays the flag from native code
     * Follows secure practices: uses char[], never String
     */
    private void showFlag() {
        // Logging for debugging the flag retrieval flow
        Log.d("FLAG_FLOW", "=== START: Getting flag ===");

        // Step 1: Get flag length from native code
        int flagLength = NativeBridge.getFlagLength();
        if (flagLength <= 0) {
            Log.e("FLAG_FLOW", "Invalid flag length");
            return; // Exit if flag length is invalid
        }

        // Step 2: Allocate buffer for the flag
        // Using char[] instead of String to avoid interning in String pool
        char[] flagBuffer = new char[flagLength];

        try {
            // Step 3: Decrypt flag directly into our buffer (no intermediate Strings)
            // NativeBridge.decryptFlagIntoBuffer fills the provided char array
            NativeBridge.decryptFlagIntoBuffer(flagBuffer);

            // Step 4: Pass buffer to SecureTextView for display
            flagView.setSecureFlag(flagBuffer, flagLength);
            // Make the flag visible (SecureTextView will show actual characters)
            flagView.setShowFlag(true);

        } finally {
            // CRITICAL SECURITY STEP: Always wipe the buffer, even if errors occur
            // The finally block ensures this runs regardless of success or failure

            // Step 5a: Ask native code to wipe its copy (if any)
            NativeBridge.wipeFlagBuffer(flagBuffer);

            // Step 5b: Wipe our local Java copy
            secureWipeArray(flagBuffer);

            // Note: flagBuffer is now local variable only - will be garbage collected
            // SecureTextView has its own internal copy that it manages
        }

        Log.d("FLAG_FLOW", "=== COMPLETE: Local buffer wiped ===");
    }

    /**
     * Securely wipes a character array by overwriting with random data
     * Prevents sensitive data from being recovered from memory
     *
     * @param array The character array to wipe (will be filled with zeros)
     */
    private void secureWipeArray(char[] array) {
        if (array == null) return; // Safety check

        // Create random bytes (2 bytes per char since char is 16-bit in Java)
        byte[] randomBytes = new byte[array.length * 2];
        secureRandom.nextBytes(randomBytes); // Fill with cryptographically secure random data

        // Overwrite each character with random data
        for (int i = 0; i < array.length; i++) {
            int byteIdx = i * 2;
            // Combine two random bytes into a character
            array[i] = (char) ((randomBytes[byteIdx] << 8) |
                    (randomBytes[byteIdx + 1] & 0xFF));
        }

        // Final pass: overwrite with all zeros
        Arrays.fill(array, '\0');
        // Also wipe the random bytes array
        Arrays.fill(randomBytes, (byte) 0);

        // Arrays are now wiped, but references still exist until garbage collected
    }

    /**
     * Hides the flag and cleans up resources
     */
    private void hideFlag() {
        // Step 1: Tell SecureTextView to wipe its internal buffer and show dots
        flagView.clearSecureFlag();

        // Step 2: Cancel any pending auto-hide task
        if (hideFlagTask != null) {
            handler.removeCallbacks(hideFlagTask);
            hideFlagTask = null; // Allow GC to collect the Runnable
        }

        // Step 3: Suggest garbage collection (not guaranteed, but helpful)
        // This encourages Java to clean up any leftover references to sensitive data
        System.gc();
    }

    /**
     * Called when activity loses foreground focus
     * Ensures flag is hidden when user leaves the app
     */
    @Override
    protected void onPause() {
        super.onPause();
        hideFlag(); // Always hide when activity is paused
    }

    /**
     * Called when activity is being destroyed
     * Final cleanup of sensitive data
     */
    @Override
    protected void onDestroy() {
        super.onDestroy();
        hideFlag(); // Final cleanup before destruction
    }
}