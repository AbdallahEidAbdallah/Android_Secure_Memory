package com.example.fuzzme_v3;

import android.content.Context;
import android.content.res.TypedArray;
import android.text.Editable;
import android.text.TextWatcher;
import android.util.AttributeSet;
import android.util.Log;
import android.widget.EditText;
import android.widget.ImageButton;
import android.widget.LinearLayout;

import com.example.fuzzme_v3.R;

import java.security.SecureRandom;
import java.util.Arrays;

// Custom secure text input component
// Stores sensitive data as char[] instead of String to prevent memory exposure
// Provides show/hide toggle functionality while maintaining security
public class SecureEditText extends LinearLayout {
    // Tag for logging (doesn't contain sensitive data)
    private static final String TAG = "SecureEditText";
    // Secure random generator for wiping sensitive arrays
    private static final SecureRandom secureRandom = new SecureRandom();

    // UI components
    private EditText editText;           // Actual text input field
    private ImageButton toggleButton;    // Show/hide toggle button (optional)

    // Secure buffer - stores actual characters as char[], NEVER as String
    private final char[] secureBuffer;
    private int bufferLength = 0;        // Actual number of characters stored

    // Configuration and state
    private boolean showToggleButton = false;  // Whether to show toggle button
    private boolean isPasswordVisible = false; // Whether password is currently visible
    private boolean isUpdating = false;        // Flag to prevent update loops

    // Temporary display cache - used when password is visible
    // Separate from secureBuffer to avoid exposing original during display
    private char[] displayCache = null;

    // Constructors (standard pattern for custom views)
    public SecureEditText(Context context) {
        this(context, null);
    }

    public SecureEditText(Context context, AttributeSet attrs) {
        this(context, attrs, 0);
    }

    // Main constructor called by all others
    public SecureEditText(Context context, AttributeSet attrs, int defStyleAttr) {
        super(context, attrs, defStyleAttr);

        // Set LinearLayout orientation to horizontal (edit text + toggle button)
        setOrientation(HORIZONTAL);

        // Parse custom attributes from XML
        TypedArray a = context.obtainStyledAttributes(attrs, R.styleable.SecureEditText);
        int maxLength = a.getInt(R.styleable.SecureEditText_maxBufferLength, 128);
        showToggleButton = a.getBoolean(R.styleable.SecureEditText_showToggleButton, false);
        a.recycle();  // Always recycle TypedArray when done

        // Initialize secure buffer with maximum capacity
        secureBuffer = new char[maxLength];
        // Initialize display cache (same size for temporary display)
        displayCache = new char[maxLength];

        // Initialize UI components
        initEditText(context);
        if (showToggleButton) {
            initToggleButton(context);
        }

        // Set up text change listener to capture input
        setupTextWatcher();
    }

    /**
     * Initializes the EditText component with secure settings
     */
    private void initEditText(Context context) {
        editText = new EditText(context);
        // Layout params: weight=1 to fill available space
        LayoutParams params = new LayoutParams(0, LayoutParams.WRAP_CONTENT, 1);
        editText.setLayoutParams(params);

        // Disable text persistence features to prevent data leaks
        editText.setSaveEnabled(false);     // Don't save text in bundle
        editText.setFreezesText(false);     // Don't save text in onSaveInstanceState

        // Set empty text initially
        editText.setText("");

        // Configure as password field by default
        editText.setInputType(android.text.InputType.TYPE_CLASS_TEXT |
                android.text.InputType.TYPE_TEXT_VARIATION_PASSWORD);

        addView(editText);
    }

    /**
     * Initializes the toggle button (show/hide eye icon)
     */
    private void initToggleButton(Context context) {
        toggleButton = new ImageButton(context);
        LayoutParams params = new LayoutParams(
                LayoutParams.WRAP_CONTENT, LayoutParams.WRAP_CONTENT);
        params.setMargins(8, 0, 0, 0);  // Add some spacing
        toggleButton.setLayoutParams(params);
        toggleButton.setBackground(null);  // Remove default button background

        // Set initial icon based on visibility state
        updateToggleIcon();

        // Set click listener to toggle visibility
        toggleButton.setOnClickListener(v -> {
            toggleVisibility();
        });

        addView(toggleButton);
    }

    /**
     * Sets up TextWatcher to capture user input securely
     * Converts EditText's String input to char[] storage
     */
    private void setupTextWatcher() {
        editText.addTextChangedListener(new TextWatcher() {
            @Override
            public void beforeTextChanged(CharSequence s, int start, int count, int after) {
                // Not used
            }

            @Override
            public void onTextChanged(CharSequence s, int start, int before, int count) {
                // Prevent infinite loops (when we programmatically update text)
                if (isUpdating) return;

                // Get current text from EditText (as String, but we'll convert)
                String current = s.toString();
                int newLength = current.length();

                // Handle text changes
                if (newLength > bufferLength) {
                    // Character added (inserted or appended)
                    char newChar = current.charAt(newLength - 1);
                    if (bufferLength < secureBuffer.length) {
                        // Store in secure buffer
                        secureBuffer[bufferLength++] = newChar;
                    }
                } else if (newLength < bufferLength) {
                    // Character deleted
                    bufferLength = newLength;
                    // Note: We don't shift array, just reduce length
                    // Old characters remain but are outside the "valid" length
                }
                // If lengths are equal, text was modified in place

                // Update display (show dots or actual text)
                updateDisplay();
            }

            @Override
            public void afterTextChanged(Editable s) {
                // Not used
            }
        });
    }

    /**
     * Toggles between showing password as dots or actual characters
     */
    private void toggleVisibility() {
        // Toggle visibility state
        isPasswordVisible = !isPasswordVisible;

        // Update input type (affects keyboard suggestions and appearance)
        if (isPasswordVisible) {
            // Show actual text - disable suggestions to prevent learning
            editText.setInputType(android.text.InputType.TYPE_CLASS_TEXT |
                    android.text.InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS);

            // Copy to display cache (temporary, separate from secure buffer)
            updateDisplayCache();
        } else {
            // Show dots (password mode)
            editText.setInputType(android.text.InputType.TYPE_CLASS_TEXT |
                    android.text.InputType.TYPE_TEXT_VARIATION_PASSWORD);

            // Clear display cache when hiding
            Arrays.fill(displayCache, 0, bufferLength, '\0');
        }

        // Update toggle button icon
        updateToggleIcon();

        // Refresh display with new visibility setting
        updateDisplay();
    }

    /**
     * Copies secure buffer to display cache for temporary visible display
     */
    private void updateDisplayCache() {
        if (bufferLength == 0) return;

        // Copy to display cache (temporary storage for visible display)
        System.arraycopy(secureBuffer, 0, displayCache, 0, bufferLength);
        // Display cache is wiped after use in showSecureText()
    }

    /**
     * Updates toggle button icon based on current visibility state
     */
    private void updateToggleIcon() {
        if (toggleButton != null) {
            if (isPasswordVisible) {
                // Show "hide" icon when password is visible
                toggleButton.setImageResource(R.drawable.ic_visibility_off);
            } else {
                // Show "show" icon when password is hidden
                toggleButton.setImageResource(R.drawable.ic_visibility);
            }
        }
    }

    /**
     * Updates the display based on current visibility state
     */
    private void updateDisplay() {
        if (isUpdating) return;

        // Set flag to prevent update loops
        isUpdating = true;

        if (isPasswordVisible) {
            // SHOW ACTUAL TEXT - using secure methods
            showSecureText();
        } else {
            // Show dots - this is safe as dots aren't sensitive
            char[] dots = new char[bufferLength];
            Arrays.fill(dots, '•');  // Bullet character
            editText.setText(new String(dots));  // Safe to create String here
            editText.setSelection(bufferLength);  // Move cursor to end

            // Wipe temporary dots array (defense in depth)
            Arrays.fill(dots, '\0');
        }

        isUpdating = false;
    }

    /**
     * Shows actual text without creating permanent Strings
     * Uses display cache (temporary copy) instead of secure buffer
     */
    private void showSecureText() {
        if (bufferLength == 0) {
            editText.setText("");
            return;
        }

        // Method 1: Build string character by character
        // This creates a String but we try to minimize exposure
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < bufferLength; i++) {
            // Use display cache, not secureBuffer directly
            sb.append(displayCache[i]);
        }

        // Set the text (creates String internally in EditText)
        editText.setText(sb.toString());
        editText.setSelection(bufferLength);

        // Try to wipe StringBuilder contents (not perfect but helpful)
        for (int i = 0; i < sb.length(); i++) {
            sb.setCharAt(i, '0');
        }

        // SECURITY: Clear display cache immediately after showing
        Arrays.fill(displayCache, 0, bufferLength, '\0');
        // Note: The String in EditText may remain in memory until cleared
    }

    // ========== PUBLIC API ==========

    /**
     * Returns a COPY of the secure buffer
     * Caller is responsible for wiping the returned array
     */
    public char[] getSecureBufferCopy() {
        char[] copy = new char[bufferLength];
        System.arraycopy(secureBuffer, 0, copy, 0, bufferLength);
        return copy;
    }

    /**
     * Returns DIRECT REFERENCE to the secure buffer
     * WARNING: Caller must NOT modify this array directly
     * Used for native calls that need direct buffer access
     */
    public char[] getSecureBufferDirect() {
        return secureBuffer;
    }

    /**
     * Returns current number of characters in buffer
     */
    public int getBufferLength() {
        return bufferLength;
    }

    /**
     * Securely clears ALL buffers (main security feature)
     * Overwrites with random data then zeros
     */
    public void clearSecureBuffer() {
        if (bufferLength == 0) return;

        Log.d(TAG, "Clearing secure buffer, length: " + bufferLength);

        // Generate random bytes for overwriting
        byte[] randomBytes = new byte[bufferLength * 2];
        secureRandom.nextBytes(randomBytes);

        // Overwrite secure buffer with random data
        for (int i = 0; i < bufferLength; i++) {
            int byteIdx = i * 2;
            secureBuffer[i] = (char) ((randomBytes[byteIdx] << 8) |
                    (randomBytes[byteIdx + 1] & 0xFF));
        }
        // Final zero pass
        Arrays.fill(secureBuffer, 0, bufferLength, '\0');

        // Wipe display cache
        Arrays.fill(displayCache, 0, bufferLength, '\0');

        // Clear random bytes array
        Arrays.fill(randomBytes, (byte) 0);

        // Reset state
        bufferLength = 0;
        isPasswordVisible = false;  // Force back to hidden state
        editText.setText("");

        // Update toggle icon
        updateToggleIcon();
    }

    /**
     * Sets hint text (non-sensitive, safe to use String)
     */
    public void setHint(CharSequence hint) {
        editText.setHint(hint);
    }

    /**
     * Shows or hides the toggle button dynamically
     */
    public void setShowToggleButton(boolean show) {
        if (this.showToggleButton != show) {
            this.showToggleButton = show;

            if (show && toggleButton == null) {
                // Add toggle button if showing
                initToggleButton(getContext());
            } else if (!show && toggleButton != null) {
                // Remove toggle button if hiding
                removeView(toggleButton);
                toggleButton = null;
            }
        }
    }

    /**
     * Called when view is removed from window
     * Ensures secure cleanup
     */
    @Override
    protected void onDetachedFromWindow() {
        super.onDetachedFromWindow();
        clearSecureBuffer();  // Always clear when view is detached
    }
}
