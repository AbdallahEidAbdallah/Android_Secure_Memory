package com.example.fuzzme_v3;

import android.content.Context;
import android.graphics.Canvas;
import android.graphics.Paint;
import android.util.AttributeSet;
import android.view.View;

import java.security.SecureRandom;
import java.util.Arrays;


// Custom View for securely displaying sensitive text (like a flag)
// Never converts sensitive data to String to prevent memory exposure
public class SecureTextView extends View {
    // Tag for logging
    private static final String TAG = "SecureTextView";
    // Secure random generator for wiping sensitive data
    private static final SecureRandom secureRandom = new SecureRandom();

    // Paint for drawing actual text
    private final Paint textPaint;
    // Paint for drawing masked dots (•••)
    private final Paint maskPaint;
    // Buffer storing sensitive characters - NEVER convert to String!
    private char[] flagBuffer = null;
    // Length of valid data in buffer
    private int flagLength = 0;
    // Controls whether to show real flag or masked dots
    private boolean showFlag = false;

    // For drawing calculations
    private float charWidth = 0;    // Width of a single character
    private float textHeight = 0;   // Height of text for vertical centering
    private float padding = 16f;    // Padding from edges of view

    // Constructor for programmatic creation
    public SecureTextView(Context context) {
        this(context, null);
    }

    // Constructor for XML inflation
    public SecureTextView(Context context, AttributeSet attrs) {
        this(context, attrs, 0);
    }

    // Main constructor that all others delegate to
    public SecureTextView(Context context, AttributeSet attrs, int defStyleAttr) {
        super(context, attrs, defStyleAttr);

        // Setup paint for actual flag text
        textPaint = new Paint(Paint.ANTI_ALIAS_FLAG);
        textPaint.setColor(0xFF000000);  // Black color
        textPaint.setTextSize(36f);      // Text size in pixels
        textPaint.setTextAlign(Paint.Align.LEFT);  // Left alignment for drawing

        // Setup paint for masked dots (same appearance but used for • characters)
        maskPaint = new Paint(Paint.ANTI_ALIAS_FLAG);
        maskPaint.setColor(0xFF000000);
        maskPaint.setTextSize(36f);
        maskPaint.setTextAlign(Paint.Align.LEFT);

        // Calculate character dimensions for layout
        // Use 'W' as it's typically the widest character in Latin alphabet
        charWidth = textPaint.measureText("W");
        // Get font metrics for vertical positioning
        Paint.FontMetrics fm = textPaint.getFontMetrics();
        // Calculate total text height (ascent to descent)
        textHeight = fm.descent - fm.ascent;

        // Disable Android's view state saving/restoring
        // This prevents sensitive data from being saved in bundle
        setSaveEnabled(false);
        // Disable drawing cache to avoid sensitive data in bitmaps
        setWillNotCacheDrawing(true);
    }

    /**
     * Set flag securely - stores as char[], never converts to String
     *
     * @param buffer Character array containing sensitive data
     * @param length Number of valid characters in buffer
     */
    public void setSecureFlag(char[] buffer, int length) {
        // Clear any previous flag data first
        clearSecureFlag();

        // Handle null or empty input
        if (buffer == null || length <= 0) {
            flagBuffer = null;
            flagLength = 0;
            showFlag = false;
            invalidate();
            return;
        }

        // Copy to internal buffer (don't store reference to external array)
        flagBuffer = new char[length];
        System.arraycopy(buffer, 0, flagBuffer, 0, length);
        flagLength = length;
        showFlag = true;

        // Trigger redraw to display the new flag
        invalidate();
    }

    /**
     * Show or hide the flag (toggle between real text and masked dots)
     *
     * @param show true to show real flag, false to show dots
     */
    public void setShowFlag(boolean show) {
        this.showFlag = show;
        invalidate();  // Request redraw with new visibility state
    }

    /**
     * Securely wipe the flag buffer to prevent memory extraction
     * Uses multiple passes with random data followed by zeroing
     */
    public void clearSecureFlag() {
        if (flagBuffer != null) {
            // Multi-pass secure wipe to prevent data recovery

            // Create random bytes array (2 bytes per char since char = 16-bit)
            byte[] randomBytes = new byte[flagBuffer.length * 2];

            // Pass 1: Overwrite with random data
            secureRandom.nextBytes(randomBytes);
            for (int i = 0; i < flagBuffer.length; i++) {
                int byteIdx = i * 2;
                // Combine two bytes into a char
                flagBuffer[i] = (char) ((randomBytes[byteIdx] << 8) |
                        (randomBytes[byteIdx + 1] & 0xFF));
            }

            // Pass 2: Overwrite with more random data
            secureRandom.nextBytes(randomBytes);
            for (int i = 0; i < flagBuffer.length; i++) {
                int byteIdx = i * 2;
                flagBuffer[i] = (char) ((randomBytes[byteIdx] << 8) |
                        (randomBytes[byteIdx + 1] & 0xFF));
            }

            // Final zero pass: Overwrite with all zeros
            Arrays.fill(flagBuffer, '\0');
            // Also zero the random bytes array
            Arrays.fill(randomBytes, (byte) 0);

            // Clear references
            flagBuffer = null;
            flagLength = 0;
            showFlag = false;
        }

        // Request redraw (will show empty/masked view)
        invalidate();
    }

    /**
     * Main drawing method called by Android framework
     */
    @Override
    protected void onDraw(Canvas canvas) {
        super.onDraw(canvas);

        // If no flag is set, draw default masked dots
        if (flagBuffer == null || flagLength == 0) {
            drawMasked(canvas, 25); // Draw 25 dots if no flag
            return;
        }

        // Draw either real flag or masked dots based on showFlag
        if (showFlag) {
            drawRealFlag(canvas);
        } else {
            drawMasked(canvas, flagLength);
        }
    }

    /**
     * Draw real flag characters one by one - AVOIDS STRING CREATION!
     * Uses single-char arrays to prevent String interning/leaking
     */
    private void drawRealFlag(Canvas canvas) {
        // Calculate total width needed for the flag
        float totalWidth = charWidth * flagLength;
        float availableWidth = getWidth() - (2 * padding);

        // Calculate scale factor if text is too wide for view
        float scale = 1.0f;
        if (totalWidth > availableWidth) {
            scale = availableWidth / totalWidth;
        }

        // Calculate starting X position (centered horizontally with padding)
        float startX = padding;
        // Calculate Y position for vertical centering
        float startY = (getHeight() + textHeight) / 2 - textPaint.getFontMetrics().descent;

        // Draw each character individually to avoid creating Strings
        for (int i = 0; i < flagLength; i++) {
            // Create a single-char array for drawing (minimal memory footprint)
            char[] singleChar = {flagBuffer[i]};

            // Calculate X position for this character (with scaling if needed)
            float x = startX + (i * charWidth * scale);

            // Apply horizontal scaling if text is too wide
            if (scale < 1.0f) {
                canvas.save();  // Save current canvas state
                // Scale only horizontally, centered at character position
                canvas.scale(scale, 1.0f, x, startY);
            }

            // Draw the single character
            // Parameters: char array, start index, count, x, y, paint
            canvas.drawText(singleChar, 0, 1, x, startY, textPaint);

            // Restore canvas if we scaled it
            if (scale < 1.0f) {
                canvas.restore();
            }

            // Immediately clear the single-char array for security
            singleChar[0] = '\0';
        }
    }

    /**
     * Draw masked dots (•) instead of real characters
     *
     * @param dotCount Number of dots to draw (usually matches flag length)
     */
    private void drawMasked(Canvas canvas, int dotCount) {
        // Calculate total width needed for all dots
        float totalWidth = charWidth * dotCount;
        float availableWidth = getWidth() - (2 * padding);

        // Calculate scale if dots are too wide
        float scale = 1.0f;
        if (totalWidth > availableWidth) {
            scale = availableWidth / totalWidth;
        }

        // Calculate starting positions (same as real flag for consistent layout)
        float startX = padding;
        float startY = (getHeight() + textHeight) / 2 - maskPaint.getFontMetrics().descent;

        // Draw each dot
        for (int i = 0; i < dotCount; i++) {
            float x = startX + (i * charWidth * scale);

            // Apply scaling if needed
            if (scale < 1.0f) {
                canvas.save();
                canvas.scale(scale, 1.0f, x, startY);
            }

            // Draw bullet character (•) - safe to use String here as it's not sensitive
            canvas.drawText("•", x, startY, maskPaint);

            if (scale < 1.0f) {
                canvas.restore();
            }
        }
    }

    /**
     * Called when view is removed from window
     * Ensures sensitive data is cleaned up
     */
    @Override
    protected void onDetachedFromWindow() {
        super.onDetachedFromWindow();
        // Securely wipe all sensitive data when view is no longer displayed
        clearSecureFlag();
    }
}