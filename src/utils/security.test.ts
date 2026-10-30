import { describe, it, expect } from 'vitest';
import { validateImageProperties, validateSafeFilename } from './security.js';

describe('Sentinel Security Input Validation', () => {
  describe('validateImageProperties', () => {
    it('should allow valid image formats within size limit', () => {
      expect(validateImageProperties(1024 * 1024, 'image/png')).toBe(true);
      expect(validateImageProperties(5 * 1024 * 1024, 'image/jpeg')).toBe(true);
      expect(validateImageProperties(9.9 * 1024 * 1024, 'image/webp')).toBe(
        true,
      );
      expect(validateImageProperties(1024 * 1024, ' IMAGE/PNG ')).toBe(true);
    });

    it('should reject non-finite size or invalid mimeType inputs', () => {
      expect(validateImageProperties(NaN, 'image/png')).toBe(false);
      expect(validateImageProperties(Infinity, 'image/png')).toBe(false);
      // @ts-ignore
      expect(validateImageProperties(1024, null)).toBe(false);
    });

    it('should reject files exceeding the 10MB limit', () => {
      expect(validateImageProperties(11 * 1024 * 1024, 'image/png')).toBe(
        false,
      );
    });

    it('should reject files with negative or zero size', () => {
      expect(validateImageProperties(0, 'image/png')).toBe(false);
      expect(validateImageProperties(-100, 'image/png')).toBe(false);
    });

    it('should reject unsupported/malicious MIME types', () => {
      expect(validateImageProperties(1024, 'application/javascript')).toBe(
        false,
      );
      expect(validateImageProperties(1024, 'image/svg+xml')).toBe(false);
      expect(validateImageProperties(1024, 'text/html')).toBe(false);
    });
  });

  describe('validateSafeFilename', () => {
    it('should allow safe, simple filenames', () => {
      expect(validateSafeFilename('profile.png')).toBe(true);
      expect(validateSafeFilename('background-123.jpg')).toBe(true);
    });

    it('should reject filenames containing path traversal characters', () => {
      expect(validateSafeFilename('../etc/passwd')).toBe(false);
      expect(validateSafeFilename('subfolder/image.png')).toBe(false);
      expect(validateSafeFilename('..\\win.ini')).toBe(false);
    });

    it('should reject invalid or empty input types', () => {
      expect(validateSafeFilename('')).toBe(false);
      // @ts-ignore
      expect(validateSafeFilename(null)).toBe(false);
    });

    it('should reject overly long filenames', () => {
      const longName = 'a'.repeat(256) + '.png';
      expect(validateSafeFilename(longName)).toBe(false);
    });
  });
});
