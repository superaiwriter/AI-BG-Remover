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

    it('should reject NaN, non-finite size and invalid mime types', () => {
      expect(validateImageProperties(NaN, 'image/png')).toBe(false);
      expect(validateImageProperties(Infinity, 'image/png')).toBe(false);
      // @ts-ignore
      expect(validateImageProperties(1024, null)).toBe(false);
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

    it('should reject filenames containing null bytes', () => {
      expect(validateSafeFilename('image\0.png')).toBe(false);
      expect(validateSafeFilename('image\u0000.png')).toBe(false);
    });

    it('should reject filenames without or with dangerous extensions', () => {
      expect(validateSafeFilename('profile')).toBe(false);
      expect(validateSafeFilename('profile.exe')).toBe(false);
      expect(validateSafeFilename('profile.png.sh')).toBe(false);
      expect(validateSafeFilename('.png')).toBe(false); // No base name
    });

    it('should allow safe extensions in different casings', () => {
      expect(validateSafeFilename('profile.PNG')).toBe(true);
      expect(validateSafeFilename('profile.Jpeg')).toBe(true);
      expect(validateSafeFilename('profile.WebP')).toBe(true);
    });

    it('should reject filenames with dangerous double extensions', () => {
      expect(validateSafeFilename('image.php.png')).toBe(false);
      expect(validateSafeFilename('avatar.EXE.jpg')).toBe(false);
      expect(validateSafeFilename('script.sh.webp')).toBe(false);
      expect(validateSafeFilename('document.aspx.jpeg')).toBe(false);
    });

    it('should reject filenames with unsafe characters, NTFS streams, or shell injection operators', () => {
      expect(validateSafeFilename('image:stream.png')).toBe(false);
      expect(validateSafeFilename('file*.png')).toBe(false);
      expect(validateSafeFilename('file?.png')).toBe(false);
      expect(validateSafeFilename('file"name.png')).toBe(false);
      expect(validateSafeFilename('file<name.png')).toBe(false);
      expect(validateSafeFilename('file>name.png')).toBe(false);
      expect(validateSafeFilename('file|name.png')).toBe(false);
      expect(validateSafeFilename('image;id.png')).toBe(false);
      expect(validateSafeFilename('image&whoami.png')).toBe(false);
      expect(validateSafeFilename('image$VAR.png')).toBe(false);
      expect(validateSafeFilename('image\r\n.png')).toBe(false);
    });

    it('should reject percent-encoded or Unicode-normalized path traversal attempts', () => {
      expect(validateSafeFilename('%2e%2e%2fetc%2fpasswd')).toBe(false);
      expect(validateSafeFilename('%252e%252e%252fimage.png')).toBe(false);
      expect(validateSafeFilename('image%00.png')).toBe(false);
      expect(validateSafeFilename('invalid%E0%A4.png')).toBe(false); // Malformed percent-encoding
      expect(validateSafeFilename('..%2fimage.png')).toBe(false);
      expect(validateSafeFilename('..%5cwin.ini')).toBe(false);
      expect(validateSafeFilename('\uFF0E\uFF0E/etc/passwd')).toBe(false); // Full-width dots
      expect(validateSafeFilename('folder\uFF0Fimage.png')).toBe(false); // Full-width solidus (slash)
    });
  });
});
