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
      expect(validateSafeFilename('file.pif.png')).toBe(false);
      expect(validateSafeFilename('file.sct.jpg')).toBe(false);
      expect(validateSafeFilename('file.cpl.webp')).toBe(false);
      expect(validateSafeFilename('file.mjs.png')).toBe(false);
      expect(validateSafeFilename('file.apk.jpeg')).toBe(false);
      expect(validateSafeFilename('file.iso.png')).toBe(false);
      expect(validateSafeFilename('file.rdp.jpg')).toBe(false);
      expect(validateSafeFilename('file.key.webp')).toBe(false);
      expect(validateSafeFilename('file.docm.png')).toBe(false);
      expect(validateSafeFilename('image.shtml.png')).toBe(false);
      expect(validateSafeFilename('image.php7.png')).toBe(false);
      expect(validateSafeFilename('image.config.png')).toBe(false);
      expect(validateSafeFilename('image.yaml.png')).toBe(false);
      expect(validateSafeFilename('payload.zip.png')).toBe(false);
      expect(validateSafeFilename('file.tar.jpg')).toBe(false);
      expect(validateSafeFilename('archive.7z.webp')).toBe(false);
      expect(validateSafeFilename('data.rar.jpeg')).toBe(false);
      expect(validateSafeFilename('archive.gz.png')).toBe(false);
      expect(validateSafeFilename('package.whl.png')).toBe(false);
      expect(validateSafeFilename('lib.nupkg.jpg')).toBe(false);
      expect(validateSafeFilename('extension.crx.webp')).toBe(false);
      expect(validateSafeFilename('addon.xpi.jpeg')).toBe(false);
      expect(validateSafeFilename('gem.gem.png')).toBe(false);
      expect(validateSafeFilename('module.ko.png')).toBe(false);
      expect(validateSafeFilename('lib.so.jpg')).toBe(false);
      expect(validateSafeFilename('archive.zst.webp')).toBe(false);
      expect(validateSafeFilename('disk.qcow2.jpeg')).toBe(false);
      expect(validateSafeFilename('file.scr.png')).toBe(false);
      expect(validateSafeFilename('file.diagcab.jpg')).toBe(false);
      expect(validateSafeFilename('file.mst.webp')).toBe(false);
      expect(validateSafeFilename('app.aar.png')).toBe(false);
      expect(validateSafeFilename('app.aab.jpeg')).toBe(false);
      expect(validateSafeFilename('script.kts.png')).toBe(false);
      expect(validateSafeFilename('page.ssi.jpg')).toBe(false);
      expect(validateSafeFilename('cert.p7b.webp')).toBe(false);
      expect(validateSafeFilename('cert.p7c.png')).toBe(false);
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

    it('should reject whitespace base filenames and Windows reserved device names', () => {
      expect(validateSafeFilename('  .png')).toBe(false);
      expect(validateSafeFilename('CON.png')).toBe(false);
      expect(validateSafeFilename('aux.jpg')).toBe(false);
      expect(validateSafeFilename('com1.webp')).toBe(false);
      expect(validateSafeFilename('lpt9.jpeg')).toBe(false);
      expect(validateSafeFilename('image.NUL.png')).toBe(false);
    });

    it('should reject whitespace-padded intermediate double extensions', () => {
      expect(validateSafeFilename('image.php .png')).toBe(false);
      expect(validateSafeFilename('avatar. exe .jpg')).toBe(false);
      expect(validateSafeFilename('script.py .png')).toBe(false);
    });

    it('should reject filenames containing Unicode Bidi override controls or zero-width characters', () => {
      expect(validateSafeFilename('image\u200E.png')).toBe(false); // LRM
      expect(validateSafeFilename('image\u200F.png')).toBe(false); // RLM
      expect(validateSafeFilename('image\u202A.png')).toBe(false); // LRE
      expect(validateSafeFilename('image\u202B.png')).toBe(false); // RLE
      expect(validateSafeFilename('image\u202C.png')).toBe(false); // PDF
      expect(validateSafeFilename('image\u202D.png')).toBe(false); // LRO
      expect(validateSafeFilename('image\u202E.png')).toBe(false); // RLO
      expect(validateSafeFilename('image\u2066.png')).toBe(false); // LRI
      expect(validateSafeFilename('image\u2067.png')).toBe(false); // RLI
      expect(validateSafeFilename('image\u2068.png')).toBe(false); // FSI
      expect(validateSafeFilename('image\u2069.png')).toBe(false); // PXI
      expect(validateSafeFilename('image\u061C.png')).toBe(false); // ALM
      expect(validateSafeFilename('image\u200B.png')).toBe(false); // ZWSP
      expect(validateSafeFilename('image\u200C.png')).toBe(false); // ZWNJ
      expect(validateSafeFilename('image\u200D.png')).toBe(false); // ZWJ
      expect(validateSafeFilename('image\uFEFF.png')).toBe(false); // BOM / ZWNBSP
    });
  });
});
