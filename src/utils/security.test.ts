import { describe, it, expect } from 'vitest';
import { validateImageProperties, validateSafeFilename } from './security.js';

describe('Sentinel Security Input Validation', () => {
  describe('validateImageProperties', () => {
    it('should allow valid image formats within size limit', () => {
      expect(validateImageProperties(1024 * 1024, 'image/png')).toBe(true);
      expect(validateImageProperties(5 * 1024 * 1024, 'image/jpeg')).toBe(true);
      expect(
        validateImageProperties(Math.floor(9.9 * 1024 * 1024), 'image/webp'),
      ).toBe(true);
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

    it('should reject NaN, non-integer, and non-string inputs', () => {
      expect(validateImageProperties(NaN, 'image/png')).toBe(false);
      expect(validateImageProperties(1.5, 'image/png')).toBe(false);
      expect(validateImageProperties(Infinity, 'image/png')).toBe(false);
      // @ts-ignore
      expect(validateImageProperties('1024', 'image/png')).toBe(false);
      // @ts-ignore
      expect(validateImageProperties(1024, null)).toBe(false);
    });
  });

  describe('validateSafeFilename', () => {
    it('should allow safe, simple filenames', () => {
      expect(validateSafeFilename('profile.png')).toBe(true);
      expect(validateSafeFilename('background-123.jpg')).toBe(true);
    });

    it('should reject deep multi-level percent-encoded path traversal bypass attempts', () => {
      // 4 levels of encoding for ../
      expect(
        validateSafeFilename('%2525252e%2525252e%2525252fprofile.png'),
      ).toBe(false);
      // 4 levels of encoding for ..\
      expect(
        validateSafeFilename('%2525252e%2525252e%2525255cprofile.png'),
      ).toBe(false);
      // 5 levels of encoding for ../
      expect(
        validateSafeFilename('%252525252e%252525252e%252525252fprofile.png'),
      ).toBe(false);
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

    it('should reject percent-encoded path traversal bypass attempts', () => {
      expect(validateSafeFilename('%2e%2e%2fetc/passwd')).toBe(false);
      expect(validateSafeFilename('images/%2e%2e%2fphoto.png')).toBe(false);
      expect(validateSafeFilename('%2e%2e%2fprofile.png')).toBe(false);
      expect(validateSafeFilename('%2E%2E%2Fprofile.png')).toBe(false);
    });

    it('should reject double percent-encoded path traversal bypass attempts', () => {
      expect(validateSafeFilename('%252e%252e%252fetc/passwd')).toBe(false);
      expect(validateSafeFilename('%252e%252e%252fprofile.png')).toBe(false);
      expect(validateSafeFilename('%25252e%25252e%25252fprofile.png')).toBe(
        false,
      );
    });

    it('should reject double extensions with dangerous intermediate components', () => {
      expect(validateSafeFilename('image.php.png')).toBe(false);
      expect(validateSafeFilename('image.php8.png')).toBe(false);
      expect(validateSafeFilename('archive.phar.jpg')).toBe(false);
      expect(validateSafeFilename('index.html.webp')).toBe(false);
      expect(validateSafeFilename('index.shtml.webp')).toBe(false);
      expect(validateSafeFilename('shell.sh.jpg')).toBe(false);
      expect(validateSafeFilename('script.ps1.png')).toBe(false);
      expect(validateSafeFilename('app.hta.png')).toBe(false);
      expect(validateSafeFilename('shortcut.lnk.png')).toBe(false);
      expect(validateSafeFilename('data.xml.png')).toBe(false);
      expect(validateSafeFilename('test.config.jpeg')).toBe(false);
    });

    it('should reject double extensions with dangerous intermediate components containing whitespace', () => {
      expect(validateSafeFilename('image.php .png')).toBe(false);
      expect(validateSafeFilename('image. php.png')).toBe(false);
      expect(validateSafeFilename('image.php%20.png')).toBe(false);
      expect(validateSafeFilename('image.%20php.png')).toBe(false);
    });

    it('should allow double extensions with safe intermediate components', () => {
      expect(validateSafeFilename('archive.tar.png')).toBe(true);
      expect(validateSafeFilename('backup.bak.webp')).toBe(true);
    });

    it('should reject Unicode-normalized path traversal bypass attempts', () => {
      expect(validateSafeFilename('\uFF0E\uFF0E\uFF0Fprofile.png')).toBe(false);
      expect(validateSafeFilename('\u2024\u2024\uFF0Fprofile.png')).toBe(false);
    });

    it('should safely reject malformed URI sequences', () => {
      expect(validateSafeFilename('profile%E0%A2%a.png')).toBe(false);
    });

    it('should correctly process safe percent-encoded filenames', () => {
      expect(validateSafeFilename('my%20photo.png')).toBe(true);
    });

    it('should reject NTFS Alternate Data Streams, wildcards, shell injection, and control characters', () => {
      // NTFS ADS colon
      expect(validateSafeFilename('image.png:stream')).toBe(false);
      expect(validateSafeFilename('image.png%3astream')).toBe(false); // percent-encoded colon

      // Wildcards
      expect(validateSafeFilename('image*.png')).toBe(false);
      expect(validateSafeFilename('image?.png')).toBe(false);

      // Shell injection characters
      expect(validateSafeFilename('image;injection.png')).toBe(false);
      expect(validateSafeFilename('image&injection.png')).toBe(false);
      expect(validateSafeFilename('image`injection`.png')).toBe(false);
      expect(validateSafeFilename('image$injection.png')).toBe(false);
      expect(validateSafeFilename('image|injection.png')).toBe(false);
      expect(validateSafeFilename('image<injection>.png')).toBe(false);

      // Control characters
      expect(validateSafeFilename('image\n.png')).toBe(false);
      expect(validateSafeFilename('image\r.png')).toBe(false);
      expect(validateSafeFilename('image\u001F.png')).toBe(false);
    });

    it('should reject empty or whitespace-only base names', () => {
      expect(validateSafeFilename(' .png')).toBe(false);
      expect(validateSafeFilename('  .jpg')).toBe(false);
      expect(validateSafeFilename('  ...webp')).toBe(false);
      expect(validateSafeFilename('.foo.png')).toBe(false);
    });

    it('should reject bidirectional override and control characters (Trojan Source mitigation)', () => {
      expect(validateSafeFilename('photo\u200E.png')).toBe(false);
      expect(validateSafeFilename('photo\u200F.png')).toBe(false);
      expect(validateSafeFilename('photo\u202A.png')).toBe(false);
      expect(validateSafeFilename('photo\u202B.png')).toBe(false);
      expect(validateSafeFilename('photo\u202C.png')).toBe(false);
      expect(validateSafeFilename('photo\u202D.png')).toBe(false);
      expect(validateSafeFilename('photo\u202E.png')).toBe(false);
      expect(validateSafeFilename('photo\u2066.png')).toBe(false);
      expect(validateSafeFilename('photo\u2067.png')).toBe(false);
      expect(validateSafeFilename('photo\u2068.png')).toBe(false);
      expect(validateSafeFilename('photo\u2069.png')).toBe(false);
      expect(validateSafeFilename('photo\u061C.png')).toBe(false);
    });

    it('should reject zero-width and invisible characters that could bypass extension signature checks', () => {
      expect(validateSafeFilename('photo\u200B.png')).toBe(false);
      expect(validateSafeFilename('photo\u200C.png')).toBe(false);
      expect(validateSafeFilename('photo\u200D.png')).toBe(false);
      expect(validateSafeFilename('photo\uFEFF.png')).toBe(false);
    });

    it('should reject double extensions with expanded list of dangerous intermediate components', () => {
      expect(validateSafeFilename('image.rb.png')).toBe(false);
      expect(validateSafeFilename('image.mjs.png')).toBe(false);
      expect(validateSafeFilename('image.cjs.png')).toBe(false);
      expect(validateSafeFilename('image.ashx.png')).toBe(false);
      expect(validateSafeFilename('image.asmx.png')).toBe(false);
      expect(validateSafeFilename('image.asax.png')).toBe(false);
      expect(validateSafeFilename('image.class.png')).toBe(false);
      expect(validateSafeFilename('image.jar.png')).toBe(false);
      expect(validateSafeFilename('image.json.png')).toBe(false);
      expect(validateSafeFilename('image.yaml.png')).toBe(false);
      expect(validateSafeFilename('image.yml.png')).toBe(false);
    });

    it('should reject Windows reserved device names as base names or intermediate components', () => {
      expect(validateSafeFilename('con.png')).toBe(false);
      expect(validateSafeFilename('AUX.jpg')).toBe(false);
      expect(validateSafeFilename('nul.webp')).toBe(false);
      expect(validateSafeFilename('prn.jpeg')).toBe(false);
      expect(validateSafeFilename('clock$.png')).toBe(false);
      expect(validateSafeFilename('conin$.jpg')).toBe(false);
      expect(validateSafeFilename('conout$.webp')).toBe(false);
      expect(validateSafeFilename('com1.png')).toBe(false);
      expect(validateSafeFilename('com9.png')).toBe(false);
      expect(validateSafeFilename('lpt1.png')).toBe(false);
      expect(validateSafeFilename('lpt9.png')).toBe(false);

      // Trailing spaces/different casing
      expect(validateSafeFilename('CON .png')).toBe(false);
      expect(validateSafeFilename('aux .jpg')).toBe(false);

      // Double-extension cases
      expect(validateSafeFilename('con.tar.png')).toBe(false);
      expect(validateSafeFilename('NUL.bak.webp')).toBe(false);
      expect(validateSafeFilename('image.con.png')).toBe(false);
      expect(validateSafeFilename('image.clock$.png')).toBe(false);
    });

    it('should reject additional script, module, and config intermediate extensions', () => {
      expect(validateSafeFilename('image.asa.png')).toBe(false);
      expect(validateSafeFilename('image.cer.jpg')).toBe(false);
      expect(validateSafeFilename('image.pht.webp')).toBe(false);
      expect(validateSafeFilename('image.env.png')).toBe(false);
      expect(validateSafeFilename('image.ini.png')).toBe(false);
      expect(validateSafeFilename('image.conf.png')).toBe(false);
      expect(validateSafeFilename('image.sql.jpg')).toBe(false);
      expect(validateSafeFilename('image.zsh.png')).toBe(false);
      expect(validateSafeFilename('image.fish.png')).toBe(false);
      expect(validateSafeFilename('image.psm1.png')).toBe(false);
      expect(validateSafeFilename('image.psd1.png')).toBe(false);
      expect(validateSafeFilename('image.vbe.png')).toBe(false);
      expect(validateSafeFilename('image.wsf.png')).toBe(false);
      expect(validateSafeFilename('image.wsc.png')).toBe(false);
      expect(validateSafeFilename('image.pyc.png')).toBe(false);
      expect(validateSafeFilename('image.pyw.png')).toBe(false);
      expect(validateSafeFilename('image.rbw.png')).toBe(false);
      expect(validateSafeFilename('image.com.png')).toBe(false);
      expect(validateSafeFilename('image.reg.jpg')).toBe(false);
      expect(validateSafeFilename('image.inf.webp')).toBe(false);
      expect(validateSafeFilename('image.sys.png')).toBe(false);
      expect(validateSafeFilename('image.vb.jpg')).toBe(false);
      expect(validateSafeFilename('image.cs.png')).toBe(false);
      expect(validateSafeFilename('image.wasm.webp')).toBe(false);
      expect(validateSafeFilename('image.swf.png')).toBe(false);
      expect(validateSafeFilename('image.jspa.png')).toBe(false);
      expect(validateSafeFilename('image.jspf.jpg')).toBe(false);
      expect(validateSafeFilename('image.action.png')).toBe(false);
      expect(validateSafeFilename('image.do.png')).toBe(false);
      expect(validateSafeFilename('image.cpl.png')).toBe(false);
      expect(validateSafeFilename('image.scf.jpg')).toBe(false);
      expect(validateSafeFilename('image.wsh.webp')).toBe(false);
      expect(validateSafeFilename('image.ws.png')).toBe(false);
      expect(validateSafeFilename('image.vba.png')).toBe(false);
      expect(validateSafeFilename('image.gadget.png')).toBe(false);
      expect(validateSafeFilename('image.appref-ms.png')).toBe(false);
      expect(validateSafeFilename('image.pif.png')).toBe(false);
      expect(validateSafeFilename('image.sct.jpg')).toBe(false);
      expect(validateSafeFilename('image.scrobj.webp')).toBe(false);
      expect(validateSafeFilename('image.htc.png')).toBe(false);
      expect(validateSafeFilename('image.application.png')).toBe(false);
      expect(validateSafeFilename('image.xbap.png')).toBe(false);
      expect(validateSafeFilename('image.axd.png')).toBe(false);
      expect(validateSafeFilename('image.rdp.jpg')).toBe(false);
      expect(validateSafeFilename('image.crt.webp')).toBe(false);
      expect(validateSafeFilename('image.pem.png')).toBe(false);
      expect(validateSafeFilename('image.key.png')).toBe(false);
      expect(validateSafeFilename('image.pfx.jpeg')).toBe(false);
      expect(validateSafeFilename('image.shs.png')).toBe(false);
      expect(validateSafeFilename('image.stm.png')).toBe(false);
      expect(validateSafeFilename('image.der.png')).toBe(false);
      expect(validateSafeFilename('image.p8.png')).toBe(false);
      expect(validateSafeFilename('image.p12.png')).toBe(false);
      expect(validateSafeFilename('image.cdx.jpg')).toBe(false);
      expect(validateSafeFilename('image.command.webp')).toBe(false);
      expect(validateSafeFilename('image.settingcontent-ms.png')).toBe(false);
      expect(validateSafeFilename('image.ps2.png')).toBe(false);
      expect(validateSafeFilename('image.psc1.png')).toBe(false);
      expect(validateSafeFilename('image.ps1xml.png')).toBe(false);
      expect(validateSafeFilename('image.deb.png')).toBe(false);
      expect(validateSafeFilename('image.rpm.png')).toBe(false);
      expect(validateSafeFilename('image.msu.png')).toBe(false);
      expect(validateSafeFilename('image.msp.png')).toBe(false);
      expect(validateSafeFilename('image.chm.png')).toBe(false);
      expect(validateSafeFilename('image.apk.png')).toBe(false);
      expect(validateSafeFilename('image.dmg.jpg')).toBe(false);
      expect(validateSafeFilename('image.pkg.webp')).toBe(false);
      expect(validateSafeFilename('image.msix.png')).toBe(false);
      expect(validateSafeFilename('image.appx.png')).toBe(false);
      expect(validateSafeFilename('image.docm.png')).toBe(false);
      expect(validateSafeFilename('image.xlsm.png')).toBe(false);
      expect(validateSafeFilename('image.pptm.png')).toBe(false);
      expect(validateSafeFilename('image.xap.png')).toBe(false);
      expect(validateSafeFilename('image.xnk.png')).toBe(false);
      expect(validateSafeFilename('image.desklink.png')).toBe(false);
      expect(validateSafeFilename('image.mapimail.png')).toBe(false);
      expect(validateSafeFilename('image.website.png')).toBe(false);
      expect(validateSafeFilename('image.url.jpg')).toBe(false);
      expect(validateSafeFilename('image.mhtml.webp')).toBe(false);
      expect(validateSafeFilename('image.mht.png')).toBe(false);
      expect(validateSafeFilename('image.vhd.png')).toBe(false);
      expect(validateSafeFilename('image.vhdx.png')).toBe(false);
      expect(validateSafeFilename('image.iso.png')).toBe(false);
      expect(validateSafeFilename('image.img.png')).toBe(false);
    });
  });
});
