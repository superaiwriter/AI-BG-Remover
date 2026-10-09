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

    it('should allow case-insensitive and whitespace-padded MIME types', () => {
      expect(validateImageProperties(1024, 'IMAGE/PNG')).toBe(true);
      expect(validateImageProperties(1024, ' image/jpeg ')).toBe(true);
      expect(validateImageProperties(1024, 'Image/WebP')).toBe(true);
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
      // 11 levels of encoding for ../ (exceeding 10 max decoding iterations)
      expect(
        validateSafeFilename(
          '%252525252525252525252e%252525252525252525252e%252525252525252525252fprofile.png',
        ),
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
      expect(validateSafeFilename('photo.v1.png')).toBe(true);
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
      expect(validateSafeFilename('com1.png')).toBe(false);
      expect(validateSafeFilename('com9.png')).toBe(false);
      expect(validateSafeFilename('lpt1.png')).toBe(false);
      expect(validateSafeFilename('lpt9.png')).toBe(false);
      expect(validateSafeFilename('clock$.png')).toBe(false);
      expect(validateSafeFilename('CONIN$.png')).toBe(false);
      expect(validateSafeFilename('CONOUT$.png')).toBe(false);

      // Trailing spaces/different casing
      expect(validateSafeFilename('CON .png')).toBe(false);
      expect(validateSafeFilename('aux .jpg')).toBe(false);

      // Double-extension and intermediate component cases
      expect(validateSafeFilename('con.tar.png')).toBe(false);
      expect(validateSafeFilename('NUL.bak.webp')).toBe(false);
      expect(validateSafeFilename('image.con.png')).toBe(false);
      expect(validateSafeFilename('photo.clock$.jpeg')).toBe(false);
    });

    it('should reject double extensions with expanded script, executable, and config intermediate extensions', () => {
      expect(validateSafeFilename('script.asa.png')).toBe(false);
      expect(validateSafeFilename('cert.cer.jpg')).toBe(false);
      expect(validateSafeFilename('page.pht.webp')).toBe(false);
      expect(validateSafeFilename('module.pyc.png')).toBe(false);
      expect(validateSafeFilename('script.pyw.jpg')).toBe(false);
      expect(validateSafeFilename('script.rbw.webp')).toBe(false);
      expect(validateSafeFilename('shell.zsh.png')).toBe(false);
      expect(validateSafeFilename('shell.fish.jpg')).toBe(false);
      expect(validateSafeFilename('script.vbe.webp')).toBe(false);
      expect(validateSafeFilename('script.wsf.png')).toBe(false);
      expect(validateSafeFilename('script.wsc.jpg')).toBe(false);
      expect(validateSafeFilename('include.inc.webp')).toBe(false);
      expect(validateSafeFilename('page.cfm.png')).toBe(false);
      expect(validateSafeFilename('component.cfc.jpg')).toBe(false);
      expect(validateSafeFilename('secrets.env.png')).toBe(false);
      expect(validateSafeFilename('config.ini.jpg')).toBe(false);
      expect(validateSafeFilename('settings.conf.webp')).toBe(false);
      expect(validateSafeFilename('module.psm1.png')).toBe(false);
      expect(validateSafeFilename('manifest.psd1.jpg')).toBe(false);
      expect(validateSafeFilename('query.sql.webp')).toBe(false);
    });

    it('should reject double extensions with macro-enabled, installer, package, and compiled help extensions', () => {
      expect(validateSafeFilename('help.chm.png')).toBe(false);
      expect(validateSafeFilename('app.apk.jpg')).toBe(false);
      expect(validateSafeFilename('installer.dmg.webp')).toBe(false);
      expect(validateSafeFilename('package.pkg.png')).toBe(false);
      expect(validateSafeFilename('bundle.msix.jpg')).toBe(false);
      expect(validateSafeFilename('app.appx.webp')).toBe(false);
      expect(validateSafeFilename('doc.docm.png')).toBe(false);
      expect(validateSafeFilename('sheet.xlsm.jpg')).toBe(false);
      expect(validateSafeFilename('presentation.pptm.webp')).toBe(false);
    });

    it('should reject double extensions with disk image, shortcut, script host, web query, and certificate extensions', () => {
      expect(validateSafeFilename('disk.iso.png')).toBe(false);
      expect(validateSafeFilename('image.img.jpg')).toBe(false);
      expect(validateSafeFilename('disk.vhd.webp')).toBe(false);
      expect(validateSafeFilename('shortcut.url.png')).toBe(false);
      expect(validateSafeFilename('setting.settingcontent-ms.jpg')).toBe(false);
      expect(validateSafeFilename('control.cpl.webp')).toBe(false);
      expect(validateSafeFilename('cert.pem.png')).toBe(false);
      expect(validateSafeFilename('key.pfx.jpg')).toBe(false);
      expect(validateSafeFilename('query.iqy.webp')).toBe(false);
      expect(validateSafeFilename('database.accdb.png')).toBe(false);
      expect(validateSafeFilename('template.xltm.jpg')).toBe(false);
    });

    it('should reject double extensions with template engine and compressed archive intermediate extensions', () => {
      expect(validateSafeFilename('view.ejs.png')).toBe(false);
      expect(validateSafeFilename('template.hbs.jpg')).toBe(false);
      expect(validateSafeFilename('page.twig.webp')).toBe(false);
      expect(validateSafeFilename('layout.liquid.png')).toBe(false);
      expect(validateSafeFilename('template.jinja.jpg')).toBe(false);
      expect(validateSafeFilename('template.jinja2.webp')).toBe(false);
      expect(validateSafeFilename('view.erb.png')).toBe(false);
      expect(validateSafeFilename('template.tpl.jpg')).toBe(false);
      expect(validateSafeFilename('archive.zip.png')).toBe(false);
      expect(validateSafeFilename('backup.tar.jpg')).toBe(false);
      expect(validateSafeFilename('data.gz.webp')).toBe(false);
      expect(validateSafeFilename('bundle.7z.png')).toBe(false);
    });

    it('should reject double extensions with system, registry, installer, and script intermediate extensions', () => {
      expect(validateSafeFilename('key.reg.png')).toBe(false);
      expect(validateSafeFilename('setup.inf.jpg')).toBe(false);
      expect(validateSafeFilename('driver.sys.webp')).toBe(false);
      expect(validateSafeFilename('app.com.png')).toBe(false);
      expect(validateSafeFilename('shortcut.pif.jpg')).toBe(false);
      expect(validateSafeFilename('script.scpt.webp')).toBe(false);
      expect(validateSafeFilename('diag.diagcab.png')).toBe(false);
      expect(validateSafeFilename('transform.mst.jpg')).toBe(false);
    });
  });
});
