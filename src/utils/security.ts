/**
 * Sentinel Security Helpers for AI Background Remover
 *
 * Implements input validation and defense-in-depth measures:
 * - Denial of Service (DoS) protection via size limiting
 * - Safe image MIME type verification
 * - Path traversal mitigation for image files
 */

// Maximum safe image size: 10 MB (10 * 1024 * 1024 bytes)
const MAX_ALLOWED_FILE_SIZE_BYTES = 10 * 1024 * 1024;

// Safe, supported MIME types for background removal via Gemini API
const ALLOWED_MIME_TYPES = new Set(['image/jpeg', 'image/png', 'image/webp']);

/**
 * Validates file properties before processing to prevent Denial of Service (DoS)
 * and arbitrary/unsafe file execution.
 *
 * @param size File size in bytes
 * @param mimeType MIME type of the file
 * @returns boolean indicating if the file is safe and supported
 */
export function validateImageProperties(
  size: number,
  mimeType: string,
): boolean {
  if (
    typeof size !== 'number' ||
    !Number.isFinite(size) ||
    size <= 0 ||
    size > MAX_ALLOWED_FILE_SIZE_BYTES
  ) {
    return false;
  }
  if (typeof mimeType !== 'string') {
    return false;
  }
  return ALLOWED_MIME_TYPES.has(mimeType);
}

/**
 * Validates a filename to prevent path traversal vulnerabilities.
 *
 * @param filename Name of the file being processed
 * @returns boolean indicating if the filename is safe (no traversal components)
 */
export function validateSafeFilename(filename: string): boolean {
  if (!filename || typeof filename !== 'string') {
    return false;
  }

  // Iteratively decode URL percent-encoding to catch multi-level obfuscated path traversal
  let decoded = filename;
  try {
    let prev = '';
    let iterations = 0;
    while (decoded !== prev && iterations < 10) {
      prev = decoded;
      decoded = decodeURIComponent(decoded);
      iterations++;
    }
  } catch {
    return false; // Reject malformed percent-encoding
  }

  // Normalize Unicode representation to prevent normalization bypasses (e.g. full-width slashes)
  const normalized = decoded.normalize('NFKC');

  // Prevent null byte injection to stop truncation attacks on OS APIs
  if (normalized.includes('\0') || normalized.includes('\u0000')) {
    return false;
  }

  // Basic validation to prevent Directory/Path Traversal
  if (
    normalized.includes('..') ||
    normalized.includes('/') ||
    normalized.includes('\\')
  ) {
    return false;
  }

  // Reject unsafe filename characters (control chars, shell injection, NTFS streams, wildcards, Bidi overrides, zero-width chars)
  if (
    /[:*?"<>|;&$`\r\n\x00-\x1F\x7F-\x9F\u061C\u200B-\u200D\u200E\u200F\u202A-\u202E\u2066-\u2069\uFEFF]/.test(
      normalized,
    )
  ) {
    return false;
  }

  // Prevent overly long filenames (limit to 255 chars)
  if (normalized.length > 255) {
    return false;
  }

  // Enforce safe, allowed image extensions in a case-insensitive manner
  const lastDotIndex = normalized.lastIndexOf('.');
  if (lastDotIndex <= 0) {
    // If no dot or dot is the first character (e.g. '.png' with no base name), reject
    return false;
  }

  // Reject base filenames that are empty or whitespace-only
  const baseName = normalized.slice(0, lastDotIndex).trim();
  if (!baseName) {
    return false;
  }

  const extension = normalized.slice(lastDotIndex).toLowerCase();
  const allowedExtensions = new Set(['.jpg', '.jpeg', '.png', '.webp']);
  if (!allowedExtensions.has(extension)) {
    return false;
  }

  // Prevent Windows reserved device names and double extension attacks
  const winReserved =
    /^(con|prn|aux|nul|com[1-9]|lpt[1-9]|conin\$|conout\$|clock\$)$/i;
  const dangerousIntermediates = new Set([
    'php',
    'php3',
    'php4',
    'php5',
    'phtml',
    'phar',
    'py',
    'rb',
    'jar',
    'asp',
    'aspx',
    'jsp',
    'cgi',
    'pl',
    'exe',
    'sh',
    'bat',
    'cmd',
    'ps1',
    'vbs',
    'hta',
    'js',
    'mjs',
    'cjs',
    'jsx',
    'tsx',
    'ashx',
    'asmx',
    'asax',
    'class',
    'asa',
    'cer',
    'pht',
    'pyc',
    'pyw',
    'rbw',
    'zsh',
    'fish',
    'vbe',
    'wsf',
    'wsc',
    'inc',
    'cfm',
    'cfc',
    'env',
    'ini',
    'conf',
    'psm1',
    'psd1',
    'sql',
    'chm',
    'apk',
    'dmg',
    'pkg',
    'msix',
    'appx',
    'docm',
    'xlsm',
    'pptm',
    'xap',
    'xnk',
    'desklink',
    'mapimail',
    'website',
    'url',
    'mhtml',
    'mht',
    'vhd',
    'vhdx',
    'iso',
    'img',
    'xltm',
    'xlam',
    'potm',
    'ppam',
    'ppsm',
    'accda',
    'accdb',
    'mda',
    'mde',
    'ade',
    'adp',
    'iqy',
    'rqy',
    'oqy',
    'dqy',
    'msc',
    'ins',
    'isp',
    'xsn',
    'sfx',
    'csh',
    'tcsh',
    'ksh',
    'pyo',
    'pyd',
    'war',
    'ear',
    'drv',
    'rake',
    'xxe',
    'xla',
    'xlt',
    'ppa',
    'pwz',
    'der',
    'p8',
    'p12',
    'cdx',
    'command',
    'settingcontent-ms',
    'ps2',
    'psc1',
    'ps1xml',
    'deb',
    'rpm',
    'msu',
    'msp',
    'axd',
    'rdp',
    'crt',
    'pem',
    'key',
    'pfx',
    'shs',
    'stm',
    'dotm',
    'sldm',
    'xll',
    'slk',
    'onetoc2',
    'pif',
    'sct',
    'scrobj',
    'htc',
    'application',
    'xbap',
    'cpl',
    'scf',
    'wsh',
    'ws',
    'vba',
    'gadget',
    'appref-ms',
    'com',
    'reg',
    'inf',
    'sys',
    'vb',
    'cs',
    'wasm',
    'swf',
    'jspa',
    'jspf',
    'action',
    'do',
    'shtml',
    'shtm',
    'php7',
    'phps',
    'config',
    'json',
    'yaml',
    'yml',
    'zip',
    'tar',
    'gz',
    '7z',
    'rar',
    'bz2',
    'xz',
    'tgz',
    'cab',
    'lz',
    'lzma',
    'z',
    'zipx',
    'whl',
    'egg',
    'nupkg',
    'crx',
    'xpi',
    'gem',
    'ace',
    'arj',
    'lzh',
    'cpio',
    'tbz',
    'tbz2',
    'txz',
    'ko',
    'so',
    'o',
    'a',
    'ebuild',
    'ipk',
    'opk',
    'zst',
    'zstd',
    'squashfs',
    'qcow2',
    'scr',
    'diagcab',
    'mst',
    'aar',
    'aab',
    'kts',
    'ssi',
    'p7b',
    'p7c',
  ]);
  const parts = normalized.toLowerCase().split('.');
  for (let i = 0; i < parts.length; i++) {
    const part = parts[i].trim();
    if (winReserved.test(part)) {
      return false;
    }
    if (i > 0 && i < parts.length - 1 && dangerousIntermediates.has(part)) {
      return false;
    }
  }

  return true;
}
