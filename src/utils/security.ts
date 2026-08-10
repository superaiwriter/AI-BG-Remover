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
  if (typeof size !== 'number' || !Number.isInteger(size)) {
    return false;
  }
  if (size <= 0 || size > MAX_ALLOWED_FILE_SIZE_BYTES) {
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

  let normalized = filename;
  let decoded = normalized;
  let iterations = 0;
  const maxIterations = 3;
  while (iterations < maxIterations) {
    try {
      const nextDecoded = decodeURIComponent(decoded);
      if (nextDecoded === decoded) {
        break;
      }
      decoded = nextDecoded;
      iterations++;
    } catch {
      return false;
    }
  }
  normalized = decoded;

  // Normalize Unicode to NFKC form to prevent Unicode normalization bypasses
  normalized = normalized.normalize('NFKC');

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

  // Prevent NTFS Alternate Data Streams, wildcards, shell injection, and control characters
  const unsafePattern = /[:*?"<>|;&$`\r\n\x00-\x1F\x7F-\x9F]/;
  if (unsafePattern.test(normalized)) {
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

  const extension = normalized.slice(lastDotIndex).toLowerCase();
  const allowedExtensions = new Set(['.jpg', '.jpeg', '.png', '.webp']);
  if (!allowedExtensions.has(extension)) {
    return false;
  }

  // Reject filenames containing dangerous intermediate executable/web extensions
  const parts = normalized.split('.');

  // Prevent filenames with empty, whitespace-only, or Windows-reserved base names
  const baseName = parts[0].trim().toLowerCase();
  if (!baseName) {
    return false;
  }

  const windowsReservedNames = new Set([
    'con',
    'prn',
    'aux',
    'nul',
    'com1',
    'com2',
    'com3',
    'com4',
    'com5',
    'com6',
    'com7',
    'com8',
    'com9',
    'lpt1',
    'lpt2',
    'lpt3',
    'lpt4',
    'lpt5',
    'lpt6',
    'lpt7',
    'lpt8',
    'lpt9',
  ]);
  if (windowsReservedNames.has(baseName)) {
    return false;
  }

  if (parts.length > 2) {
    const dangerousIntermediates = new Set([
      'php',
      'phtml',
      'php3',
      'php4',
      'php5',
      'php7',
      'phps',
      'asp',
      'aspx',
      'jsp',
      'jspx',
      'cgi',
      'pl',
      'py',
      'sh',
      'bash',
      'bat',
      'cmd',
      'exe',
      'msi',
      'dll',
      'scr',
      'vbs',
      'js',
      'ts',
      'html',
      'htm',
      'xhtml',
      'svg',
      'xml',
      'config',
      'htaccess',
    ]);
    for (let i = 1; i < parts.length - 1; i++) {
      if (dangerousIntermediates.has(parts[i].trim().toLowerCase())) {
        return false;
      }
    }
  }

  return true;
}
