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

  // Reject unsafe filename characters (control chars, shell injection chars, NTFS streams, wildcards)
  if (/[:*?"<>|;&$`\r\n\x00-\x1F\x7F-\x9F]/.test(normalized)) {
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

  // Prevent double extension attacks (e.g. image.php.png, avatar.exe.jpg)
  const dangerousIntermediates = new Set([
    'php',
    'php3',
    'php4',
    'php5',
    'phtml',
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
  ]);
  const parts = normalized.toLowerCase().split('.');
  // Check intermediate extensions (all parts except the base filename and final extension)
  for (let i = 1; i < parts.length - 1; i++) {
    if (dangerousIntermediates.has(parts[i])) {
      return false;
    }
  }

  return true;
}
