import crypto from 'crypto';

export interface GenerateOptions {
  length?: number;
  uppercase?: boolean;
  lowercase?: boolean;
  numbers?: boolean;
  symbols?: boolean;
  excludeAmbiguous?: boolean;
}

export interface StrengthResult {
  password: string;
  score: number;
  level: 'very_weak' | 'weak' | 'fair' | 'strong' | 'very_strong';
  feedback: string[];
  entropy: number;
  crackTime: string;
}

const CHARS = {
  uppercase: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
  lowercase: 'abcdefghijklmnopqrstuvwxyz',
  numbers: '0123456789',
  symbols: '!@#$%^&*()_+-=[]{}|;:,.<>?',
  ambiguous: 'Il1O0',
};

/**
 * Generate a cryptographically secure random password
 */
export function generatePassword(options: GenerateOptions = {}): string {
  const {
    length = 16,
    uppercase = true,
    lowercase = true,
    numbers = true,
    symbols = true,
    excludeAmbiguous = false,
  } = options;

  // Build character set
  let charset = '';
  const required: string[] = [];

  if (uppercase) {
    let chars = CHARS.uppercase;
    if (excludeAmbiguous) {
      chars = chars.replace(/[IO]/g, '');
    }
    charset += chars;
    required.push(secureRandomChar(chars));
  }

  if (lowercase) {
    let chars = CHARS.lowercase;
    if (excludeAmbiguous) {
      chars = chars.replace(/[l]/g, '');
    }
    charset += chars;
    required.push(secureRandomChar(chars));
  }

  if (numbers) {
    let chars = CHARS.numbers;
    if (excludeAmbiguous) {
      chars = chars.replace(/[01]/g, '');
    }
    charset += chars;
    required.push(secureRandomChar(chars));
  }

  if (symbols) {
    charset += CHARS.symbols;
    required.push(secureRandomChar(CHARS.symbols));
  }

  if (charset.length === 0) {
    throw new Error('At least one character type must be enabled');
  }

  // Ensure minimum length
  const minLength = Math.max(length, required.length);
  
  // Generate remaining characters
  const remaining: string[] = [];
  for (let i = required.length; i < minLength; i++) {
    remaining.push(secureRandomChar(charset));
  }

  // Combine and shuffle
  const allChars = [...required, ...remaining];
  return secureShuffleArray(allChars).join('');
}

/**
 * Generate multiple passwords at once
 */
export function generateBatch(
  count: number,
  options: GenerateOptions = {}
): string[] {
  const passwords: string[] = [];
  const maxCount = Math.min(count, 100); // Limit batch size
  
  for (let i = 0; i < maxCount; i++) {
    passwords.push(generatePassword(options));
  }
  
  return passwords;
}

/**
 * Analyze password strength
 */
export function analyzeStrength(password: string): StrengthResult {
  const feedback: string[] = [];
  let score = 0;

  // Length scoring
  if (password.length >= 8) score += 1;
  if (password.length >= 12) score += 1;
  if (password.length >= 16) score += 1;
  if (password.length >= 20) score += 1;

  // Character variety
  const hasLower = /[a-z]/.test(password);
  const hasUpper = /[A-Z]/.test(password);
  const hasNumber = /\d/.test(password);
  const hasSymbol = /[!@#$%^&*()_+\-=\[\]{}|;:,.<>?]/.test(password);

  if (hasLower) score += 1;
  if (hasUpper) score += 1;
  if (hasNumber) score += 1;
  if (hasSymbol) score += 1;

  // Penalties
  if (password.length < 8) {
    feedback.push('Password is too short (minimum 8 characters)');
    score -= 2;
  }

  if (!hasLower) feedback.push('Add lowercase letters');
  if (!hasUpper) feedback.push('Add uppercase letters');
  if (!hasNumber) feedback.push('Add numbers');
  if (!hasSymbol) feedback.push('Add special characters');

  // Common patterns
  if (/(.)\1{2,}/.test(password)) {
    feedback.push('Avoid repeated characters');
    score -= 1;
  }

  if (/^[a-zA-Z]+$/.test(password)) {
    feedback.push('Mix in numbers and symbols');
    score -= 1;
  }

  if (/^[0-9]+$/.test(password)) {
    feedback.push('Include letters and symbols');
    score -= 2;
  }

  // Sequential patterns
  if (/(?:abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz|012|123|234|345|456|567|678|789)/i.test(password)) {
    feedback.push('Avoid sequential patterns');
    score -= 1;
  }

  // Keyboard patterns
  if (/(?:qwert|asdf|zxcv)/i.test(password)) {
    feedback.push('Avoid keyboard patterns');
    score -= 1;
  }

  // Calculate entropy
  let charsetSize = 0;
  if (hasLower) charsetSize += 26;
  if (hasUpper) charsetSize += 26;
  if (hasNumber) charsetSize += 10;
  if (hasSymbol) charsetSize += 32;
  
  const entropy = password.length * Math.log2(charsetSize || 1);

  // Normalize score
  score = Math.max(0, Math.min(10, score));

  // Determine level
  let level: StrengthResult['level'];
  if (score <= 2) level = 'very_weak';
  else if (score <= 4) level = 'weak';
  else if (score <= 6) level = 'fair';
  else if (score <= 8) level = 'strong';
  else level = 'very_strong';

  // Estimate crack time
  const crackTime = estimateCrackTime(entropy);

  if (feedback.length === 0) {
    feedback.push('Password looks strong!');
  }

  return {
    password: password.substring(0, 3) + '*'.repeat(Math.max(0, password.length - 3)),
    score,
    level,
    feedback,
    entropy: Math.round(entropy * 100) / 100,
    crackTime,
  };
}

/**
 * Get a cryptographically secure random character from a string
 */
function secureRandomChar(chars: string): string {
  const randomIndex = crypto.randomInt(0, chars.length);
  return chars[randomIndex];
}

/**
 * Securely shuffle an array using Fisher-Yates
 */
function secureShuffleArray<T>(array: T[]): T[] {
  const result = [...array];
  for (let i = result.length - 1; i > 0; i--) {
    const j = crypto.randomInt(0, i + 1);
    [result[i], result[j]] = [result[j], result[i]];
  }
  return result;
}

/**
 * Estimate time to crack based on entropy
 */
function estimateCrackTime(entropy: number): string {
  // Assuming 10 billion guesses per second (modern GPU cluster)
  const guessesPerSecond = 10_000_000_000;
  const combinations = Math.pow(2, entropy);
  const seconds = combinations / guessesPerSecond / 2; // Average case

  if (seconds < 1) return 'instant';
  if (seconds < 60) return `${Math.round(seconds)} seconds`;
  if (seconds < 3600) return `${Math.round(seconds / 60)} minutes`;
  if (seconds < 86400) return `${Math.round(seconds / 3600)} hours`;
  if (seconds < 31536000) return `${Math.round(seconds / 86400)} days`;
  if (seconds < 31536000 * 100) return `${Math.round(seconds / 31536000)} years`;
  if (seconds < 31536000 * 1000000) return `${Math.round(seconds / 31536000 / 1000)} thousand years`;
  if (seconds < 31536000 * 1000000000) return `${Math.round(seconds / 31536000 / 1000000)} million years`;
  return 'billions of years';
}
