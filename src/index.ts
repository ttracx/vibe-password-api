import express, { Request, Response, NextFunction } from 'express';
import cors from 'cors';
import helmet from 'helmet';
import { generatePassword, generateBatch, analyzeStrength, GenerateOptions } from './password';

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(helmet());
app.use(cors());
app.use(express.json());

// Request logging
app.use((req: Request, _res: Response, next: NextFunction) => {
  console.log(`${new Date().toISOString()} ${req.method} ${req.path}`);
  next();
});

/**
 * Health check endpoint
 */
app.get('/health', (_req: Request, res: Response) => {
  res.json({
    status: 'healthy',
    timestamp: new Date().toISOString(),
    version: process.env.npm_package_version || '1.0.0',
    uptime: process.uptime(),
  });
});

/**
 * Generate a single password
 * 
 * POST /generate
 * Body: {
 *   length?: number (8-128, default: 16)
 *   uppercase?: boolean (default: true)
 *   lowercase?: boolean (default: true)
 *   numbers?: boolean (default: true)
 *   symbols?: boolean (default: true)
 *   excludeAmbiguous?: boolean (default: false)
 * }
 */
app.post('/generate', (req: Request, res: Response) => {
  try {
    const options = validateGenerateOptions(req.body);
    const password = generatePassword(options);
    
    res.json({
      success: true,
      password,
      options: {
        length: options.length ?? 16,
        uppercase: options.uppercase ?? true,
        lowercase: options.lowercase ?? true,
        numbers: options.numbers ?? true,
        symbols: options.symbols ?? true,
        excludeAmbiguous: options.excludeAmbiguous ?? false,
      },
    });
  } catch (error) {
    res.status(400).json({
      success: false,
      error: error instanceof Error ? error.message : 'Unknown error',
    });
  }
});

/**
 * Generate multiple passwords
 * 
 * POST /batch
 * Body: {
 *   count: number (1-100)
 *   ...GenerateOptions
 * }
 */
app.post('/batch', (req: Request, res: Response) => {
  try {
    const { count = 5, ...rest } = req.body;
    
    if (typeof count !== 'number' || count < 1 || count > 100) {
      throw new Error('Count must be between 1 and 100');
    }
    
    const options = validateGenerateOptions(rest);
    const passwords = generateBatch(count, options);
    
    res.json({
      success: true,
      count: passwords.length,
      passwords,
      options: {
        length: options.length ?? 16,
        uppercase: options.uppercase ?? true,
        lowercase: options.lowercase ?? true,
        numbers: options.numbers ?? true,
        symbols: options.symbols ?? true,
        excludeAmbiguous: options.excludeAmbiguous ?? false,
      },
    });
  } catch (error) {
    res.status(400).json({
      success: false,
      error: error instanceof Error ? error.message : 'Unknown error',
    });
  }
});

/**
 * Analyze password strength
 * 
 * POST /strength
 * Body: {
 *   password: string
 * }
 */
app.post('/strength', (req: Request, res: Response) => {
  try {
    const { password } = req.body;
    
    if (!password || typeof password !== 'string') {
      throw new Error('Password is required');
    }
    
    if (password.length > 1000) {
      throw new Error('Password too long (max 1000 characters)');
    }
    
    const result = analyzeStrength(password);
    
    res.json({
      success: true,
      ...result,
    });
  } catch (error) {
    res.status(400).json({
      success: false,
      error: error instanceof Error ? error.message : 'Unknown error',
    });
  }
});

/**
 * API documentation
 */
app.get('/', (_req: Request, res: Response) => {
  res.json({
    name: 'Vibe Password API',
    version: '1.0.0',
    description: 'Secure password generation and strength analysis API',
    endpoints: {
      'GET /health': 'Health check',
      'POST /generate': 'Generate a single password',
      'POST /batch': 'Generate multiple passwords',
      'POST /strength': 'Analyze password strength',
    },
    documentation: 'https://github.com/ttracx/vibe-password-api',
  });
});

/**
 * 404 handler
 */
app.use((_req: Request, res: Response) => {
  res.status(404).json({
    success: false,
    error: 'Not found',
  });
});

/**
 * Error handler
 */
app.use((err: Error, _req: Request, res: Response, _next: NextFunction) => {
  console.error('Unhandled error:', err);
  res.status(500).json({
    success: false,
    error: 'Internal server error',
  });
});

/**
 * Validate and sanitize generate options
 */
function validateGenerateOptions(body: Record<string, unknown>): GenerateOptions {
  const options: GenerateOptions = {};
  
  if (body.length !== undefined) {
    const length = Number(body.length);
    if (isNaN(length) || length < 4 || length > 128) {
      throw new Error('Length must be between 4 and 128');
    }
    options.length = length;
  }
  
  if (body.uppercase !== undefined) {
    options.uppercase = Boolean(body.uppercase);
  }
  
  if (body.lowercase !== undefined) {
    options.lowercase = Boolean(body.lowercase);
  }
  
  if (body.numbers !== undefined) {
    options.numbers = Boolean(body.numbers);
  }
  
  if (body.symbols !== undefined) {
    options.symbols = Boolean(body.symbols);
  }
  
  if (body.excludeAmbiguous !== undefined) {
    options.excludeAmbiguous = Boolean(body.excludeAmbiguous);
  }
  
  return options;
}

// Start server
app.listen(PORT, () => {
  console.log(`🔐 Vibe Password API running on port ${PORT}`);
  console.log(`   Health: http://localhost:${PORT}/health`);
  console.log(`   Docs:   http://localhost:${PORT}/`);
});
