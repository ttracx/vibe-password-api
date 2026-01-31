# 🔐 Vibe Password API

A secure, cryptographically-sound password generation API built with Express and TypeScript. Uses Node.js `crypto` module for true randomness.

[![Deploy to Render](https://render.com/images/deploy-to-render-button.svg)](https://render.com/deploy?repo=https://github.com/ttracx/vibe-password-api)

## Features

- 🎲 **Cryptographically Secure** - Uses `crypto.randomInt()` for true randomness
- ⚡ **Fast & Lightweight** - Minimal dependencies, optimized for speed
- 🛡️ **Security Hardened** - Helmet, input validation, rate limiting ready
- 🐳 **Docker Ready** - Multi-stage build with non-root user
- 📊 **Strength Analysis** - Entropy calculation and crack time estimation

## API Endpoints

### `GET /health`

Health check endpoint.

```bash
curl https://your-api.onrender.com/health
```

Response:
```json
{
  "status": "healthy",
  "timestamp": "2024-01-15T10:30:00.000Z",
  "version": "1.0.0",
  "uptime": 3600
}
```

### `POST /generate`

Generate a single password.

```bash
curl -X POST https://your-api.onrender.com/generate \
  -H "Content-Type: application/json" \
  -d '{
    "length": 20,
    "uppercase": true,
    "lowercase": true,
    "numbers": true,
    "symbols": true,
    "excludeAmbiguous": false
  }'
```

**Options:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `length` | number | 16 | Password length (4-128) |
| `uppercase` | boolean | true | Include A-Z |
| `lowercase` | boolean | true | Include a-z |
| `numbers` | boolean | true | Include 0-9 |
| `symbols` | boolean | true | Include !@#$%^&*... |
| `excludeAmbiguous` | boolean | false | Exclude Il1O0 |

Response:
```json
{
  "success": true,
  "password": "K#9xLm$pQ2wR&vN!",
  "options": {
    "length": 16,
    "uppercase": true,
    "lowercase": true,
    "numbers": true,
    "symbols": true,
    "excludeAmbiguous": false
  }
}
```

### `POST /batch`

Generate multiple passwords at once.

```bash
curl -X POST https://your-api.onrender.com/batch \
  -H "Content-Type: application/json" \
  -d '{
    "count": 5,
    "length": 12
  }'
```

**Options:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `count` | number | 5 | Number of passwords (1-100) |
| *...all generate options* | | | |

Response:
```json
{
  "success": true,
  "count": 5,
  "passwords": [
    "K#9xLm$pQ2wR",
    "aB3@nM!qR7xP",
    "Zv&8kL#2mNpQ",
    "wX4$jH@9sTfR",
    "bN6%cV!3yUiO"
  ],
  "options": { ... }
}
```

### `POST /strength`

Analyze password strength.

```bash
curl -X POST https://your-api.onrender.com/strength \
  -H "Content-Type: application/json" \
  -d '{"password": "MyP@ssw0rd123!"}'
```

Response:
```json
{
  "success": true,
  "password": "MyP***********",
  "score": 8,
  "level": "strong",
  "feedback": ["Password looks strong!"],
  "entropy": 91.73,
  "crackTime": "billions of years"
}
```

**Strength Levels:**
- `very_weak` (0-2)
- `weak` (3-4)
- `fair` (5-6)
- `strong` (7-8)
- `very_strong` (9-10)

## Local Development

```bash
# Install dependencies
npm install

# Run in development mode
npm run dev

# Build for production
npm run build

# Start production server
npm start
```

## Docker

```bash
# Build image
docker build -t vibe-password-api .

# Run container
docker run -p 3000:3000 vibe-password-api
```

## Deploy to Render

1. Fork this repository
2. Connect your GitHub account to Render
3. Create a new Web Service from the repo
4. Render will automatically detect the `render.yaml` and deploy

Or use the deploy button above!

## Security Considerations

- Uses `crypto.randomInt()` for cryptographically secure random numbers
- No passwords are logged or stored
- Input validation on all endpoints
- Helmet.js for security headers
- Non-root Docker user
- Strength analysis masks input password in response

## License

MIT © 2024
