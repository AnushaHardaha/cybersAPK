
# Cryptera APK Security Scanner

Cryptera is an advanced APK security scanner designed to detect fake banking applications and analyze Android APK files for malicious behavior. The system provides comprehensive security analysis including permission analysis, threat intelligence, and machine learning-based detection.

## Features

- **APK Analysis**: Deep analysis of Android APK files including manifest parsing, certificate extraction, and DEX file analysis
- **Banking App Detection**: Specialized detection for fake banking applications using pattern matching and behavioral analysis
- **Security Scanning**: Comprehensive security analysis including permission analysis, string analysis, and obfuscation detection
- **Threat Intelligence**: Integration with VirusTotal and MalwareBazaar for real-time threat intelligence
- **Machine Learning Detection**: AI-powered malware detection capabilities
- **RESTful API**: Easy-to-use REST API for programmatic access
- **Web Interface**: User-friendly web interface for manual APK uploads and analysis

## Technology Stack

- **Backend**: Node.js, Express.js
- **Database**: MongoDB (optional)
- **Security**: Helmet, CORS, Rate Limiting
- **File Processing**: Multer, yauzl, xml2js
- **Threat Intelligence**: VirusTotal API, MalwareBazaar API
- **Logging**: Winston
- **Frontend**: HTML5, CSS3, JavaScript

## Prerequisites

- Node.js (version 16.0.0 or higher)
- npm (Node Package Manager)
- Optional: MongoDB for storing scan results
- Optional: Android SDK Build Tools for advanced APK parsing

## Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/AnushaHardaha/APKDetector.git
   cd cybershield
   ```

2. **Install dependencies**
   ```bash
   npm install
   ```

3. **Configure environment variables**
   ```bash
   cp .env.example .env
   ```
   Edit the `.env` file with your API keys and configuration.

4. **Create required directories**
   ```bash
   mkdir -p uploads logs data
   ```

## Configuration

### Environment Variables

Copy `.env.example` to `.env` and configure the following variables:

- `VIRUSTOTAL_API_KEY`: Your VirusTotal API key (optional but recommended)
- `MALWAREBAZAAR_API_KEY`: Your MalwareBazaar API key (optional but recommended)
- `ABUSEIPDB_API_KEY`: Your AbuseIPDB API key (optional)
- `PORT`: Server port (default: 3000)
- `NODE_ENV`: Environment (development/production)
<!-- - `ALLOWED_ORIGINS`: CORS allowed origins
- `ML_DETECTION_ENABLED`: Enable ML detection (true/false)
- `YARA_ENABLED`: Enable YARA rule matching (true/false) -->

### API Keys Setup

1. **VirusTotal API Key**
   - Visit [VirusTotal](https://www.virustotal.com/gui/join-us)
   - Create an account and get your API key
   - Add it to your `.env` file

2. **MalwareBazaar API Key**
   - Visit [abuse.ch Authentication Portal](https://abuse.ch/api/)
   - Create an account and get your API key
   - Add it to your `.env` file

## Running the Server

### Development Mode
```bash
npm run dev
```

### Production Mode
```bash
npm start
```

### Using PM2 (Recommended for Production)
```bash
npm install -g pm2
pm2 start server.js --name cybershield
pm2 startup
pm2 save
```

## API Endpoints

### Scan APK File
```http
POST /api/scan-apk
Content-Type: multipart/form-data

Body: 
- apk: APK file (max 220MB)
```

**Response:**
```json
{
  "success": true,
  "scanId": "uuid-here",
  "result": {
    "riskLevel": "high|medium|low|minimal|critical",
    "isFake": true,
    "confidence": 85,
    "threats": ["Banking app impersonation detected"],
    "recommendations": ["DO NOT INSTALL - This appears to be a fake banking application"],
    "summary": "DANGER: This APK appears to be a fake banking application..."
  }
}
```

### Health Check
```http
GET /api/health
```

**Response:**
```json
{
  "status": "healthy",
  "timestamp": "2025-08-27T10:30:00.000Z",
  "services": {
    "threatIntel": "initialized"
  }
}
```

## Usage Examples

### Using cURL
```bash
# Scan an APK file
curl -X POST -F "apk=@sample.apk" http://localhost:3000/api/scan-apk

# Check server health
curl http://localhost:3000/api/health
```

### Using the Web Interface
1. Start the server
2. Open your browser and navigate to the frontend HTML file
3. Upload an APK file
4. View the analysis results

## Development

### Project Structure
```
cybershield/
└── backend/
    ├── services/           # Core service modules
    │   ├── apkAnalyzer.js     # APK analysis logic
    │   ├── securityScanner.js # Security scanning logic
    │   ├── threatIntelligence.js # Threat intelligence integration
    │   └── database.js        # Database operations
    ├── uploads/            # Temporary file storage
    ├── logs/              # Application logs
    ├── data/              # Static data files
    ├── server.js          # Main server file
    ├── package.json       # Dependencies and scripts
    └── README.md          # This file
```

### Available Scripts
```bash
npm run dev      # Start in development mode with nodemon
npm start        # Start in production mode
npm test         # Run tests
npm run scan     # Run standalone APK scanner
```

### Contributing
1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## Security Features

### Rate Limiting
- 10 requests per minute per IP address
- Configurable rate limits for different endpoints

### File Validation
- Strict APK file validation
- File size limits (max 220MB)
- MIME type checking

### Security Headers
- Helmet.js for security headers
- CORS configuration
- Input validation and sanitization


## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- VirusTotal for threat intelligence API
- MalwareBazaar for malware sample database
- Android security research community
- National Cryptera Hackathon 2025

## Support

For support and questions, please open an issue on GitHub or contact the development team.

---

<!-- **Made at National Cryptera Hackathon 2025 🚀 | Team CyberShield** -->
=======
# CyberShield APK Security Scanner

CyberShield is an advanced APK security scanner designed to detect fake banking applications and analyze Android APK files for malicious behavior. The system provides comprehensive security analysis including permission analysis, threat intelligence, and machine learning-based detection.

## Features

- **APK Analysis**: Deep analysis of Android APK files including manifest parsing, certificate extraction, and DEX file analysis
- **Banking App Detection**: Specialized detection for fake banking applications using pattern matching and behavioral analysis
- **Security Scanning**: Comprehensive security analysis including permission analysis, string analysis, and obfuscation detection
- **Threat Intelligence**: Integration with VirusTotal and MalwareBazaar for real-time threat intelligence
- **Machine Learning Detection**: AI-powered malware detection capabilities
- **RESTful API**: Easy-to-use REST API for programmatic access
- **Web Interface**: User-friendly web interface for manual APK uploads and analysis

## Technology Stack

- **Backend**: Node.js, Express.js
- **Database**: MongoDB (optional)
- **Security**: Helmet, CORS, Rate Limiting
- **File Processing**: Multer, yauzl, xml2js
- **Threat Intelligence**: VirusTotal API, MalwareBazaar API
- **Logging**: Winston
- **Frontend**: HTML5, CSS3, JavaScript

## Prerequisites

- Node.js (version 16.0.0 or higher)
- npm (Node Package Manager)
- Optional: MongoDB for storing scan results
- Optional: Android SDK Build Tools for advanced APK parsing

## Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/AnushaHardaha/APKDetector.git
   cd cybershield
   ```

2. **Install dependencies**
   ```bash
   npm install
   ```

3. **Configure environment variables**
   ```bash
   cp .env.example .env
   ```
   Edit the `.env` file with your API keys and configuration.

4. **Create required directories**
   ```bash
   mkdir -p uploads logs data
   ```

## Configuration

### Environment Variables

Copy `.env.example` to `.env` and configure the following variables:

- `VIRUSTOTAL_API_KEY`: Your VirusTotal API key (optional but recommended)
- `MALWAREBAZAAR_API_KEY`: Your MalwareBazaar API key (optional but recommended)
- `ABUSEIPDB_API_KEY`: Your AbuseIPDB API key (optional)
- `PORT`: Server port (default: 3000)
- `NODE_ENV`: Environment (development/production)
<!-- - `ALLOWED_ORIGINS`: CORS allowed origins
- `ML_DETECTION_ENABLED`: Enable ML detection (true/false)
- `YARA_ENABLED`: Enable YARA rule matching (true/false) -->

### API Keys Setup

1. **VirusTotal API Key**
   - Visit [VirusTotal](https://www.virustotal.com/gui/join-us)
   - Create an account and get your API key
   - Add it to your `.env` file

2. **MalwareBazaar API Key**
   - Visit [abuse.ch Authentication Portal](https://abuse.ch/api/)
   - Create an account and get your API key
   - Add it to your `.env` file

## Running the Server

### Development Mode
```bash
npm run dev
```

### Production Mode
```bash
npm start
```

### Using PM2 (Recommended for Production)
```bash
npm install -g pm2
pm2 start server.js --name cybershield
pm2 startup
pm2 save
```

## API Endpoints

### Scan APK File
```http
POST /api/scan-apk
Content-Type: multipart/form-data

Body: 
- apk: APK file (max 220MB)
```

**Response:**
```json
{
  "success": true,
  "scanId": "uuid-here",
  "result": {
    "riskLevel": "high|medium|low|minimal|critical",
    "isFake": true,
    "confidence": 85,
    "threats": ["Banking app impersonation detected"],
    "recommendations": ["DO NOT INSTALL - This appears to be a fake banking application"],
    "summary": "DANGER: This APK appears to be a fake banking application..."
  }
}
```

### Health Check
```http
GET /api/health
```

**Response:**
```json
{
  "status": "healthy",
  "timestamp": "2025-08-27T10:30:00.000Z",
  "services": {
    "threatIntel": "initialized"
  }
}
```

## Usage Examples

### Using cURL
```bash
# Scan an APK file
curl -X POST -F "apk=@sample.apk" http://localhost:3000/api/scan-apk

# Check server health
curl http://localhost:3000/api/health
```

### Using the Web Interface
1. Start the server
2. Open your browser and navigate to the frontend HTML file
3. Upload an APK file
4. View the analysis results

## Development

### Project Structure
```
cybershield/
└── backend/
    ├── services/           # Core service modules
    │   ├── apkAnalyzer.js     # APK analysis logic
    │   ├── securityScanner.js # Security scanning logic
    │   ├── threatIntelligence.js # Threat intelligence integration
    │   └── database.js        # Database operations
    ├── uploads/            # Temporary file storage
    ├── logs/              # Application logs
    ├── data/              # Static data files
    ├── server.js          # Main server file
    ├── package.json       # Dependencies and scripts
    └── README.md          # This file
```

### Available Scripts
```bash
npm run dev      # Start in development mode with nodemon
npm start        # Start in production mode
npm test         # Run tests
npm run scan     # Run standalone APK scanner
```

### Contributing
1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## Security Features

### Rate Limiting
- 10 requests per minute per IP address
- Configurable rate limits for different endpoints

### File Validation
- Strict APK file validation
- File size limits (max 220MB)
- MIME type checking

### Security Headers
- Helmet.js for security headers
- CORS configuration
- Input validation and sanitization


## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- VirusTotal for threat intelligence API
- MalwareBazaar for malware sample database
- Android security research community
- National Cryptera Hackathon 2025

## Support

For support and questions, please open an issue on GitHub or contact the development team.

---

<!-- **Made at National Cryptera Hackathon 2025 🚀 | Team CyberShield** -->
>>>>>>> a7f6e2d73e08afd70cbe6949c0b5fe85fb4b02f0
