const express = require('express');
const multer = require('multer');
const path = require('path');
const fs = require('fs').promises;
const helmet = require('helmet');
const cors = require('cors');
const rateLimit = require('rate-limiter-flexible');
const winston = require('winston');
const { v4: uuidv4 } = require('uuid');
require('dotenv').config({ path: path.join(__dirname, '.env') });

// Import custom modules
const APKAnalyzer = require('./services/apkAnalyzer');
const SecurityScanner = require('./services/securityScanner');
const ThreatIntelligence = require('./services/threatIntelligence');
const DatabaseService = require('./services/database');

const app = express();
const PORT = process.env.PORT || 3000;

// Logger configuration
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  transports: [
    new winston.transports.File({ filename: 'logs/error.log', level: 'error' }),
    new winston.transports.File({ filename: 'logs/combined.log' }),
    new winston.transports.Console()
  ]
});

// Rate limiting
const rateLimiter = new rateLimit.RateLimiterMemory({
  keyPrefix: 'apk_scan',
  points: 10, // 10 requests
  duration: 60, // per 60 seconds
});

// Middleware
app.use(helmet());
app.use(cors({
  origin: process.env.ALLOWED_ORIGINS?.split(',') || ['http://localhost:3000', 'http://127.0.0.1:5500'],
  methods: ['GET', 'POST'],
  maxAge: 86400
}));
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true }));

// File upload configuration
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, 'uploads/');
  },
  filename: (req, file, cb) => {
    const uniqueName = `${Date.now()}-${Math.round(Math.random() * 1E9)}.apk`;
    cb(null, uniqueName);
  }
});

const upload = multer({
  storage: storage,
  limits: {
    fileSize: 220 * 1024 * 1024, // 220MB
    files: 1
  },
  fileFilter: (req, file, cb) => {
    if (file.mimetype === 'application/vnd.android.package-archive' || 
        file.originalname.endsWith('.apk')) {
      cb(null, true);
    } else {
      cb(new Error('Only APK files are allowed'), false);
    }
  }
});

// Initialize services
let apkAnalyzer, securityScanner, threatIntel, database;

async function initializeServices() {
  try {
    apkAnalyzer = new APKAnalyzer();
    securityScanner = new SecurityScanner();
    threatIntel = new ThreatIntelligence();
    database = new DatabaseService();
    
    await threatIntel.initialize();
    await database.connect();
    
    logger.info('All services initialized successfully');
  } catch (error) {
    logger.error('Failed to initialize services:', error);
    process.exit(1);
  }
}

// Rate limiting middleware
const rateLimitMiddleware = async (req, res, next) => {
  try {
    await rateLimiter.consume(req.ip);
    next();
  } catch (rejRes) {
    res.status(429).json({
      error: 'Too many requests',
      retryAfter: Math.round(rejRes.msBeforeNext) || 1000
    });
  }
};

// Main APK scanning endpoint
app.post('/api/scan-apk', rateLimitMiddleware, upload.single('apk'), async (req, res) => {
  const scanId = uuidv4();
  let filePath = null;
  
  try {
    if (!req.file) {
      return res.status(400).json({ 
        success: false, 
        error: 'No APK file provided',
        message: 'Please select a valid APK file to scan'
      });
    }
    
    filePath = req.file.path;
    const filename = req.file.originalname;
    logger.info(`Starting APK scan - ID: ${scanId}, File: ${filename}`);
    
    // Initialize scan result
    const scanResult = {
      scanId,
      filename: filename,
      timestamp: new Date(),
      riskLevel: 'unknown',
      isFake: false,
      confidence: 0,
      threats: [],
      analysis: {},
      recommendations: []
    };
    
    // Step 1: Basic APK Analysis
    logger.info(`${scanId}: Starting basic APK analysis`);
    const apkInfo = await apkAnalyzer.analyzeAPK(filePath);
    scanResult.analysis.basic = apkInfo;
    
    // Step 2: Security Scanning
    logger.info(`${scanId}: Starting security scan`);
    const securityResults = await securityScanner.scanAPK(filePath, apkInfo);
    scanResult.analysis.security = securityResults;
    
    // Step 3: Banking App Detection
    logger.info(`${scanId}: Checking banking app characteristics`);
    const bankingAnalysis = await apkAnalyzer.analyzeBankingCharacteristics(filePath, apkInfo);
    scanResult.analysis.banking = bankingAnalysis;
    
    // Step 4: Threat Intelligence Check
    logger.info(`${scanId}: Running threat intelligence checks`);
    const threatResults = await threatIntel.checkAPK(apkInfo);
    scanResult.analysis.threats = threatResults;
    
    // Step 5: Machine Learning Detection (if available)
    if (process.env.ML_DETECTION_ENABLED === 'true') {
      logger.info(`${scanId}: Running ML detection`);
      const mlResults = await securityScanner.mlDetection(filePath, apkInfo);
      scanResult.analysis.ml = mlResults;
    }
    
    // Calculate final risk assessment
    const riskAssessment = calculateRiskLevel(scanResult);
    scanResult.riskLevel = riskAssessment.level;
    scanResult.isFake = riskAssessment.isFake;
    scanResult.confidence = riskAssessment.confidence;
    scanResult.threats = riskAssessment.threats;
    scanResult.recommendations = riskAssessment.recommendations;
    
    // Save to database
    try {
      await database.saveScanResult(scanResult);
    } catch (dbError) {
      logger.error('Failed to save scan result to database:', dbError);
    }
    
    logger.info(`${scanId}: Scan completed - Risk: ${scanResult.riskLevel}, Fake: ${scanResult.isFake}`);
    
    // Send response
    res.json({
      success: true,
      scanId,
      result: {
        riskLevel: scanResult.riskLevel,
        isFake: scanResult.isFake,
        confidence: scanResult.confidence,
        threats: scanResult.threats,
        recommendations: scanResult.recommendations,
        summary: generateScanSummary(scanResult)
      }
    });
    
  } catch (error) {
    logger.error(`${scanId}: Scan failed: ${error.message}`, { stack: error.stack });
    
    if (!res.headersSent) {
      return res.status(500).json({
        success: false,
        scanId,
        error: 'Scan failed',
        message: process.env.NODE_ENV === 'development' ? error.message : 'Internal server error'
      });
    }
  } finally {
    // Cleanup the uploaded file
    if (filePath) {
      try {
        await fs.unlink(filePath);
        logger.info(`Cleaned up file: ${filePath}`);
      } catch (cleanupError) {
        logger.error(`Failed to cleanup file ${filePath}:`, cleanupError);
      }
    }
  }
});

// Health check endpoint
app.get('/api/health', (req, res) => {
  res.json({
    status: 'healthy',
    timestamp: new Date(),
    services: {
      apkAnalyzer: apkAnalyzer ? 'initialized' : 'not initialized',
      securityScanner: securityScanner ? 'initialized' : 'not initialized',
      threatIntel: threatIntel ? 'initialized' : 'not initialized',
      database: database ? 'initialized' : 'not initialized'
    }
  });
});

// Get scan result endpoint
app.get('/api/scan-result/:scanId', async (req, res) => {
  try {
    const scanId = req.params.scanId;
    const result = await database.getScanResult(scanId);
    
    if (!result) {
      return res.status(404).json({
        success: false,
        error: 'Scan result not found'
      });
    }
    
    res.json({
      success: true,
      result: result
    });
    
  } catch (error) {
    logger.error('Failed to retrieve scan result:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to retrieve scan result'
    });
  }
});

// Risk calculation function
function calculateRiskLevel(scanResult) {
    const { basic, security, banking, threats, ml } = scanResult.analysis;
    let riskScore = 0;
    let confidence = 0;
    let detectedThreats = [];
    let recommendations = [];
    
    // Basic APK analysis scoring
    if (basic) {
      if (basic.isDebuggable) riskScore += 10;
      if (basic.allowBackup) riskScore += 5;
      if (basic.hasNativeCode) riskScore += 5;
    }
    
    // Security analysis scoring
    if (security) {
      if (security.maliciousPermissions > 0) {
        riskScore += security.maliciousPermissions * 15;
        detectedThreats.push(`${security.maliciousPermissions} dangerous permissions detected`);
      }
      if (security.suspiciousStrings > 0) {
        riskScore += security.suspiciousStrings * 10;
        detectedThreats.push(`${security.suspiciousStrings} suspicious code patterns found`);
      }
      if (security.obfuscated) {
        riskScore += 20;
        detectedThreats.push('Code obfuscation detected');
      }
      if (security.packedExecutables > 0) {
        riskScore += security.packedExecutables * 25;
        detectedThreats.push(`${security.packedExecutables} packed executables found`);
      }
    }
    
    // Banking characteristics scoring
    if (banking) {
      if (banking.imitatesBankingApp) {
        riskScore += 50;
        detectedThreats.push('Banking app impersonation detected');
      }
      if (banking.hasPhishingIndicators) {
        riskScore += 40;
        detectedThreats.push('Phishing indicators found');
      }
      if (banking.suspiciousNetworking) {
        riskScore += 30;
        detectedThreats.push('Suspicious network behavior');
      }
    }
    
    // Threat intelligence scoring
    if (threats) {
      if (threats.knownMalware) {
        riskScore += 100;
        detectedThreats.push('Known malware signature detected');
      }
      if (threats.suspiciousDomains > 0) {
        riskScore += threats.suspiciousDomains * 20;
        detectedThreats.push('Communicates with suspicious domains');
      }
      if (threats.bankingTrojanMatch) {
        riskScore += 80;
        detectedThreats.push(`Banking trojan detected: ${threats.bankingTrojanMatch}`);
      }
    }
    
    // ML detection scoring (if available)
    if (ml && ml.malwareProbability > 0.7) {
      riskScore += ml.malwareProbability * 50;
      detectedThreats.push('AI-based malware detection triggered');
    }
    
    // Determine risk level and fake status
    let level, isFake;
    if (riskScore >= 80) {
      level = 'critical';
      isFake = true;
      confidence = Math.min(95, 70 + riskScore * 0.3);
    } else if (riskScore >= 50) {
      level = 'high';
      isFake = riskScore >= 60;
      confidence = Math.min(85, 60 + riskScore * 0.4);
    } else if (riskScore >= 25) {
      level = 'medium';
      isFake = false;
      confidence = Math.min(75, 50 + riskScore * 0.5);
    } else if (riskScore >= 10) {
      level = 'low';
      isFake = false;
      confidence = Math.min(65, 40 + riskScore * 0.6);
    } else {
      level = 'minimal';
      isFake = false;
      confidence = Math.min(60, 30 + riskScore);
    }
    
    // Generate recommendations
    if (isFake) {
      recommendations.push('DO NOT INSTALL - This appears to be a fake banking application');
      recommendations.push('Report this APK to your bank and security authorities');
    } else if (level === 'high' || level === 'medium') {
      recommendations.push('Exercise caution - review all permissions before installation');
    }
    
    if (security && security.maliciousPermissions > 0) {
      recommendations.push('Review app permissions carefully before installation');
    }
    if (banking && banking.suspiciousNetworking) {
      recommendations.push('This app may transmit sensitive data to unauthorized servers');
    }
    
    // Add default recommendations if none exist
    if (recommendations.length === 0) {
      if (level === 'minimal' || level === 'low') {
        recommendations.push('App appears relatively safe, but always verify from official sources');
      } else {
        recommendations.push('Consider using official app stores for banking applications');
      }
    }
    
    return {
      level,
      isFake,
      confidence: Math.round(confidence),
      threats: detectedThreats,
      recommendations,
      riskScore: Math.round(riskScore)
    };
}

function generateScanSummary(scanResult) {
  const { riskLevel, isFake, threats } = scanResult;
  
  if (isFake) {
    return `DANGER: This APK appears to be a fake banking application with ${riskLevel} risk level. ${threats.length} threats detected.`;
  } else {
    return `This APK appears legitimate with ${riskLevel} risk level. ${threats.length} potential issues found.`;
  }
}

// Error handling middleware
app.use((error, req, res, next) => {
  logger.error('Unhandled error:', error);
  if (res.headersSent) {
    return next(error);
  }
  
  if (error instanceof multer.MulterError) {
    if (error.code === 'LIMIT_FILE_SIZE') {
      return res.status(413).json({
        success: false,
        error: 'File too large',
        message: 'Maximum file size is 220MB'
      });
    }
  }
  
  res.status(500).json({
    success: false,
    error: 'Internal server error',
    message: process.env.NODE_ENV === 'development' ? error.message : 'Something went wrong'
  });
});

// Start server
async function startServer() {
  try {
    await initializeServices();
    
    app.listen(PORT, () => {
      logger.info(`APK Security Scanner running on port ${PORT}`);
      logger.info(`Environment: ${process.env.NODE_ENV || 'development'}`);
      logger.info(`CORS allowed origins: ${process.env.ALLOWED_ORIGINS || 'http://localhost:3000'}`);
    });
  } catch (error) {
    logger.error('Failed to start server:', error);
    process.exit(1);
  }
}

// Handle graceful shutdown
process.on('SIGINT', async () => {
  logger.info('Received SIGINT, shutting down gracefully...');
  if (database) {
    await database.disconnect();
  }
  process.exit(0);
});

startServer();

module.exports = app;