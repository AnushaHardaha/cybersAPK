const winston = require('winston');

// Simple in-memory database service (for development)
// In production, replace with MongoDB implementation
class DatabaseService {
  constructor() {
    this.scanResults = new Map();
    this.connected = false;
    this.logger = winston.createLogger({
      level: 'info',
      format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.json()
      ),
      transports: [
        new winston.transports.Console()
      ]
    });
  }

  async connect() {
    try {
      // For now, just use in-memory storage
      // In production, you would connect to MongoDB here:
      /*
      if (process.env.MONGODB_CONNECTION) {
        const { MongoClient } = require('mongodb');
        this.client = new MongoClient(process.env.MONGODB_CONNECTION);
        await this.client.connect();
        this.db = this.client.db(process.env.DB_NAME || 'apk_scanner');
        await this.createIndexes();
        this.logger.info('Connected to MongoDB');
      } else {
        this.logger.info('Using in-memory database (no MongoDB configured)');
      }
      */
      
      this.logger.info('Using in-memory database (development mode)');
      this.connected = true;
      return true;
    } catch (error) {
      this.logger.error('Database connection failed:', error);
      throw error;
    }
  }

  async createIndexes() {
    // MongoDB index creation would go here
    try {
      if (this.db) {
        const scanResults = this.db.collection('scan_results');
        await scanResults.createIndex({ scanId: 1 }, { unique: true });
        await scanResults.createIndex({ 'fileHashes.sha256': 1 });
        await scanResults.createIndex({ timestamp: -1 });
        this.logger.info('Database indexes created');
      }
    } catch (error) {
      this.logger.error('Index creation failed:', error);
    }
  }

  async saveScanResult(scanResult) {
    try {
      if (!this.connected) {
        this.logger.warn('Database not connected, skipping save');
        return null;
      }

      // In-memory storage
      this.scanResults.set(scanResult.scanId, {
        ...scanResult,
        savedAt: new Date()
      });

      this.logger.info(`Saved scan result: ${scanResult.scanId} (${scanResult.filename})`);
      
      // MongoDB storage would be:
      /*
      if (this.db) {
        const collection = this.db.collection('scan_results');
        const result = await collection.insertOne(scanResult);
        return result.insertedId;
      }
      */
      
      return scanResult.scanId;
    } catch (error) {
      this.logger.error('Failed to save scan result:', error);
      throw error;
    }
  }

  async getScanResult(scanId) {
    try {
      if (!this.connected) {
        return null;
      }

      // In-memory retrieval
      const result = this.scanResults.get(scanId);
      
      // MongoDB retrieval would be:
      /*
      if (this.db) {
        const collection = this.db.collection('scan_results');
        return await collection.findOne({ scanId });
      }
      */
      
      return result || null;
    } catch (error) {
      this.logger.error('Failed to get scan result:', error);
      throw error;
    }
  }

  async getAllScanResults(limit = 100) {
    try {
      if (!this.connected) {
        return [];
      }

      // In-memory retrieval
      const results = Array.from(this.scanResults.values())
        .sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp))
        .slice(0, limit);
      
      return results;
    } catch (error) {
      this.logger.error('Failed to get scan results:', error);
      throw error;
    }
  }

  async getStats() {
    try {
      if (!this.connected) {
        return { total: 0, fake: 0, safe: 0 };
      }

      const results = Array.from(this.scanResults.values());
      const total = results.length;
      const fake = results.filter(r => r.isFake).length;
      const safe = total - fake;
      
      return { total, fake, safe };
    } catch (error) {
      this.logger.error('Failed to get stats:', error);
      return { total: 0, fake: 0, safe: 0 };
    }
  }

  async disconnect() {
    try {
      if (this.client) {
        await this.client.close();
      }
      this.connected = false;
      this.logger.info('Database disconnected');
    } catch (error) {
      this.logger.error('Database disconnect failed:', error);
    }
  }
}

module.exports = DatabaseService;