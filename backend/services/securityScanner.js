const crypto = require('crypto');
const fs = require('fs').promises;
const path = require('path');
const { exec } = require('child_process');
const util = require('util');
const execPromise = util.promisify(exec);
const yauzl = require('yauzl');

class SecurityScanner {
  constructor() {
    this.maliciousPermissions = new Set([
      'android.permission.SEND_SMS',
      // 'android.permission.RECEIVE_SMS', // To Receive OTP
      'android.permission.READ_SMS',
      'android.permission.WRITE_SMS',
      'android.permission.RECEIVE_MMS',
      'android.permission.RECEIVE_WAP_PUSH',
      'android.permission.CALL_PHONE',
      'android.permission.PROCESS_OUTGOING_CALLS',
      'android.permission.MODIFY_PHONE_STATE',
      'android.permission.BIND_ACCESSIBILITY_SERVICE',
      'android.permission.BIND_DEVICE_ADMIN',
      'android.permission.SYSTEM_ALERT_WINDOW',
      'android.permission.WRITE_SECURE_SETTINGS',
      'android.permission.INSTALL_PACKAGES',
      'android.permission.DELETE_PACKAGES',
      'android.permission.MOUNT_UNMOUNT_FILESYSTEMS',
      'android.permission.FORMAT_MEDIA',
      'android.permission.RECORD_AUDIO',
      'android.permission.CAMERA',
      'android.permission.READ_CONTACTS',
      'android.permission.WRITE_CONTACTS',
      'android.permission.ACCESS_FINE_LOCATION',
      'android.permission.ACCESS_COARSE_LOCATION'
    ]);
    
    this.suspiciousStrings = [
      // Banking/Financial
      'password', 'pin', 'account', 'balance', 'transfer', 'credit_card',
      'bank_account', 'routing_number', 'ssn', 'social_security',
      
      // Malware indicators
      'keylogger', 'keylog', 'screen_capture', 'screenshot', 'record_screen',
      'steal', 'extract', 'harvest', 'backdoor', 'trojan', 'malware',
      'virus', 'exploit', 'payload', 'shell', 'root', 'su_binary',
      
      // Suspicious networking
      'tcp_socket', 'raw_socket', 'proxy', 'tunnel', 'tor', 'onion',
      'anonymous', 'hide_ip', 'vpn', 'encrypt_traffic',
      
      // SMS/Call interception
      'intercept_sms', 'read_sms', 'forward_sms', 'call_log', 'phone_state',
      'outgoing_calls', 'incoming_calls', 'block_calls', 'redirect_calls',
      
      // Device admin
      'device_admin', 'admin_receiver', 'lock_screen', 'wipe_data',
      'disable_camera', 'force_lock', 'reset_password',
      
      // Accessibility abuse
      'accessibility_service', 'overlay_attack', 'click_jacking',
      'auto_click', 'gesture_recorder', 'ui_automation',
      
      // Anti-analysis
      'anti_vm', 'anti_debug', 'anti_emulator', 'detect_sandbox',
      'obfuscate', 'encrypt_string', 'dynamic_load', 'reflection'
    ];
    
    this.phishingIndicators = [
      // Fake banking UI elements
      'login_form', 'password_field', 'pin_entry', 'account_input',
      'balance_display', 'transaction_list', 'transfer_form',
      
      // Credential harvesting
      'capture_input', 'log_keystrokes', 'save_credentials', 'steal_password',
      'extract_data', 'send_data', 'upload_info',
      
      // Social engineering
      'urgent_action', 'account_suspended', 'verify_identity', 'security_alert',
      'immediate_response', 'click_here', 'update_info', 'confirm_details'
    ];
    
    this.yaraRules = this.initializeYaraRules();
  }
  
  async scanAPK(apkPath, apkInfo) {
    const results = {
      maliciousPermissions: 0,
      suspiciousStrings: 0,
      phishingIndicators: 0,
      obfuscated: false,
      packedExecutables: 0,
      suspiciousNetworkActivity: false,
      antiAnalysis: false,
      rootingCapabilities: false,
      yaraMatches: [],
      riskScore: 0,
      details: {}
    };
    
    try {
      // 1. Analyze permissions
      results.maliciousPermissions = this.analyzePermissions(apkInfo);
      
      // 2. String analysis
      const stringAnalysis = await this.analyzeStrings(apkPath, apkInfo);
      results.suspiciousStrings = stringAnalysis.suspicious;
      results.phishingIndicators = stringAnalysis.phishing;
      
      // 3. Code analysis
      const codeAnalysis = await this.analyzeCode(apkPath, apkInfo);
      results.obfuscated = codeAnalysis.obfuscated;
      results.antiAnalysis = codeAnalysis.antiAnalysis;
      
      // 4. Native library analysis
      const nativeAnalysis = await this.analyzeNativeLibraries(apkPath);
      results.packedExecutables = nativeAnalysis.packedCount;
      results.rootingCapabilities = nativeAnalysis.hasRootingCapabilities;
      
      // 5. Network analysis
      const networkAnalysis = await this.analyzeNetworkBehavior(apkPath, apkInfo);
      results.suspiciousNetworkActivity = networkAnalysis.suspicious;
      
      // 6. YARA rule matching
      if (process.env.YARA_ENABLED === 'true') {
        results.yaraMatches = await this.runYaraRules(apkPath);
      }
      
      // Calculate risk score
      results.riskScore = this.calculateSecurityRiskScore(results);
      results.details = {
        stringAnalysis,
        codeAnalysis,
        nativeAnalysis,
        networkAnalysis
      };
      
      return results;
      
    } catch (error) {
      console.error('Security scan failed:', error);
      throw new Error(`Security scan failed: ${error.message}`);
    }
  }
  
 analyzePermissions(apkInfo) {
  if (!apkInfo.manifest || !apkInfo.manifest.permissions) {
    return 0;
  }

  // Handle both string arrays and object arrays
  const permissions = Array.isArray(apkInfo.manifest.permissions) 
    ? apkInfo.manifest.permissions.map(perm => {
        if (typeof perm === 'string') return perm;
        if (typeof perm === 'object' && perm.name) return perm.name;
        return String(perm);
      })
    : [];

  console.log("Analyzing permissions:", permissions);
  return permissions.filter(permission =>
    this.maliciousPermissions.has(permission)
  ).length;
}
  async analyzeStrings(apkPath, apkInfo) {
    let suspiciousCount = 0;
    let phishingCount = 0;
    const foundStrings = { suspicious: [], phishing: [] };
    console.log("Starting string analysis");
    try {
      // Analyze DEX files
      if (apkInfo.dexAnalysis) {
        apkInfo.dexAnalysis.forEach(dex => {
          if (dex.stringAnalysis && dex.stringAnalysis.samples) {
            dex.stringAnalysis.samples.forEach(sample => {
              const text = sample.text.toLowerCase();
              
              // Check suspicious strings
              this.suspiciousStrings.forEach(suspicious => {
                if (text.includes(suspicious.toLowerCase())) {
                  suspiciousCount++;
                  foundStrings.suspicious.push({
                    string: suspicious,
                    context: sample.text.substring(0, 100)
                  });
                }
              });
              
              // Check phishing indicators
              this.phishingIndicators.forEach(indicator => {
                if (text.includes(indicator.toLowerCase())) {
                  phishingCount++;
                  foundStrings.phishing.push({
                    string: indicator,
                    context: sample.text.substring(0, 100)
                  });
                }
              });
            });
          }
        });
      }
      
      console.log(`Found ${suspiciousCount} suspicious strings and ${phishingCount} phishing indicators in code.`);
      // Analyze resources and assets
      const resourceStrings = await this.analyzeResourceStrings(apkPath);
      suspiciousCount += resourceStrings.suspicious;
      phishingCount += resourceStrings.phishing;
      
      return {
        suspicious: suspiciousCount,
        phishing: phishingCount,
        details: foundStrings,
        resources: resourceStrings
      };
      
    } catch (error) {
      console.error('String analysis failed:', error);
      return { suspicious: 0, phishing: 0, error: error.message };
    }
  }
  
  async analyzeResourceStrings(apkPath) {
    return new Promise((resolve, reject) => {
      let suspiciousCount = 0;
      let phishingCount = 0;
      console.log("Starting resource string analysis");
      yauzl.open(apkPath, { lazyEntries: true }, (err, zipfile) => {
        if (err) return reject(err);
        
        const resourceFiles = [];
        zipfile.readEntry();
        
        zipfile.on('entry', (entry) => {
          const fileName = entry.fileName.toLowerCase();
          
          // Analyze strings.xml and other resource files
          if (fileName.includes('res/values/') && fileName.endsWith('.xml')) {
            zipfile.openReadStream(entry, (err, readStream) => {
              if (err) {
                zipfile.readEntry();
                return;
              }
              
              const chunks = [];
              readStream.on('data', chunk => chunks.push(chunk));
              readStream.on('end', () => {
                const content = Buffer.concat(chunks).toString('utf8');
                
                this.suspiciousStrings.forEach(suspicious => {
                  if (content.toLowerCase().includes(suspicious.toLowerCase())) {
                    suspiciousCount++;
                  }
                });
                
                this.phishingIndicators.forEach(indicator => {
                  if (content.toLowerCase().includes(indicator.toLowerCase())) {
                    phishingCount++;
                  }
                });
                
                zipfile.readEntry();
              });
            });
          } else {
            zipfile.readEntry();
          }
        });
        
        zipfile.on('end', () => {
          console.log(`Resource string analysis complete: ${suspiciousCount} suspicious, ${phishingCount} phishing`);
          resolve({ suspicious: suspiciousCount, phishing: phishingCount });
        });
      });
    });
  }
  
  async analyzeCode(apkPath, apkInfo) {
    const analysis = {
      obfuscated: false,
      antiAnalysis: false,
      dynamicLoading: false,
      reflectionUsage: false,
      encryptedStrings: false
    };
    
    try {
      if (!apkInfo.dexAnalysis || apkInfo.dexAnalysis.length === 0) {
        return analysis;
      }
      
      // Check for obfuscation indicators
      apkInfo.dexAnalysis.forEach(dex => {
        if (dex.stringAnalysis && dex.stringAnalysis.samples) {
          const strings = dex.stringAnalysis.samples.map(s => s.text);
          
          // Look for obfuscated class/method names (single chars, random strings)
          const shortNames = strings.filter(s => 
            s.length === 1 || (s.length <= 3 && /^[a-zA-Z0-9]+$/.test(s))
          );
          
          if (shortNames.length > 20) {
            analysis.obfuscated = true;
          }
          
          // Check for anti-analysis techniques
          const antiAnalysisStrings = [
            'anti_debug', 'anti_vm', 'anti_emulator', 'detect_sandbox',
            'frida', 'xposed', 'substrate', 'cydia'
          ];
          
          strings.forEach(str => {
            const lowerStr = str.toLowerCase();
            if (antiAnalysisStrings.some(anti => lowerStr.includes(anti))) {
              analysis.antiAnalysis = true;
            }
            
            if (lowerStr.includes('dynamicload') || lowerStr.includes('classloader')) {
              analysis.dynamicLoading = true;
            }
            
            if (lowerStr.includes('reflection') || lowerStr.includes('getmethod')) {
              analysis.reflectionUsage = true;
            }
            
            // Check for encrypted strings (base64, hex patterns)
            if (/^[A-Za-z0-9+/]{20,}={0,2}$/.test(str) || 
                /^[0-9a-fA-F]{32,}$/.test(str)) {
              analysis.encryptedStrings = true;
            }
          });
        }
      });
      
      return analysis;
      
    } catch (error) {
      console.error('Code analysis failed:', error);
      return { ...analysis, error: error.message };
    }
  }
  
  async analyzeNativeLibraries(apkPath) {
    return new Promise((resolve, reject) => {
      const analysis = {
        packedCount: 0,
        hasRootingCapabilities: false,
        suspiciousLibraries: [],
        architectures: new Set()
      };
      
      console.log("Starting native library analysis");
      yauzl.open(apkPath, { lazyEntries: true }, (err, zipfile) => {
        if (err) return reject(err);
        
        zipfile.readEntry();
        zipfile.on('entry', (entry) => {
          const fileName = entry.fileName.toLowerCase();
          
          if (fileName.includes('lib/') && fileName.endsWith('.so')) {
            // Extract architecture
            const archMatch = fileName.match(/lib\/([^\/]+)\//);
            if (archMatch) {
              analysis.architectures.add(archMatch[1]);
            }
            
            // Check for suspicious library names
            const libName = path.basename(fileName);
            const suspiciousLibNames = [
              'su', 'busybox', 'root', 'exploit', 'shell',
              'inject', 'hook', 'bypass', 'crack'
            ];
            
            if (suspiciousLibNames.some(sus => libName.includes(sus))) {
              analysis.suspiciousLibraries.push(fileName);
              analysis.hasRootingCapabilities = true;
            }
            
            // Analyze library content
            zipfile.openReadStream(entry, (err, readStream) => {
              if (err) {
                zipfile.readEntry();
                return;
              }
              
              const chunks = [];
              readStream.on('data', chunk => chunks.push(chunk));
              readStream.on('end', () => {
                const buffer = Buffer.concat(chunks);
                
                // Check for packed/encrypted content
                if (this.isPacked(buffer)) {
                  analysis.packedCount++;
                }
                
                // Check for rooting strings in native code
                const content = buffer.toString('binary');
                const rootingStrings = ['/system/bin/su', '/system/xbin/su', 'busybox', 'superuser'];
                
                if (rootingStrings.some(str => content.includes(str))) {
                  analysis.hasRootingCapabilities = true;
                }
                
                zipfile.readEntry();
              });
            });
          } else {
            zipfile.readEntry();
          }
        });
        
        zipfile.on('end', () => {
          console.log(`Native library analysis complete: ${analysis.packedCount} packed libraries, rooting capabilities: ${analysis.hasRootingCapabilities}`);
          resolve(analysis);
        });
      });
    });
  }
  
  isPacked(buffer) {
    // Simple packed executable detection
    // Check for high entropy (typical of packed/encrypted files)
    const entropy = this.calculateEntropy(buffer.slice(0, Math.min(1024, buffer.length)));
    return entropy > 7.5; // High entropy threshold
  }
  
  calculateEntropy(buffer) {
    const freq = new Array(256).fill(0);
    
    for (let i = 0; i < buffer.length; i++) {
      freq[buffer[i]]++;
    }
    
    let entropy = 0;
    for (let i = 0; i < 256; i++) {
      if (freq[i] > 0) {
        const p = freq[i] / buffer.length;
        entropy -= p * Math.log2(p);
      }
    }
    
    return entropy;
  }
  
  async analyzeNetworkBehavior(apkPath, apkInfo) {
    const analysis = {
      suspicious: false,
      domains: [],
      ipAddresses: [],
      suspiciousUrls: [],
      networkApis: []
    };
    
    try {
      // Extract network-related strings from DEX files
      if (apkInfo.dexAnalysis) {
        console.log("Starting network behavior analysis");
        apkInfo.dexAnalysis.forEach(dex => {
          if (dex.stringAnalysis && dex.stringAnalysis.samples) {
            dex.stringAnalysis.samples.forEach(sample => {
              const text = sample.text;
              
              // Extract URLs and domains
              const urlRegex = /(https?:\/\/[^\s]+)/gi;
              const urls = text.match(urlRegex);
              if (urls) {
                analysis.suspiciousUrls.push(...urls);
              }
              
              // Extract IP addresses
              const ipRegex = /\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b/g;
              const ips = text.match(ipRegex);
              if (ips) {
                analysis.ipAddresses.push(...ips);
              }
              
              // Check for suspicious networking APIs
              const networkingApis = [
                'Socket', 'ServerSocket', 'HttpURLConnection', 'OkHttp',
                'Volley', 'Retrofit', 'WebView', 'SSLContext'
              ];
              
              networkingApis.forEach(api => {
                if (text.includes(api)) {
                  analysis.networkApis.push(api);
                }
              });
            });
          }
        });
      }
      
      // Check for suspicious characteristics
      const suspiciousIndicators = [
        analysis.suspiciousUrls.some(url => url.includes('bit.ly') || url.includes('tinyurl')),
        analysis.ipAddresses.length > 5,
        analysis.suspiciousUrls.some(url => 
          url.includes('login') || url.includes('bank') || url.includes('secure')
        )
      ];
      
      analysis.suspicious = suspiciousIndicators.some(indicator => indicator);
      console.log(`Network behavior analysis complete: suspicious=${analysis.suspicious}, URLs found=${analysis.suspiciousUrls.length}, IPs found=${analysis.ipAddresses.length}`);
      return analysis;
      
    } catch (error) {
      console.error('Network analysis failed:', error);
      return { ...analysis, error: error.message };
    }
  }
  
  async runYaraRules(apkPath) {
    try {
      if (!this.yaraRules) {
        return [];
      }
      
      // This is a placeholder - in production, you'd use actual YARA
      // const { stdout } = await execPromise(`yara ${this.yaraRules} "${apkPath}"`);
      // return stdout.split('\n').filter(line => line.trim());
      
      return []; // Placeholder
      
    } catch (error) {
      console.error('YARA scanning failed:', error);
      return [];
    }
  }
  
  calculateSecurityRiskScore(results) {
    let score = 0;
    
    // Permission-based scoring
    score += results.maliciousPermissions * 5;
    
    // String analysis scoring
    score += results.suspiciousStrings * 2;
    score += results.phishingIndicators * 3;
    
    // Code analysis scoring
    if (results.obfuscated) score += 15;
    if (results.antiAnalysis) score += 20;
    
    // Native library scoring
    score += results.packedExecutables * 10;
    if (results.rootingCapabilities) score += 25;
    
    // Network behavior scoring
    if (results.suspiciousNetworkActivity) score += 15;
    
    // YARA matches
    score += results.yaraMatches.length * 20;
    
    return Math.min(score, 100);
  }
  
  async mlDetection(apkPath, apkInfo) {
    // Placeholder for machine learning detection
    // In production, this would interface with a trained ML model
    try {
      const features = this.extractMLFeatures(apkInfo);
      
      // Simulate ML prediction (replace with actual model inference)
      const malwareProbability = Math.random(); // Placeholder
      
      return {
        malwareProbability,
        confidence: Math.random() * 0.3 + 0.7, // 70-100% confidence
        features: features,
        model: 'banking_trojan_classifier_v1.0'
      };
      
    } catch (error) {
      console.error('ML detection failed:', error);
      return null;
    }
  }
  
  extractMLFeatures(apkInfo) {
    // Extract features for ML model
    return {
      fileSize: apkInfo.fileSize || 0,
      permissionCount: apkInfo.manifest?.permissions?.length || 0,
      maliciousPermissionRatio: 0, // Calculate based on permissions
      dexFileCount: apkInfo.dexAnalysis?.length || 0,
      hasNativeCode: apkInfo.hasNativeCode || false,
      stringEntropy: 0, // Calculate from string analysis
      networkingIndicators: 0 // Count of networking-related strings
    };
  }
  
  initializeYaraRules() {
    // In production, load actual YARA rules from files
    return null;
  }
}

module.exports = SecurityScanner;
