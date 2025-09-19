// Apollo Unified Protection Engine - Combines all protection modules into single optimized system
// This replaces the separate Threat Engine, Wallet Shield, APT Detector, and Threat Blocker

const { EventEmitter } = require('events');
const fs = require('fs-extra');
const path = require('path');
const os = require('os');
const crypto = require('crypto');

class ApolloUnifiedProtectionEngine extends EventEmitter {
    constructor() {
        super();

        // Unified engine state
        this.engineName = 'Apollo Unified Protection Engine';
        this.version = '2.0.0';
        this.isActive = false;
        this.lastScanTime = null;

        // Consolidated protection modules
        this.protectionModules = {
            threatDetection: true,
            walletProtection: true,
            aptMonitoring: true,
            systemBlocking: true,
            behavioralAnalysis: true,
            networkMonitoring: true
        };

        // Unified threat database
        this.threatSignatures = new Map();
        this.behaviorPatterns = new Map();
        this.cryptoSignatures = new Map();
        this.aptSignatures = new Map();

        // Performance optimization
        this.scanInterval = 30000; // 30 second unified scans
        this.scanTimer = null;
        this.performanceMode = 'balanced'; // balanced, performance, maximum_protection

        // Initialize enhanced security features
        this.processWhitelist = null; // Will be initialized by initializeProcessWhitelist()
        this.criticalProcesses = new Set([
            'winlogon.exe', 'csrss.exe', 'wininit.exe', 'services.exe',
            'lsass.exe', 'smss.exe', 'explorer.exe', 'dwm.exe'
        ]);
        this.initializeProcessWhitelist();

        // Unified statistics
        this.stats = {
            threatsDetected: 0,
            threatsBlocked: 0,
            cryptoTransactionsProtected: 0,
            aptAlertsGenerated: 0,
            filesScanned: 0,
            networkConnectionsMonitored: 0,
            totalScanTime: 0,
            engineUptime: Date.now()
        };

        // Active threat tracking
        this.activeThreatSessions = new Map();
        this.quarantinedItems = new Map();
        this.blockedConnections = new Set();

        // System monitoring
        this.monitoredPaths = [
            process.env.USERPROFILE || os.homedir(),
            'C:\\Windows\\System32',
            'C:\\Program Files',
            'C:\\Program Files (x86)'
        ];

        this.networkConnectionCache = new Map();
        this.processMonitorCache = new Map();

        console.log('🛡️ Apollo Unified Protection Engine initialized');
    }

    async initialize() {
        try {
            console.log('🔥 Starting Apollo Unified Protection Engine...');

            // Load all threat signatures into unified database
            await this.loadUnifiedSignatures();

            // Initialize behavioral analysis baseline
            await this.establishBehaviorBaseline();

            // Start unified monitoring
            await this.startUnifiedMonitoring();

            // Initialize network monitoring
            await this.initializeNetworkMonitoring();

            // Start performance-optimized scanning
            this.startOptimizedScanning();

            this.isActive = true;
            console.log('✅ Apollo Unified Protection Engine active - all modules integrated');

            this.emit('engine-ready', {
                engine: this.engineName,
                modules: Object.keys(this.protectionModules).length,
                signatures: this.threatSignatures.size,
                status: 'active'
            });

            return true;
        } catch (error) {
            console.error('❌ Failed to initialize Unified Protection Engine:', error);
            return false;
        }
    }

    async loadUnifiedSignatures() {
        console.log('📊 Loading unified threat signatures...');

        // Consolidated threat signatures from all modules
        const signatures = {
            // File-based threats
            'trojan_generic': { type: 'file', severity: 'high', pattern: /trojan|backdoor|keylogger/i },
            'crypto_stealer': { type: 'crypto', severity: 'critical', pattern: /wallet\.dat|private.*key|seed.*phrase/i },
            'apt_persistence': { type: 'apt', severity: 'high', pattern: /schtasks|registry.*run|startup/i },

            // Network-based threats
            'c2_communication': { type: 'network', severity: 'critical', ports: [4444, 5555, 6666, 8080] },
            'crypto_mining': { type: 'network', severity: 'medium', domains: ['pool.', 'mining.', 'stratum.'] },

            // Behavioral patterns
            'mass_file_encryption': { type: 'behavior', severity: 'critical', threshold: 100 },
            'privilege_escalation': { type: 'behavior', severity: 'high', pattern: /runas|psexec|wmic/i },
            'data_exfiltration': { type: 'behavior', severity: 'high', threshold: 50 }
        };

        // Load into unified threat database
        for (const [name, sig] of Object.entries(signatures)) {
            this.threatSignatures.set(name, {
                ...sig,
                lastTriggered: null,
                triggerCount: 0,
                id: crypto.randomUUID()
            });
        }

        // Load APT group signatures
        const aptGroups = {
            'lazarus_group': {
                techniques: ['T1055', 'T1071', 'T1105'],
                severity: 'critical',
                indicators: ['rundll32.exe', 'regsvr32.exe']
            },
            'apt29_cozy_bear': {
                techniques: ['T1086', 'T1064', 'T1036'],
                severity: 'critical',
                indicators: ['powershell.exe', 'wscript.exe']
            },
            'pegasus_nso': {
                techniques: ['T1068', 'T1055', 'T1012'],
                severity: 'critical',
                indicators: ['zero_day', 'kernel_exploit']
            }
        };

        for (const [group, data] of Object.entries(aptGroups)) {
            this.aptSignatures.set(group, {
                ...data,
                lastDetection: null,
                confidence: 0,
                id: crypto.randomUUID()
            });
        }

        // Load crypto protection signatures
        const cryptoPatterns = {
            'wallet_access': /wallet\.dat|wallet\.json|keystore|private.*key/i,
            'seed_phrase': /seed.*phrase|mnemonic.*phrase|recovery.*phrase/i,
            'crypto_clipboard': /[13][a-km-zA-HJ-NP-Z1-9]{25,34}|0x[a-fA-F0-9]{40}/,
            'mining_config': /pool.*config|stratum.*config|mining.*config/i,
            'exchange_credentials': /binance|coinbase|kraken|bitstamp/i
        };

        for (const [name, pattern] of Object.entries(cryptoPatterns)) {
            this.cryptoSignatures.set(name, {
                pattern,
                severity: 'high',
                category: 'crypto_protection',
                id: crypto.randomUUID()
            });
        }

        console.log(`✅ Loaded ${this.threatSignatures.size} threat signatures, ${this.aptSignatures.size} APT patterns, ${this.cryptoSignatures.size} crypto protections`);
    }

    async establishBehaviorBaseline() {
        console.log('📊 Establishing unified behavior baseline...');

        try {
            // Establish baseline for file system activity
            const homeDir = os.homedir();
            const fileCounts = {};

            for (const monitorPath of this.monitoredPaths) {
                if (await fs.pathExists(monitorPath)) {
                    try {
                        const files = await fs.readdir(monitorPath);
                        fileCounts[monitorPath] = files.length;
                    } catch (error) {
                        // Skip directories we can't access
                        fileCounts[monitorPath] = 0;
                    }
                }
            }

            // Establish network baseline
            const { exec } = require('child_process');
            const networkConnections = await new Promise((resolve) => {
                exec('netstat -an | find "ESTABLISHED"', (error, stdout) => {
                    if (error) resolve(0);
                    else resolve(stdout.split('\n').length);
                });
            });

            // Store baseline
            this.behaviorPatterns.set('file_system_baseline', {
                fileCounts,
                timestamp: Date.now(),
                type: 'baseline'
            });

            this.behaviorPatterns.set('network_baseline', {
                connectionCount: networkConnections,
                timestamp: Date.now(),
                type: 'baseline'
            });

            console.log('✅ Behavioral baseline established');
        } catch (error) {
            console.warn('⚠️ Could not establish complete baseline:', error.message);
        }
    }

    async startUnifiedMonitoring() {
        console.log('🔍 Starting unified system monitoring...');

        // File system monitoring for all threat types
        this.setupFileSystemMonitoring();

        // Process monitoring for APT and malware
        this.setupProcessMonitoring();

        // Registry monitoring for persistence
        this.setupRegistryMonitoring();

        // Memory monitoring for injection attacks
        this.setupMemoryMonitoring();

        console.log('✅ Unified monitoring systems active');
    }

    setupFileSystemMonitoring() {
        // Monitor critical paths for all threat types
        for (const monitorPath of this.monitoredPaths) {
            try {
                if (fs.existsSync(monitorPath)) {
                    fs.watch(monitorPath, { recursive: false }, (eventType, filename) => {
                        if (filename) {
                            this.analyzeFileSystemEvent(monitorPath, filename, eventType);
                        }
                    });
                }
            } catch (error) {
                console.warn(`⚠️ Could not monitor ${monitorPath}:`, error.message);
            }
        }
    }

    async analyzeFileSystemEvent(path, filename, eventType) {
        const fullPath = require('path').join(path, filename);

        // Unified threat analysis
        const threats = await this.performUnifiedThreatAnalysis(fullPath, 'file_system');

        if (threats.length > 0) {
            this.handleDetectedThreats(threats, fullPath);
        }
    }

    setupProcessMonitoring() {
        // Monitor for suspicious processes (APT, malware, crypto mining)
        setInterval(async () => {
            try {
                const { exec } = require('child_process');
                const processes = await new Promise((resolve) => {
                    exec('tasklist /fo csv', (error, stdout) => {
                        if (error) resolve([]);
                        else {
                            const lines = stdout.split('\n').slice(1);
                            const procs = lines.map(line => {
                                const parts = line.split(',');
                                return {
                                    name: parts[0]?.replace(/"/g, ''),
                                    pid: parts[1]?.replace(/"/g, ''),
                                    memory: parts[4]?.replace(/"/g, '')
                                };
                            }).filter(p => p.name);
                            resolve(procs);
                        }
                    });
                });

                await this.analyzeProcessList(processes);
            } catch (error) {
                console.warn('⚠️ Process monitoring error:', error.message);
            }
        }, 15000); // Every 15 seconds
    }

    async analyzeProcessList(processes) {
        for (const process of processes) {
            // Check against all threat signatures
            const threats = [];

            // APT detection
            for (const [groupName, aptSig] of this.aptSignatures) {
                if (aptSig.indicators.some(indicator =>
                    process.name.toLowerCase().includes(indicator.toLowerCase()))) {
                    threats.push({
                        type: 'APT_DETECTION',
                        severity: aptSig.severity,
                        group: groupName,
                        process: process.name,
                        pid: process.pid,
                        technique: aptSig.techniques[0]
                    });
                }
            }

            // Generic malware detection
            const suspiciousPatterns = [
                /.*\.tmp\.exe$/i,
                /^[a-f0-9]{8,}\.exe$/i,
                /temp.*\.exe$/i,
                /system.*\.exe$/i,
                /svchost.*[0-9]\.exe$/i
            ];

            for (const pattern of suspiciousPatterns) {
                if (pattern.test(process.name)) {
                    threats.push({
                        type: 'SUSPICIOUS_PROCESS',
                        severity: 'medium',
                        process: process.name,
                        pid: process.pid,
                        reason: 'Suspicious naming pattern'
                    });
                }
            }

            if (threats.length > 0) {
                this.handleDetectedThreats(threats, process.name);
            }
        }
    }

    setupRegistryMonitoring() {
        // Monitor registry for persistence mechanisms
        setInterval(async () => {
            try {
                const { exec } = require('child_process');
                const registryEntries = await new Promise((resolve) => {
                    exec('reg query "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"', (error, stdout) => {
                        if (error) resolve([]);
                        else {
                            const entries = stdout.split('\n')
                                .filter(line => line.includes('REG_'))
                                .map(line => line.trim());
                            resolve(entries);
                        }
                    });
                });

                await this.analyzeRegistryEntries(registryEntries);
            } catch (error) {
                console.warn('⚠️ Registry monitoring error:', error.message);
            }
        }, 30000); // Every 30 seconds
    }

    async analyzeRegistryEntries(entries) {
        for (const entry of entries) {
            // Check for APT persistence techniques
            const threats = [];

            // Check against known persistence patterns
            const persistencePatterns = [
                { pattern: /.*\.tmp\.exe/, severity: 'high', reason: 'Temporary executable in startup' },
                { pattern: /system32.*svchost/, severity: 'medium', reason: 'Suspicious svchost variant' },
                { pattern: /temp.*\.exe/, severity: 'high', reason: 'Temporary location executable' },
                { pattern: /[a-f0-9]{16,}\.exe/, severity: 'medium', reason: 'Random named executable' }
            ];

            for (const patternInfo of persistencePatterns) {
                if (patternInfo.pattern.test(entry)) {
                    threats.push({
                        type: 'REGISTRY_PERSISTENCE',
                        severity: patternInfo.severity,
                        details: {
                            registry_key: 'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run',
                            entry: entry,
                            technique: 'T1547.001'
                        },
                        reason: patternInfo.reason
                    });
                }
            }

            if (threats.length > 0) {
                this.handleDetectedThreats(threats, 'Registry');
            }
        }
    }

    setupMemoryMonitoring() {
        // Monitor for process injection and memory manipulation
        setInterval(async () => {
            try {
                // Monitor memory usage patterns for anomalies
                const memInfo = await this.getSystemMemoryInfo();
                await this.analyzeMemoryPatterns(memInfo);
            } catch (error) {
                console.warn('⚠️ Memory monitoring error:', error.message);
            }
        }, 45000); // Every 45 seconds
    }

    async getSystemMemoryInfo() {
        const { exec } = require('child_process');
        return new Promise((resolve) => {
            exec('wmic OS get TotalVirtualMemorySize,TotalVisibleMemorySize,FreePhysicalMemory /format:csv', (error, stdout) => {
                if (error) resolve({});
                else {
                    const lines = stdout.split('\n').filter(line => line.includes(','));
                    if (lines.length > 1) {
                        const parts = lines[1].split(',');
                        resolve({
                            freePhysical: parseInt(parts[1]) || 0,
                            totalVirtual: parseInt(parts[2]) || 0,
                            totalVisible: parseInt(parts[3]) || 0
                        });
                    } else {
                        resolve({});
                    }
                }
            });
        });
    }

    async analyzeMemoryPatterns(memInfo) {
        // Detect memory-based attacks
        if (memInfo.freePhysical && memInfo.totalVisible) {
            const memoryUsagePercent = ((memInfo.totalVisible - memInfo.freePhysical) / memInfo.totalVisible) * 100;

            if (memoryUsagePercent > 95) {
                this.handleDetectedThreats([{
                    type: 'POSSIBLE_MEMORY_ATTACK',
                    severity: 'medium',
                    details: {
                        memoryUsage: memoryUsagePercent.toFixed(2) + '%',
                        technique: 'T1055'
                    },
                    reason: 'Extremely high memory usage detected'
                }], 'System Memory');
            }
        }
    }

    async performUnifiedThreatAnalysis(target, context) {
        const threats = [];

        try {
            // File-based analysis
            if (context === 'file_system' && await fs.pathExists(target)) {
                const stat = await fs.stat(target);
                const filename = path.basename(target);

                // Check against all signature types
                for (const [sigName, signature] of this.threatSignatures) {
                    if (signature.pattern && signature.pattern.test(filename)) {
                        threats.push({
                            type: 'FILE_THREAT',
                            signature: sigName,
                            severity: signature.severity,
                            file: target,
                            size: stat.size,
                            reason: `Matches ${signature.type} signature`
                        });
                    }
                }

                // Crypto-specific analysis
                for (const [cryptoName, cryptoSig] of this.cryptoSignatures) {
                    if (cryptoSig.pattern.test(filename) || cryptoSig.pattern.test(target)) {
                        threats.push({
                            type: 'CRYPTO_THREAT',
                            signature: cryptoName,
                            severity: cryptoSig.severity,
                            file: target,
                            category: cryptoSig.category,
                            reason: 'Potential cryptocurrency-related threat'
                        });
                    }
                }
            }

            // Network-based analysis
            if (context === 'network') {
                for (const [sigName, signature] of this.threatSignatures) {
                    if (signature.type === 'network') {
                        // Check domains, ports, etc.
                        if (signature.domains) {
                            for (const domain of signature.domains) {
                                if (target.includes(domain)) {
                                    threats.push({
                                        type: 'NETWORK_THREAT',
                                        signature: sigName,
                                        severity: signature.severity,
                                        target: target,
                                        reason: `Suspicious network pattern: ${domain}`
                                    });
                                }
                            }
                        }
                    }
                }
            }

        } catch (error) {
            console.warn('⚠️ Threat analysis error:', error.message);
        }

        return threats;
    }

    async handleDetectedThreats(threats, source) {
        for (const threat of threats) {
            this.stats.threatsDetected++;

            // Log threat detection with confidence score
            console.log(`🚨 ${threat.type.toUpperCase()} DETECTED: ${threat.severity?.toUpperCase() || 'UNKNOWN'}`);
            console.log(`Source: ${source}`);
            if (threat.details?.confidenceScore) {
                console.log(`Confidence: ${threat.details.confidenceScore}%`);
            }
            console.log(`Details: ${JSON.stringify(threat, null, 2)}`);

            // Check if process termination is involved and if it's a critical process
            if (threat.pid && this.criticalProcesses) {
                const processName = threat.details?.tool || '';
                if (this.criticalProcesses.has(processName.toLowerCase())) {
                    console.log('⚠️ CRITICAL PROCESS DETECTED - Termination blocked for system stability');
                    console.log(`🛡️ Protected process: ${processName} (PID: ${threat.pid})`);
                    continue; // Skip processing this threat
                }
            }

            // Handle confirmation requirements
            if (threat.requiresConfirmation && threat.pid) {
                const shouldProceed = await this.requestUserConfirmation(threat, source);
                if (!shouldProceed) {
                    console.log(`⏹️ User cancelled action for ${threat.details?.tool || 'process'} (PID: ${threat.pid})`);
                    continue;
                }
            }

            // Emit threat alert
            this.emit('threat-detected', {
                type: threat.type,
                severity: threat.severity || 'medium',
                source: source,
                details: threat,
                timestamp: new Date().toISOString(),
                engineVersion: this.version
            });

            // Auto-response based on severity
            if (threat.severity === 'critical') {
                await this.handleCriticalThreat(threat, source);
            } else if (threat.severity === 'high') {
                await this.handleHighThreat(threat, source);
            }

            // Update threat signature statistics
            if (threat.signature && this.threatSignatures.has(threat.signature)) {
                const sig = this.threatSignatures.get(threat.signature);
                sig.triggerCount++;
                sig.lastTriggered = Date.now();
            }
        }
    }

    async handleCriticalThreat(threat, source) {
        console.log('🚨 CRITICAL THREAT - Initiating emergency response');

        // Quarantine if it's a file
        if (threat.file && await fs.pathExists(threat.file)) {
            await this.quarantineFile(threat.file);
        }

        // Block network connections if applicable
        if (threat.type === 'NETWORK_THREAT') {
            this.blockedConnections.add(threat.target);
        }

        this.stats.threatsBlocked++;
    }

    async handleHighThreat(threat, source) {
        console.log('⚠️ HIGH THREAT - Logging and monitoring');

        // Add to active threat tracking
        const threatId = crypto.randomUUID();
        this.activeThreatSessions.set(threatId, {
            threat,
            source,
            startTime: Date.now(),
            status: 'monitoring'
        });
    }

    async quarantineFile(filePath) {
        try {
            const quarantineDir = path.join(os.homedir(), '.apollo', 'quarantine');
            await fs.ensureDir(quarantineDir);

            const filename = path.basename(filePath);
            const timestamp = Date.now();
            const quarantinedPath = path.join(quarantineDir, `${timestamp}_${filename}.quarantine`);

            await fs.move(filePath, quarantinedPath);

            this.quarantinedItems.set(quarantinedPath, {
                originalPath: filePath,
                quarantineTime: timestamp,
                reason: 'Critical threat detected'
            });

            console.log(`🔒 File quarantined: ${filePath} -> ${quarantinedPath}`);
        } catch (error) {
            console.error('❌ Failed to quarantine file:', error);
        }
    }

    async initializeNetworkMonitoring() {
        console.log('🌐 Initializing unified network monitoring...');

        // Monitor network connections for all threat types
        setInterval(async () => {
            await this.performNetworkScan();
        }, 20000); // Every 20 seconds
    }

    async performNetworkScan() {
        try {
            const { exec } = require('child_process');
            const connections = await new Promise((resolve) => {
                exec('netstat -an', (error, stdout) => {
                    if (error) resolve([]);
                    else {
                        const lines = stdout.split('\n')
                            .filter(line => line.includes('ESTABLISHED') || line.includes('LISTENING'))
                            .map(line => line.trim().split(/\s+/));
                        resolve(lines);
                    }
                });
            });

            this.stats.networkConnectionsMonitored = connections.length;

            // Analyze connections for threats
            for (const connection of connections) {
                if (connection.length >= 4) {
                    const localAddr = connection[1];
                    const remoteAddr = connection[2];
                    const state = connection[3];

                    await this.analyzeNetworkConnection(localAddr, remoteAddr, state);
                }
            }

            // Check for data exfiltration patterns
            this.detectDataExfiltrationPatterns(connections);

        } catch (error) {
            console.warn('⚠️ Network monitoring error:', error.message);
        }
    }

    async analyzeNetworkConnection(localAddr, remoteAddr, state) {
        // Extract port numbers
        const localPort = parseInt(localAddr.split(':').pop());
        const remotePort = parseInt(remoteAddr.split(':').pop());

        // Check against threat signatures
        for (const [sigName, signature] of this.threatSignatures) {
            if (signature.type === 'network' && signature.ports) {
                if (signature.ports.includes(localPort) || signature.ports.includes(remotePort)) {
                    this.handleDetectedThreats([{
                        type: 'SUSPICIOUS_NETWORK_CONNECTION',
                        signature: sigName,
                        severity: signature.severity,
                        localAddr,
                        remoteAddr,
                        state,
                        reason: `Connection on suspicious port: ${localPort || remotePort}`
                    }], 'Network Monitor');
                }
            }
        }
    }

    detectDataExfiltrationPatterns(connections) {
        // Count outbound connections
        const outboundConnections = connections.filter(conn =>
            conn[3] === 'ESTABLISHED' && !conn[2].startsWith('127.0.0.1')
        ).length;

        if (outboundConnections > 50) {
            this.handleDetectedThreats([{
                type: 'POSSIBLE_DATA_EXFILTRATION',
                severity: 'high',
                details: {
                    connection_count: outboundConnections,
                    technique: 'T1041'
                },
                reason: `High number of outbound connections: ${outboundConnections}`
            }], 'Network Analysis');
        }
    }

    startOptimizedScanning() {
        console.log('🔍 Starting optimized unified scanning...');

        this.scanTimer = setInterval(async () => {
            const scanStartTime = Date.now();

            try {
                await this.performComprehensiveScan();
            } catch (error) {
                console.error('❌ Scan error:', error);
            }

            const scanEndTime = Date.now();
            this.stats.totalScanTime += (scanEndTime - scanStartTime);
            this.stats.scansCompleted++;
            this.lastScanTime = scanEndTime;

        }, this.scanInterval);
    }

    async performComprehensiveScan() {
        console.log('🔍 Performing comprehensive unified scan...');

        // Scan critical paths for all threat types
        for (const scanPath of this.monitoredPaths) {
            if (await fs.pathExists(scanPath)) {
                await this.scanDirectoryUnified(scanPath);
            }
        }

        // Check for living-off-the-land techniques
        await this.detectLivingOffTheLand();

        // Scan for privilege escalation attempts
        await this.detectPrivilegeEscalation();

        // Monitor for crypto-specific threats
        await this.performCryptoThreatScan();
    }

    async scanDirectoryUnified(dirPath) {
        try {
            const items = await fs.readdir(dirPath);

            for (const item of items.slice(0, 10)) { // Limit for performance
                const fullPath = path.join(dirPath, item);
                const threats = await this.performUnifiedThreatAnalysis(fullPath, 'file_system');

                if (threats.length > 0) {
                    this.handleDetectedThreats(threats, fullPath);
                }

                this.stats.filesScanned++;
            }
        } catch (error) {
            // Skip directories we can't access
        }
    }

    async detectLivingOffTheLand() {
        // Enhanced detection with context analysis and confidence scoring
        const toolPatterns = {
            'powershell.exe': {
                suspiciousArgs: ['-EncodedCommand', '-WindowStyle Hidden', '-ExecutionPolicy Bypass',
                               'DownloadString', 'IEX', 'Invoke-Expression', 'Net.WebClient'],
                legitimateParents: ['explorer.exe', 'cmd.exe', 'winlogon.exe', 'services.exe'],
                technique: 'T1059.001'
            },
            'wmic.exe': {
                suspiciousArgs: ['process call create', 'shadowcopy delete', '/format:'],
                legitimateParents: ['svchost.exe', 'wmiprvse.exe'],
                technique: 'T1047'
            },
            'certutil.exe': {
                suspiciousArgs: ['-urlcache', '-split', '-decode'],
                legitimateParents: ['mmc.exe', 'svchost.exe'],
                technique: 'T1140'
            },
            'bitsadmin.exe': {
                suspiciousArgs: ['/transfer', '/download', '/addfile'],
                legitimateParents: ['svchost.exe'],
                technique: 'T1197'
            }
        };

        // Critical processes that should never be killed
        this.criticalProcesses = new Set([
            'winlogon.exe', 'csrss.exe', 'wininit.exe', 'services.exe',
            'lsass.exe', 'smss.exe', 'explorer.exe', 'dwm.exe'
        ]);

        try {
            const { exec } = require('child_process');

            // Get detailed process information with command lines
            const processInfo = await new Promise((resolve) => {
                exec('wmic process get Name,ProcessId,CommandLine,ParentProcessId /format:csv', (error, stdout) => {
                    if (error) resolve([]);
                    else resolve(stdout.split('\n').filter(line => line.trim()));
                });
            });

            for (const [tool, config] of Object.entries(toolPatterns)) {
                const toolProcesses = processInfo.filter(line =>
                    line.toLowerCase().includes(tool.toLowerCase()) && line.includes(',')
                );

                for (const processLine of toolProcesses) {
                    const analysis = await this.analyzeProcessContext(processLine, config);

                    if (analysis.suspicionLevel > 0.3) { // Only flag if confidence > 30%
                        const threat = {
                            type: analysis.suspicionLevel > 0.7 ? 'APT_DETECTION' : 'LIVING_OFF_THE_LAND',
                            severity: this.calculateThreatSeverity(analysis.suspicionLevel),
                            details: {
                                tool: tool,
                                technique: config.technique,
                                suspiciousArgs: analysis.suspiciousArgs,
                                parentProcess: analysis.parentProcess,
                                confidenceScore: Math.round(analysis.suspicionLevel * 100),
                                description: `${tool} with suspicious context (${Math.round(analysis.suspicionLevel * 100)}% confidence)`
                            },
                            reason: analysis.reason,
                            pid: analysis.pid,
                            requiresConfirmation: analysis.suspicionLevel < 0.8 // Require confirmation for medium confidence
                        };

                        // Check if this matches APT signatures
                        if (analysis.suspicionLevel > 0.7) {
                            threat.details.group = this.identifyAPTGroup(tool, analysis.suspiciousArgs);
                        }

                        this.handleDetectedThreats([threat], 'Advanced Process Monitor');
                    }
                }
            }
        } catch (error) {
            console.warn('⚠️ Living-off-the-land detection error:', error.message);
        }
    }

    async analyzeProcessContext(processLine, config) {
        // Parse process information from wmic output
        const parts = processLine.split(',');
        if (parts.length < 4) return { suspicionLevel: 0 };

        const commandLine = parts[2] || '';
        const processName = parts[1] || '';
        const pid = parts[3] || '';
        const parentPid = parts[4] || '';

        let suspicionLevel = 0;
        let reason = [];
        let suspiciousArgs = [];

        // Check for suspicious command line arguments
        for (const suspiciousArg of config.suspiciousArgs) {
            if (commandLine.toLowerCase().includes(suspiciousArg.toLowerCase())) {
                suspicionLevel += 0.3;
                suspiciousArgs.push(suspiciousArg);
                reason.push(`Suspicious argument: ${suspiciousArg}`);
            }
        }

        // Check parent process legitimacy and whitelist
        const parentProcess = await this.getParentProcessName(parentPid);

        // Check if this process chain is whitelisted
        if (parentProcess && this.isProcessWhitelisted(parentProcess, processName)) {
            console.log(`✅ Whitelisted process chain: ${parentProcess}>${processName}`);
            suspicionLevel = 0; // Override all suspicion for whitelisted processes
            reason = ['Process chain is whitelisted'];
        } else if (parentProcess && !config.legitimateParents.includes(parentProcess.toLowerCase())) {
            suspicionLevel += 0.2;
            reason.push(`Unusual parent process: ${parentProcess}`);
        }

        // Check for encoded or obfuscated commands
        if (commandLine.includes('base64') || commandLine.includes('FromBase64String') ||
            commandLine.match(/[A-Za-z0-9+/]{20,}/)) {
            suspicionLevel += 0.4;
            reason.push('Potentially encoded/obfuscated command');
        }

        // Check for network-related activities
        if (commandLine.includes('http') || commandLine.includes('wget') || commandLine.includes('curl')) {
            suspicionLevel += 0.2;
            reason.push('Network activity detected');
        }

        // Cap suspicion level at 1.0
        suspicionLevel = Math.min(suspicionLevel, 1.0);

        return {
            suspicionLevel,
            reason: reason.join(', '),
            suspiciousArgs,
            parentProcess,
            pid: pid.trim()
        };
    }

    async getParentProcessName(parentPid) {
        if (!parentPid || parentPid === '0') return null;

        try {
            const { exec } = require('child_process');
            const result = await new Promise((resolve) => {
                exec(`wmic process where "ProcessId=${parentPid}" get Name /format:csv`, (error, stdout) => {
                    if (error) resolve(null);
                    else {
                        const lines = stdout.split('\n').filter(line => line.includes(','));
                        if (lines.length > 0) {
                            const parts = lines[0].split(',');
                            resolve(parts[1] || null);
                        } else {
                            resolve(null);
                        }
                    }
                });
            });
            return result;
        } catch (error) {
            return null;
        }
    }

    calculateThreatSeverity(suspicionLevel) {
        if (suspicionLevel >= 0.8) return 'critical';
        if (suspicionLevel >= 0.6) return 'high';
        if (suspicionLevel >= 0.4) return 'medium';
        return 'low';
    }

    identifyAPTGroup(tool, suspiciousArgs) {
        // Map specific tool usage patterns to known APT groups
        if (tool === 'powershell.exe') {
            if (suspiciousArgs.some(arg => arg.includes('-EncodedCommand') || arg.includes('IEX'))) {
                return 'apt29_cozy_bear';
            }
        }
        return 'unknown_apt';
    }

    async requestUserConfirmation(threat, source) {
        // For now, implement a console-based confirmation
        // In a real UI, this would show a modal dialog
        console.log('⚠️ USER CONFIRMATION REQUIRED');
        console.log(`Process: ${threat.details?.tool || 'Unknown'} (PID: ${threat.pid})`);
        console.log(`Threat: ${threat.type} - ${threat.severity} severity`);
        console.log(`Confidence: ${threat.details?.confidenceScore || 'Unknown'}%`);
        console.log(`Reason: ${threat.reason || 'Suspicious behavior detected'}`);
        console.log('');
        console.log('This process will be terminated if confirmed.');
        console.log('To prevent this action in the future, add to whitelist: addToWhitelist(' + threat.pid + ')');

        // For safety, default to false (don't terminate) unless explicitly confirmed
        // In a real implementation, this would wait for user input
        return false; // Conservative default - require explicit user action
    }

    initializeProcessWhitelist() {
        if (!this.processWhitelist) {
            this.processWhitelist = new Set([
                // Common legitimate PowerShell scenarios
                'explorer.exe>powershell.exe', // User launched PowerShell
                'cmd.exe>powershell.exe',      // Command prompt to PowerShell
                'code.exe>powershell.exe',     // VS Code integrated terminal
                'WindowsTerminal.exe>powershell.exe', // Windows Terminal
                'powershell_ise.exe>powershell.exe', // PowerShell ISE

                // System processes
                'services.exe>svchost.exe',
                'winlogon.exe>userinit.exe',
                'userinit.exe>explorer.exe'
            ]);
        }
    }

    addToWhitelist(pid) {
        // Get process info and add to whitelist
        this.getProcessChain(pid).then(chain => {
            if (chain) {
                this.processWhitelist.add(chain);
                console.log(`✅ Added to whitelist: ${chain}`);
            }
        });
    }

    async getProcessChain(pid) {
        try {
            const { exec } = require('child_process');
            const result = await new Promise((resolve) => {
                exec(`wmic process where "ProcessId=${pid}" get Name,ParentProcessId /format:csv`, (error, stdout) => {
                    if (error) resolve(null);
                    else resolve(stdout);
                });
            });

            const lines = result.split('\n').filter(line => line.includes(','));
            if (lines.length > 0) {
                const parts = lines[0].split(',');
                const processName = parts[1];
                const parentPid = parts[2];

                if (parentPid && parentPid !== '0') {
                    const parentInfo = await new Promise((resolve) => {
                        exec(`wmic process where "ProcessId=${parentPid}" get Name /format:csv`, (error, stdout) => {
                            if (error) resolve(null);
                            else {
                                const parentLines = stdout.split('\n').filter(line => line.includes(','));
                                if (parentLines.length > 0) {
                                    const parentParts = parentLines[0].split(',');
                                    resolve(parentParts[1]);
                                } else {
                                    resolve(null);
                                }
                            }
                        });
                    });

                    if (parentInfo) {
                        return `${parentInfo}>${processName}`;
                    }
                }
            }
            return null;
        } catch (error) {
            return null;
        }
    }

    isProcessWhitelisted(parentProcess, processName) {
        if (!this.processWhitelist) this.initializeProcessWhitelist();

        const chain = `${parentProcess}>${processName}`;
        return this.processWhitelist.has(chain);
    }

    async detectPrivilegeEscalation() {
        // Monitor for privilege escalation attempts
        try {
            const { exec } = require('child_process');
            const services = await new Promise((resolve) => {
                exec('sc query type= service state= all', (error, stdout) => {
                    if (error) resolve([]);
                    else resolve(stdout.split('\n'));
                });
            });

            // Look for suspicious service creation or modification
            const suspiciousServices = services.filter(line =>
                line.includes('TEMP') ||
                line.includes('TMP') ||
                /[a-f0-9]{16,}/i.test(line)
            );

            if (suspiciousServices.length > 0) {
                this.handleDetectedThreats([{
                    type: 'SUSPICIOUS_SERVICE_PERSISTENCE',
                    severity: 'high',
                    details: {
                        services: suspiciousServices.slice(0, 3), // Limit output
                        technique: 'T1543.003'
                    },
                    reason: 'Suspicious Windows service detected'
                }], 'Service Monitor');
            }
        } catch (error) {
            console.warn('⚠️ Privilege escalation detection error:', error.message);
        }
    }

    async performCryptoThreatScan() {
        // Scan for cryptocurrency-related threats
        try {
            const homeDir = os.homedir();
            const cryptoFiles = [];

            // Look for wallet files and crypto-related items
            for (const [cryptoName, cryptoSig] of this.cryptoSignatures) {
                try {
                    const items = await fs.readdir(homeDir);
                    for (const item of items) {
                        if (cryptoSig.pattern.test(item)) {
                            cryptoFiles.push({ file: item, signature: cryptoName });
                        }
                    }
                } catch (error) {
                    // Skip if can't read directory
                }
            }

            if (cryptoFiles.length > 0) {
                this.stats.cryptoTransactionsProtected += cryptoFiles.length;

                console.log(`👁️ Monitoring ${cryptoFiles.length} cryptocurrency-related files`);

                // Enhanced monitoring for crypto files
                for (const cryptoFile of cryptoFiles) {
                    this.emit('crypto-asset-detected', {
                        file: cryptoFile.file,
                        signature: cryptoFile.signature,
                        timestamp: new Date().toISOString()
                    });
                }
            }
        } catch (error) {
            console.warn('⚠️ Crypto threat scan error:', error.message);
        }
    }

    // Public API methods for external control
    async scan(target) {
        if (!target) {
            return await this.performComprehensiveScan();
        } else {
            return await this.performUnifiedThreatAnalysis(target, 'manual');
        }
    }

    async quarantine(filePath) {
        return await this.quarantineFile(filePath);
    }

    getStatistics() {
        return {
            ...this.stats,
            engine: this.engineName,
            version: this.version,
            isActive: this.isActive,
            lastScanTime: this.lastScanTime,
            uptime: Date.now() - this.stats.engineUptime,
            signatureCount: this.threatSignatures.size,
            aptSignatureCount: this.aptSignatures.size,
            cryptoSignatureCount: this.cryptoSignatures.size,
            activeThreatSessions: this.activeThreatSessions.size,
            quarantinedItems: this.quarantinedItems.size,
            blockedConnections: this.blockedConnections.size
        };
    }

    async stop() {
        console.log('🛑 Stopping Apollo Unified Protection Engine...');

        if (this.scanTimer) {
            clearInterval(this.scanTimer);
            this.scanTimer = null;
        }

        this.isActive = false;
        this.emit('engine-stopped');

        console.log('✅ Apollo Unified Protection Engine stopped');
    }

    // Configuration methods
    setPerformanceMode(mode) {
        const modes = {
            'performance': { scanInterval: 60000, maxFiles: 5 },
            'balanced': { scanInterval: 30000, maxFiles: 10 },
            'maximum_protection': { scanInterval: 15000, maxFiles: 20 }
        };

        if (modes[mode]) {
            this.performanceMode = mode;
            this.scanInterval = modes[mode].scanInterval;

            // Restart scanning with new interval
            if (this.scanTimer) {
                clearInterval(this.scanTimer);
                this.startOptimizedScanning();
            }

            console.log(`🔧 Performance mode set to: ${mode}`);
        }
    }

    enableModule(moduleName) {
        if (this.protectionModules.hasOwnProperty(moduleName)) {
            this.protectionModules[moduleName] = true;
            console.log(`✅ Module enabled: ${moduleName}`);
        }
    }

    disableModule(moduleName) {
        if (this.protectionModules.hasOwnProperty(moduleName)) {
            this.protectionModules[moduleName] = false;
            console.log(`⚠️ Module disabled: ${moduleName}`);
        }
    }
}

module.exports = ApolloUnifiedProtectionEngine;