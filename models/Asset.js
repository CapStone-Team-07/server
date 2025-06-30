// models/Asset.js - Updated Asset Management Model for Network Monitoring
const mongoose = require('mongoose');

const assetSchema = new mongoose.Schema({
  // Basic Information
  assetId: {
    type: String,
    required: false,// from true to false
    unique: true,
    // match: /^AST-\d{4}$/ 
  },
  name: {
    type: String,
    required: [true, 'Asset name is required'],
    trim: true,
    maxlength: [100, 'Asset name cannot exceed 100 characters']
  },
  type: {
    type: String,
    required: true,
    enum: [
      'firewall', 'switch', 'router', 'workstation', 'server', 
      'mobile_device', 'printer', 'cloud_instance', 'container', 
      'iot_device', 'vpn_gateway', 'access_point'
    ]
  },
  
  // Network Information
  ipAddress: {
    type: String,
    required: true,
    validate: {
      validator: function(v) {
        return /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/.test(v);
      },
      message: 'Invalid IP address format'
    }
  },
  macAddress: {
    type: String,
    validate: {
      validator: function(v) {
        return /^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$/.test(v);
      },
      message: 'Invalid MAC address format'
    }
  },
  hostname: {
    type: String,
    trim: true
  },
  
  // Network Topology - Connections to other assets
  connections: [{
    type: String, // Asset IDs or names that this asset is connected to
    required: false
  }],
  
  // Position for topology visualization
  position: {
    x: {
      type: Number,
      default: 0
    },
    y: {
      type: Number,
      default: 0
    }
  },
  
  // System Information
  operatingSystem: {
    type: String,
    trim: true
  },
  osVersion: {
    type: String,
    trim: true
  },
  
  // Location and Ownership
  location: {
    type: String,
    required: true,
    trim: true
  },
  department: {
    type: String,
    trim: true
  },
  owner: {
    type: String,
    required: true,
    trim: true
  },
  ownerContact: {
    type: String,
    trim: true
  },
  
  // Status and Monitoring
  status: {
    type: String,
    enum: ['online', 'offline', 'warning', 'maintenance', 'decommissioned'],
    default: 'online'
  },
  lastSeen: {
    type: Date,
    required: true,
    default: Date.now
  },
  uptime: {
    type: Number, // days
    min: 0,
    default: 0
  },
  
  // Security Assessment
  criticality: {
    type: String,
    enum: ['critical', 'high', 'medium', 'low'],
    default: 'medium'
  },
  securityScore: {
    type: Number,
    min: 0,
    max: 100,
    default: 50
  },
  complianceScore: {
    type: Number,
    min: 0,
    max: 100,
    default: 70
  },
  riskLevel: {
    type: String,
    enum: ['very_low', 'low', 'medium', 'high', 'critical'],
    default: 'medium'
  },
  
  // Real-time Performance Metrics (as shown in AssetsMonitored component)
  metadata: {
    // Performance metrics
    cpu: {
      type: Number,
      min: 0,
      max: 100,
      default: 0
    },
    memory: {
      type: Number,
      min: 0,
      max: 100,
      default: 0
    },
    storage: {
      type: Number,
      min: 0,
      max: 100,
      default: 0
    },
    networkLoad: {
      type: Number,
      min: 0,
      max: 100,
      default: 0
    },
    
    // Network-specific metrics
    throughput: String, // e.g., "150 Mbps"
    bandwidth: String,  // e.g., "1 Gbps"
    connectedDevices: Number,
    activeports: Number,
    
    // Device-specific information
    manufacturer: String,
    model: String,
    serialNumber: String,
    firmware: String,
    version: String,
    
    // Security-specific metadata
    rules: Number, // For firewalls
    ports: Number, // For switches/routers
    
    // User information (for workstations)
    user: String,
    domain: String,
    lastLogin: String,
    
    // Additional flexible metadata
    warrantyExpiry: Date,
    lastMaintenanceDate: Date,
    nextMaintenanceDate: Date
  },
  
  // Vulnerability Information
  vulnerabilities: {
    total: { type: Number, default: 0 },
    critical: { type: Number, default: 0 },
    high: { type: Number, default: 0 },
    medium: { type: Number, default: 0 },
    low: { type: Number, default: 0 }
  },
  lastVulnScan: {
    type: Date,
    default: null
  },
  nextVulnScan: {
    type: Date,
    default: null
  },
  
  // Patch Management
  patchLevel: {
    type: Number, // percentage
    min: 0,
    max: 100,
    default: 100
  },
  lastPatchDate: {
    type: Date,
    default: null
  },
  pendingPatches: {
    type: Number,
    default: 0
  },
  
  // Software Information
  software: [{
    name: {
      type: String,
      required: true
    },
    version: String,
    vendor: String,
    licenseType: {
      type: String,
      enum: ['Commercial', 'Open Source', 'Freeware', 'Trial', 'Built-in']
    },
    installDate: Date,
    lastUpdate: Date
  }],
  
  // Network Services
  services: [{
    name: {
      type: String,
      required: true
    },
    port: {
      type: Number,
      min: 1,
      max: 65535
    },
    protocol: {
      type: String,
      enum: ['TCP', 'UDP']
    },
    status: {
      type: String,
      enum: ['running', 'stopped', 'failed', 'disabled'],
      default: 'running'
    },
    version: String
  }],
  
  // Security Controls
  securityControls: {
    antivirus: {
      installed: { type: Boolean, default: false },
      product: String,
      version: String,
      lastUpdate: Date,
      status: {
        type: String,
        enum: ['active', 'inactive', 'outdated', 'unknown'],
        default: 'unknown'
      }
    },
    firewall: {
      enabled: { type: Boolean, default: false },
      type: String,
      rules: Number
    },
    encryption: {
      enabled: { type: Boolean, default: false },
      type: String,
      algorithm: String
    },
    backups: {
      enabled: { type: Boolean, default: false },
      frequency: String,
      lastBackup: Date,
      retention: String
    },
    monitoring: {
      enabled: { type: Boolean, default: false },
      agent: String,
      version: String
    }
  },
  
  // Compliance and Audit
  compliance: {
    frameworks: [{
      name: String,
      status: {
        type: String,
        enum: ['compliant', 'non_compliant', 'partial', 'unknown']
      },
      lastAssessment: Date,
      score: Number
    }],
    policies: [{
      name: String,
      status: {
        type: String,
        enum: ['compliant', 'non_compliant', 'exempt']
      },
      lastCheck: Date
    }]
  },
  
  // Incident History
  incidents: [{
    incidentId: String,
    type: String,
    severity: String,
    date: Date,
    resolved: Boolean,
    resolutionDate: Date
  }],
  
  // Asset Lifecycle
  lifecycle: {
    acquisitionDate: Date,
    deploymentDate: Date,
    lastMaintenanceDate: Date,
    nextMaintenanceDate: Date,
    endOfLifeDate: Date,
    retirementDate: Date
  },
  
  // Financial Information
  financial: {
    acquisitionCost: Number,
    currentValue: Number,
    maintenanceCost: Number,
    currency: {
      type: String,
      default: 'USD'
    }
  },
  
  // Tags and Classification
  tags: [String],
  businessFunction: String,
  dataClassification: {
    type: String,
    enum: ['public', 'internal', 'confidential', 'restricted'],
    default: 'internal'
  },
  
  // Discovery Information
  discoveryMethod: {
    type: String,
    enum: ['network_scan', 'agent', 'manual', 'import', 'cmdb_sync'],
    default: 'network_scan'
  },
  discoveredBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  },
  
  // Asset Dependencies (for network topology)
  dependencies: [{
    assetId: {
      type: String, // Can be assetId or mongoose ObjectId
      required: true
    },
    relationship: {
      type: String,
      enum: ['depends_on', 'supports', 'connected_to', 'hosted_on'],
      required: true
    },
    description: String
  }],
  
  // Monitoring Configuration
  monitoring: {
    enabled: { type: Boolean, default: true },
    intervals: {
      heartbeat: { type: Number, default: 30 }, // seconds
      performance: { type: Number, default: 300 }, // seconds
      vulnerability: { type: Number, default: 86400 } // seconds (daily)
    },
    thresholds: {
      cpu: { type: Number, default: 80 },
      memory: { type: Number, default: 85 },
      storage: { type: Number, default: 90 },
      network: { type: Number, default: 75 }
    }
  },
  
  // Alert Configuration
  alerts: {
    enabled: { type: Boolean, default: true },
    notifications: [{
      type: {
        type: String,
        enum: ['email', 'sms', 'webhook', 'slack']
      },
      endpoint: String, // email address, phone number, webhook URL, etc.
      enabled: { type: Boolean, default: true }
    }]
  },
  
  // Audit Trail
  lastUpdatedBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  },
  notes: {
    type: String,
    maxlength: 2000
  }
}, {
  timestamps: true,
  toJSON: { virtuals: true },
  toObject: { virtuals: true }
});

// Indexes for performance
assetSchema.index({ assetId: 1 });
assetSchema.index({ ipAddress: 1 });
assetSchema.index({ name: 1 });
assetSchema.index({ type: 1 });
assetSchema.index({ status: 1 });
assetSchema.index({ criticality: 1 });
assetSchema.index({ owner: 1 });
assetSchema.index({ location: 1 });
assetSchema.index({ lastSeen: -1 });
assetSchema.index({ tags: 1 });
assetSchema.index({ hostname: 1 });

// Compound indexes
assetSchema.index({ type: 1, status: 1 });
assetSchema.index({ criticality: 1, riskLevel: 1 });
assetSchema.index({ location: 1, type: 1 });

// Text index for search functionality
assetSchema.index({
  name: 'text',
  hostname: 'text',
  ipAddress: 'text',
  'metadata.model': 'text',
  'metadata.manufacturer': 'text'
});

// Virtual for total vulnerabilities count
assetSchema.virtual('totalVulnerabilities').get(function() {
  return this.vulnerabilities.critical + this.vulnerabilities.high + 
         this.vulnerabilities.medium + this.vulnerabilities.low;
});

// Virtual for asset age in days
assetSchema.virtual('age').get(function() {
  if (this.lifecycle.deploymentDate) {
    return Math.floor((Date.now() - this.lifecycle.deploymentDate) / (1000 * 60 * 60 * 24));
  }
  return 0;
});

// Virtual for days since last seen
assetSchema.virtual('daysSinceLastSeen').get(function() {
  return Math.floor((Date.now() - this.lastSeen) / (1000 * 60 * 60 * 24));
});

// Virtual for overall health score
assetSchema.virtual('healthScore').get(function() {
  if (this.status === 'offline') return 0;
  
  let score = 100;
  
  // Deduct points for high resource usage
  if (this.metadata.cpu > 80) score -= 10;
  if (this.metadata.memory > 85) score -= 10;
  if (this.metadata.storage > 90) score -= 15;
  
  // Deduct points for vulnerabilities
  score -= (this.vulnerabilities.critical * 5);
  score -= (this.vulnerabilities.high * 2);
  
  // Deduct points for outdated patches
  score -= ((100 - this.patchLevel) * 0.2);
  
  return Math.max(0, Math.round(score));
});

// Virtual for network topology info (used in AssetsMonitored component)
assetSchema.virtual('typeInfo').get(function() {
  const typeMapping = {
    'firewall': { icon: 'Shield', color: '#ef4444', category: 'Security' },
    'switch': { icon: 'Router', color: '#3b82f6', category: 'Network' },
    'router': { icon: 'Router', color: '#8b5cf6', category: 'Network' },
    'workstation': { icon: 'Monitor', color: '#f59e0b', category: 'Endpoint' },
    'server': { icon: 'Server', color: '#10b981', category: 'Infrastructure' },
    'mobile_device': { icon: 'Smartphone', color: '#ec4899', category: 'Endpoint' },
    'printer': { icon: 'Printer', color: '#6b7280', category: 'Peripheral' },
    'access_point': { icon: 'Wifi', color: '#06b6d4', category: 'Network' }
  };
  
  return typeMapping[this.type] || { icon: 'HardDrive', color: '#6b7280', category: 'Unknown' };
});

// Pre-save middleware to generate asset ID
// No more using middlware | automatically generating assetId in seedDatabase.js 
assetSchema.pre('save', async function(next) {
  if (!this.assetId) {
    try {
      const lastAsset = await this.constructor.findOne({}, {}, { sort: { 'assetId': -1 } });
      console.log('🕔 Last Asset:', lastAsset);
      let nextNumber = 1;
      if (lastAsset && lastAsset.assetId) {
        const match = lastAsset.assetId.match(/AST-(\d{4})/);
        if (match) {
          nextNumber = parseInt(match[1]) + 1;
        }
      }
      
      this.assetId = `AST-${nextNumber.toString().padStart(4, '0')}`;
    } catch (error) {
      return next(error);
    }
  }
  
  // Update last seen when asset is modified (except for new assets)
  if (this.isModified() && !this.isNew) {
    this.lastSeen = new Date();
  }
  
  // Auto-calculate uptime if deployment date exists
  if (this.lifecycle.deploymentDate && this.status === 'online') {
    const daysSinceDeployment = Math.floor((Date.now() - this.lifecycle.deploymentDate) / (1000 * 60 * 60 * 24));
    if (daysSinceDeployment > 0) {
      this.uptime = daysSinceDeployment;
    }
  }
  
  next();
});

// Instance method to calculate risk score
assetSchema.methods.calculateRiskScore = function() {
  let score = 0;
  
  // Criticality weight (40%)
  const criticalityWeight = {
    'critical': 40,
    'high': 30,
    'medium': 20,
    'low': 10
  };
  score += criticalityWeight[this.criticality] || 20;
  
  // Vulnerability weight (30%)
  const vulnScore = (this.vulnerabilities.critical * 10) + 
                   (this.vulnerabilities.high * 5) + 
                   (this.vulnerabilities.medium * 2) + 
                   (this.vulnerabilities.low * 1);
  score += Math.min(vulnScore, 30);
  
  // Patch level weight (20%)
  score += (100 - this.patchLevel) * 0.2;
  
  // Compliance weight (10%)
  score += (100 - this.complianceScore) * 0.1;
  
  return Math.round(Math.min(score, 100));
};

// Instance method to update performance metrics
assetSchema.methods.updateMetrics = function(metrics) {
  if (metrics.cpu !== undefined) this.metadata.cpu = metrics.cpu;
  if (metrics.memory !== undefined) this.metadata.memory = metrics.memory;
  if (metrics.storage !== undefined) this.metadata.storage = metrics.storage;
  if (metrics.networkLoad !== undefined) this.metadata.networkLoad = metrics.networkLoad;
  
  this.lastSeen = new Date();
  
  return this.save();
};

// Instance method to add connection
assetSchema.methods.addConnection = function(targetAssetId, relationship = 'connected_to') {
  // Avoid duplicate connections
  const existingConnection = this.dependencies.find(dep => dep.assetId === targetAssetId);
  
  if (!existingConnection) {
    this.dependencies.push({
      assetId: targetAssetId,
      relationship: relationship
    });
  }
  
  // Also add to connections array for topology visualization
  if (!this.connections.includes(targetAssetId)) {
    this.connections.push(targetAssetId);
  }
  
  return this.save();
};

// Static method to get asset statistics
assetSchema.statics.getAssetStatistics = async function(filter = {}) {
  const pipeline = [
    { $match: filter },
    {
      $group: {
        _id: null,
        total: { $sum: 1 },
        online: {
          $sum: { $cond: [{ $eq: ['$status', 'online'] }, 1, 0] }
        },
        offline: {
          $sum: { $cond: [{ $eq: ['$status', 'offline'] }, 1, 0] }
        },
        warning: {
          $sum: { $cond: [{ $eq: ['$status', 'warning'] }, 1, 0] }
        },
        critical: {
          $sum: { $cond: [{ $eq: ['$criticality', 'critical'] }, 1, 0] }
        },
        avgSecurityScore: { $avg: '$securityScore' },
        avgComplianceScore: { $avg: '$complianceScore' },
        totalVulnerabilities: {
          $sum: {
            $add: [
              '$vulnerabilities.critical',
              '$vulnerabilities.high',
              '$vulnerabilities.medium',
              '$vulnerabilities.low'
            ]
          }
        },
        avgCpuUsage: { $avg: '$metadata.cpu' },
        avgMemoryUsage: { $avg: '$metadata.memory' }
      }
    }
  ];
  
  const result = await this.aggregate(pipeline);
  return result[0] || {
    total: 0,
    online: 0,
    offline: 0,
    warning: 0,
    critical: 0,
    avgSecurityScore: 0,
    avgComplianceScore: 0,
    totalVulnerabilities: 0,
    avgCpuUsage: 0,
    avgMemoryUsage: 0
  };
};

// Static method to get assets by location
assetSchema.statics.getAssetsByLocation = function() {
  return this.aggregate([
    {
      $group: {
        _id: '$location',
        count: { $sum: 1 },
        online: {
          $sum: { $cond: [{ $eq: ['$status', 'online'] }, 1, 0] }
        },
        offline: {
          $sum: { $cond: [{ $eq: ['$status', 'offline'] }, 1, 0] }
        },
        types: { $addToSet: '$type' }
      }
    },
    { $sort: { count: -1 } }
  ]);
};

// Static method to get network topology data
assetSchema.statics.getNetworkTopology = function(filter = {}) {
  return this.find(filter, {
    assetId: 1,
    name: 1,
    type: 1,
    ipAddress: 1,
    status: 1,
    criticality: 1,
    location: 1,
    position: 1,
    connections: 1,
    metadata: 1,
    lastSeen: 1,
    uptime: 1
  }).lean();
};

// Static method to search assets
assetSchema.statics.searchAssets = function(searchTerm, filters = {}) {
  const query = { ...filters };
  
  if (searchTerm) {
    query.$or = [
      { name: { $regex: searchTerm, $options: 'i' } },
      { hostname: { $regex: searchTerm, $options: 'i' } },
      { ipAddress: { $regex: searchTerm, $options: 'i' } },
      { type: { $regex: searchTerm, $options: 'i' } },
      { location: { $regex: searchTerm, $options: 'i' } }
    ];
  }
  
  return this.find(query).sort({ lastSeen: -1 });
};

module.exports = mongoose.model('Asset', assetSchema);