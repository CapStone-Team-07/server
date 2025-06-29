// models/Asset.js - Asset Management Model
const mongoose = require('mongoose');

const assetSchema = new mongoose.Schema({
  // Basic Information
  assetId: {
    type: String,
    required: true,
    unique: true,
    match: /^AST-\d{4}$/
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
      'Web Server', 'Database Server', 'Domain Controller', 'Email Server',
      'Firewall', 'Router', 'Switch', 'Workstation', 'Mobile Device',
      'Cloud Instance', 'Container', 'IoT Device', 'Network Printer', 'VPN Gateway'
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
  
  // System Information
  operatingSystem: {
    type: String,
    required: true,
    trim: true
  },
  osVersion: {
    type: String,
    trim: true
  },
  hostname: {
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
    enum: ['Online', 'Offline', 'Warning', 'Maintenance', 'Decommissioned'],
    default: 'Online'
  },
  lastSeen: {
    type: Date,
    required: true,
    default: Date.now
  },
  uptime: {
    type: Number, // percentage
    min: 0,
    max: 100,
    default: 100
  },
  
  // Security Assessment
  criticality: {
    type: String,
    enum: ['Critical', 'High', 'Medium', 'Low'],
    default: 'Medium'
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
    enum: ['Very Low', 'Low', 'Medium', 'High', 'Critical'],
    default: 'Medium'
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
  
  // Hardware Information
  hardware: {
    manufacturer: String,
    model: String,
    serialNumber: String,
    cpu: String,
    memory: String,
    storage: String,
    warrantyExpiry: Date
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
      enum: ['Commercial', 'Open Source', 'Freeware', 'Trial']
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
      enum: ['Running', 'Stopped', 'Failed'],
      default: 'Running'
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
        enum: ['Active', 'Inactive', 'Outdated', 'Unknown'],
        default: 'Unknown'
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
        enum: ['Compliant', 'Non-Compliant', 'Partial', 'Unknown']
      },
      lastAssessment: Date,
      score: Number
    }],
    policies: [{
      name: String,
      status: {
        type: String,
        enum: ['Compliant', 'Non-Compliant', 'Exempt']
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
  
  // Configuration Management
  configuration: {
    baseline: {
      type: mongoose.Schema.Types.Mixed,
      default: {}
    },
    current: {
      type: mongoose.Schema.Types.Mixed,
      default: {}
    },
    driftDetected: {
      type: Boolean,
      default: false
    },
    lastConfigScan: {
      type: Date,
      default: null
    }
  },
  
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
    enum: ['Public', 'Internal', 'Confidential', 'Restricted'],
    default: 'Internal'
  },
  
  // Monitoring and Metrics
  metrics: {
    cpuUsage: { type: Number, min: 0, max: 100 },
    memoryUsage: { type: Number, min: 0, max: 100 },
    diskUsage: { type: Number, min: 0, max: 100 },
    networkTraffic: Number,
    lastMetricsUpdate: Date
  },
  
  // Discovery Information
  discoveryMethod: {
    type: String,
    enum: ['Network Scan', 'Agent', 'Manual', 'Import', 'CMDB Sync'],
    default: 'Network Scan'
  },
  discoveredBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  },
  
  // Asset Relationships
  dependencies: [{
    assetId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'Asset'
    },
    relationship: {
      type: String,
      enum: ['Depends On', 'Supports', 'Connected To', 'Hosted On']
    },
    description: String
  }],
  
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
assetSchema.index({ type: 1 });
assetSchema.index({ status: 1 });
assetSchema.index({ criticality: 1 });
assetSchema.index({ owner: 1 });
assetSchema.index({ location: 1 });
assetSchema.index({ lastSeen: -1 });
assetSchema.index({ tags: 1 });

// Compound indexes
assetSchema.index({ type: 1, status: 1 });
assetSchema.index({ criticality: 1, riskLevel: 1 });

// Virtual for total vulnerabilities count
assetSchema.virtual('totalVulnerabilities').get(function() {
  return this.vulnerabilities.critical + this.vulnerabilities.high + 
         this.vulnerabilities.medium + this.vulnerabilities.low;
});

// Virtual for asset age
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

// Pre-save middleware to generate asset ID
assetSchema.pre('save', async function(next) {
  if (!this.assetId) {
    try {
      const lastAsset = await this.constructor.findOne({}, {}, { sort: { 'assetId': -1 } });
      
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
  
  // Update last seen
  if (this.isModified() && !this.isNew) {
    this.lastSeen = new Date();
  }
  
  next();
});

// Instance method to calculate risk score
assetSchema.methods.calculateRiskScore = function() {
  let score = 0;
  
  // Criticality weight (40%)
  const criticalityWeight = {
    'Critical': 40,
    'High': 30,
    'Medium': 20,
    'Low': 10
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

// Static method to get asset statistics
assetSchema.statics.getAssetStatistics = async function(filter = {}) {
  const pipeline = [
    { $match: filter },
    {
      $group: {
        _id: null,
        total: { $sum: 1 },
        online: {
          $sum: { $cond: [{ $eq: ['$status', 'Online'] }, 1, 0] }
        },
        offline: {
          $sum: { $cond: [{ $eq: ['$status', 'Offline'] }, 1, 0] }
        },
        critical: {
          $sum: { $cond: [{ $eq: ['$criticality', 'Critical'] }, 1, 0] }
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
        }
      }
    }
  ];
  
  const result = await this.aggregate(pipeline);
  return result[0] || {
    total: 0,
    online: 0,
    offline: 0,
    critical: 0,
    avgSecurityScore: 0,
    avgComplianceScore: 0,
    totalVulnerabilities: 0
  };
};

module.exports = mongoose.model('Asset', assetSchema);