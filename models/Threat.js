// models/Threat.js - Complete Threat Model
const mongoose = require('mongoose');

const threatSchema = new mongoose.Schema({
  // Basic Information
  threatId: {
    type: String,
    required: true,
    unique: true,
    match: /^THR-\d{6}$/
  },
  title: {
    type: String,
    required: [true, 'Threat title is required'],
    trim: true,
    maxlength: [200, 'Title cannot exceed 200 characters']
  },
  description: {
    type: String,
    required: [true, 'Threat description is required'],
    trim: true,
    maxlength: [1000, 'Description cannot exceed 1000 characters']
  },
  
  // Classification
  severity: {
    type: String,
    required: true,
    enum: ['Critical', 'High', 'Medium', 'Low'],
    default: 'Medium'
  },
  category: {
    type: String,
    required: true,
    enum: [
      'Malware', 'Phishing', 'Brute Force', 'Data Exfiltration', 
      'Insider Threat', 'Advanced Persistent Threat', 'Ransomware', 
      'DDoS', 'SQL Injection', 'Cross-Site Scripting', 'Zero-Day Exploit',
      'Social Engineering', 'Man-in-the-Middle', 'Buffer Overflow'
    ]
  },
  status: {
    type: String,
    enum: ['Active', 'Investigating', 'Contained', 'Resolved', 'Blocked', 'Escalated', 'False Positive'],
    default: 'Active'
  },
  
  // Risk Assessment
  riskScore: {
    type: Number,
    required: true,
    min: 0,
    max: 100,
    default: 50
  },
  confidence: {
    type: Number,
    required: true,
    min: 0,
    max: 100,
    default: 70
  },
  
  // Network Information
  sourceIP: {
    type: String,
    required: true,
    validate: {
      validator: function(v) {
        return /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/.test(v);
      },
      message: 'Invalid IP address format'
    }
  },
  targetIP: {
    type: String,
    required: true,
    validate: {
      validator: function(v) {
        return /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/.test(v);
      },
      message: 'Invalid IP address format'
    }
  },
  protocol: {
    type: String,
    enum: ['TCP', 'UDP', 'HTTP', 'HTTPS', 'FTP', 'SSH', 'DNS', 'SMTP', 'ICMP'],
    required: true
  },
  port: {
    type: Number,
    min: 1,
    max: 65535
  },
  
  // Geolocation
  country: {
    type: String,
    required: true,
    trim: true
  },
  region: {
    type: String,
    trim: true
  },
  city: {
    type: String,
    trim: true
  },
  
  // Attack Details
  attackVector: {
    type: String,
    required: true,
    trim: true
  },
  mitreTactics: {
    type: String,
    enum: [
      'Initial Access', 'Execution', 'Persistence', 'Privilege Escalation',
      'Defense Evasion', 'Credential Access', 'Discovery', 'Lateral Movement',
      'Collection', 'Command and Control', 'Exfiltration', 'Impact'
    ]
  },
  mitreId: {
    type: String,
    trim: true,
    match: /^T\d{4}(\.\d{3})?$/
  },
  
  // Detection Source
  source: {
    type: String,
    required: true,
    enum: ['Firewall', 'IDS/IPS', 'Endpoint Detection', 'Email Security', 'Network Monitor', 'SIEM', 'Threat Intel', 'Manual']
  },
  detectionRule: {
    type: String,
    trim: true
  },
  
  // Impact Assessment
  affectedAssets: {
    type: Number,
    default: 0,
    min: 0
  },
  affectedUsers: {
    type: Number,
    default: 0,
    min: 0
  },
  businessImpact: {
    type: String,
    enum: ['None', 'Low', 'Medium', 'High', 'Critical'],
    default: 'Low'
  },
  
  // IOCs (Indicators of Compromise)
  iocs: {
    ipAddresses: [String],
    domains: [String],
    urls: [String],
    fileHashes: [String],
    emailAddresses: [String],
    fileNames: [String]
  },
  iocsCount: {
    type: Number,
    default: 0
  },
  
  // Timeline
  firstSeen: {
    type: Date,
    required: true,
    default: Date.now
  },
  lastActivity: {
    type: Date,
    required: true,
    default: Date.now
  },
  containmentTime: {
    type: Number, // minutes
    default: null
  },
  resolutionTime: {
    type: Number, // minutes
    default: null
  },
  
  // Assignment and Tracking
  analyst: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  analystName: {
    type: String,
    required: true
  },
  escalatedTo: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    default: null
  },
  
  // Actions Taken
  actions: [{
    type: {
      type: String,
      enum: ['block', 'escalate', 'resolve', 'investigate', 'contain', 'monitor'],
      required: true
    },
    timestamp: {
      type: Date,
      required: true,
      default: Date.now
    },
    user: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      required: true
    },
    userName: {
      type: String,
      required: true
    },
    notes: {
      type: String,
      maxlength: 500
    },
    metadata: {
      type: mongoose.Schema.Types.Mixed,
      default: {}
    }
  }],
  
  // Status Tracking
  blockedAt: {
    type: Date,
    default: null
  },
  escalatedAt: {
    type: Date,
    default: null
  },
  resolvedAt: {
    type: Date,
    default: null
  },
  blockedBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    default: null
  },
  escalatedBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    default: null
  },
  resolvedBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    default: null
  },
  
  // Additional Information
  notes: {
    type: String,
    maxlength: 2000,
    default: ''
  },
  starred: {
    type: Boolean,
    default: false
  },
  flagged: {
    type: Boolean,
    default: false
  },
  tags: [String],
  
  // Related Threats
  relatedThreats: [{
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Threat'
  }],
  
  // Evidence and Artifacts
  evidence: [{
    type: {
      type: String,
      enum: ['log', 'screenshot', 'file', 'pcap', 'memory_dump']
    },
    fileName: String,
    filePath: String,
    fileSize: Number,
    uploadedBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User'
    },
    uploadedAt: {
      type: Date,
      default: Date.now
    },
    description: String,
    hash: String // File hash for integrity verification
  }],
  
  // Communication and Collaboration
  comments: [{
    user: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      required: true
    },
    userName: {
      type: String,
      required: true
    },
    content: {
      type: String,
      required: true,
      maxlength: 1000
    },
    timestamp: {
      type: Date,
      default: Date.now
    },
    edited: {
      type: Boolean,
      default: false
    },
    editedAt: {
      type: Date
    }
  }],
  
  // Notification Preferences
  watchers: [{
    user: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User'
    },
    notificationPreferences: {
      statusChanges: {
        type: Boolean,
        default: true
      },
      newComments: {
        type: Boolean,
        default: true
      },
      escalations: {
        type: Boolean,
        default: true
      }
    }
  }],
  
  // External References
  externalReferences: [{
    source: {
      type: String,
      enum: ['CVE', 'MITRE', 'NIST', 'FBI', 'CISA', 'Other']
    },
    referenceId: String,
    url: String,
    description: String
  }],
  
  // Compliance and Regulatory
  complianceImpact: {
    frameworks: [{
      name: {
        type: String,
        enum: ['SOX', 'HIPAA', 'PCI-DSS', 'GDPR', 'ISO27001', 'NIST']
      },
      impactLevel: {
        type: String,
        enum: ['None', 'Low', 'Medium', 'High', 'Critical']
      }
    }],
    requiresReporting: {
      type: Boolean,
      default: false
    },
    reportingDeadline: Date
  },
  
  // Machine Learning and Analytics
  mlPredictions: {
    falsePositiveProbability: {
      type: Number,
      min: 0,
      max: 1
    },
    severityPrediction: {
      type: String,
      enum: ['Critical', 'High', 'Medium', 'Low']
    },
    similarThreats: [{
      threatId: String,
      similarity: Number
    }]
  },
  
  // Custom Fields for Organization-specific data
  customFields: {
    type: Map,
    of: mongoose.Schema.Types.Mixed,
    default: new Map()
  }
}, {
  timestamps: true, // Adds createdAt and updatedAt automatically
  toJSON: { virtuals: true },
  toObject: { virtuals: true }
});

// Indexes for better query performance
threatSchema.index({ threatId: 1 });
threatSchema.index({ sourceIP: 1 });
threatSchema.index({ targetIP: 1 });
threatSchema.index({ severity: 1, status: 1 });
threatSchema.index({ category: 1 });
threatSchema.index({ analyst: 1 });
threatSchema.index({ firstSeen: -1 });
threatSchema.index({ riskScore: -1 });
threatSchema.index({ country: 1 });
threatSchema.index({ 'actions.type': 1, 'actions.timestamp': -1 });

// Compound indexes for complex queries
threatSchema.index({ status: 1, severity: 1, firstSeen: -1 });
threatSchema.index({ analyst: 1, status: 1, severity: 1 });

// Text index for search functionality
threatSchema.index({
  title: 'text',
  description: 'text',
  'notes': 'text',
  'comments.content': 'text'
});

// Virtual fields
threatSchema.virtual('duration').get(function() {
  if (this.resolvedAt) {
    return Math.floor((this.resolvedAt - this.firstSeen) / (1000 * 60)); // Duration in minutes
  }
  return Math.floor((new Date() - this.firstSeen) / (1000 * 60));
});

threatSchema.virtual('isActive').get(function() {
  return ['Active', 'Investigating', 'Escalated'].includes(this.status);
});

threatSchema.virtual('totalIOCs').get(function() {
  if (!this.iocs) return 0;
  return Object.values(this.iocs).reduce((total, arr) => total + (Array.isArray(arr) ? arr.length : 0), 0);
});

// Pre-save middleware
threatSchema.pre('save', function(next) {
  // Auto-generate threatId if not provided
  if (!this.threatId && this.isNew) {
    // This would typically be handled by a counter or sequence
    this.threatId = `THR-${String(Date.now()).slice(-6)}`;
  }
  
  // Update iocsCount
  this.iocsCount = this.totalIOCs;
  
  // Update lastActivity on any change
  if (!this.isNew) {
    this.lastActivity = new Date();
  }
  
  // Set resolution time when status changes to resolved
  if (this.status === 'Resolved' && !this.resolvedAt) {
    this.resolvedAt = new Date();
    this.resolutionTime = Math.floor((this.resolvedAt - this.firstSeen) / (1000 * 60));
  }
  
  next();
});

// Instance methods
threatSchema.methods.addAction = function(actionType, userId, userName, notes = '', metadata = {}) {
  this.actions.push({
    type: actionType,
    user: userId,
    userName: userName,
    notes: notes,
    metadata: metadata,
    timestamp: new Date()
  });
  
  // Update status tracking fields
  switch (actionType) {
    case 'block':
      this.blockedAt = new Date();
      this.blockedBy = userId;
      this.status = 'Blocked';
      break;
    case 'escalate':
      this.escalatedAt = new Date();
      this.escalatedBy = userId;
      this.status = 'Escalated';
      break;
    case 'resolve':
      this.resolvedAt = new Date();
      this.resolvedBy = userId;
      this.status = 'Resolved';
      break;
    case 'contain':
      this.status = 'Contained';
      this.containmentTime = Math.floor((new Date() - this.firstSeen) / (1000 * 60));
      break;
  }
  
  return this.save();
};

threatSchema.methods.addComment = function(userId, userName, content) {
  this.comments.push({
    user: userId,
    userName: userName,
    content: content,
    timestamp: new Date()
  });
  
  return this.save();
};

threatSchema.methods.addWatcher = function(userId, preferences = {}) {
  const existingWatcher = this.watchers.find(w => w.user.toString() === userId.toString());
  
  if (!existingWatcher) {
    this.watchers.push({
      user: userId,
      notificationPreferences: {
        statusChanges: preferences.statusChanges !== undefined ? preferences.statusChanges : true,
        newComments: preferences.newComments !== undefined ? preferences.newComments : true,
        escalations: preferences.escalations !== undefined ? preferences.escalations : true
      }
    });
  }
  
  return this.save();
};

// Static methods
threatSchema.statics.findByAnalyst = function(analystId, status = null) {
  const query = { analyst: analystId };
  if (status) {
    query.status = status;
  }
  return this.find(query).sort({ firstSeen: -1 });
};

threatSchema.statics.findActiveBySeverity = function(severity) {
  return this.find({
    severity: severity,
    status: { $in: ['Active', 'Investigating', 'Escalated'] }
  }).sort({ firstSeen: -1 });
};

threatSchema.statics.findByDateRange = function(startDate, endDate) {
  return this.find({
    firstSeen: {
      $gte: startDate,
      $lte: endDate
    }
  }).sort({ firstSeen: -1 });
};

threatSchema.statics.getStatsByAnalyst = function(analystId) {
  return this.aggregate([
    { $match: { analyst: mongoose.Types.ObjectId(analystId) } },
    {
      $group: {
        _id: '$status',
        count: { $sum: 1 },
        avgRiskScore: { $avg: '$riskScore' }
      }
    }
  ]);
};

threatSchema.statics.getTrendData = function(days = 30) {
  const startDate = new Date();
  startDate.setDate(startDate.getDate() - days);
  
  return this.aggregate([
    { $match: { firstSeen: { $gte: startDate } } },
    {
      $group: {
        _id: {
          date: { $dateToString: { format: '%Y-%m-%d', date: '$firstSeen' } },
          severity: '$severity'
        },
        count: { $sum: 1 }
      }
    },
    { $sort: { '_id.date': 1 } }
  ]);
};

// Export the model
module.exports = mongoose.model('Threat', threatSchema);