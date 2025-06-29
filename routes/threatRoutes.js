// routes/threatRoutes.js - Threat Management Routes
const express = require('express');
const { body } = require('express-validator');
const {
  getThreats,
  getThreat,
  createThreat,
  updateThreat,
  deleteThreat,
  blockThreat,
  escalateThreat,
  resolveThreat,
  addIOC,
  toggleStar,
  toggleFlag,
  getThreatStats,
  getTrendingThreats,
  getTopSources,
  bulkUpdateThreats,
  assignThreat,
  getThreatTimeline,
  exportThreats
} = require('../controllers/threatController');

const { 
  protect, 
  requirePermission, 
  authorize,
  auditLog 
} = require('../middleware/authMiddleware');

const router = express.Router();

// Validation rules for threat creation
const createThreatValidation = [
  body('title')
    .isLength({ min: 1, max: 200 })
    .withMessage('Title is required and must be less than 200 characters')
    .trim(),
  body('description')
    .isLength({ min: 1, max: 1000 })
    .withMessage('Description is required and must be less than 1000 characters')
    .trim(),
  body('severity')
    .isIn(['Critical', 'High', 'Medium', 'Low'])
    .withMessage('Invalid severity level'),
  body('category')
    .isIn([
      'Malware', 'Phishing', 'Brute Force', 'Data Exfiltration', 
      'Insider Threat', 'Advanced Persistent Threat', 'Ransomware', 
      'DDoS', 'SQL Injection', 'Cross-Site Scripting', 'Zero-Day Exploit',
      'Social Engineering', 'Man-in-the-Middle', 'Buffer Overflow'
    ])
    .withMessage('Invalid threat category'),
  body('sourceIP')
    .isIP(4)
    .withMessage('Valid source IP address is required'),
  body('targetIP')
    .isIP(4)
    .withMessage('Valid target IP address is required'),
  body('protocol')
    .isIn(['TCP', 'UDP', 'HTTP', 'HTTPS', 'FTP', 'SSH', 'DNS', 'SMTP', 'ICMP'])
    .withMessage('Invalid protocol'),
  body('riskScore')
    .isInt({ min: 0, max: 100 })
    .withMessage('Risk score must be between 0 and 100'),
  body('confidence')
    .isInt({ min: 0, max: 100 })
    .withMessage('Confidence must be between 0 and 100'),
  body('country')
    .isLength({ min: 1 })
    .withMessage('Country is required')
    .trim(),
  body('attackVector')
    .isLength({ min: 1 })
    .withMessage('Attack vector is required')
    .trim(),
  body('source')
    .isIn(['Firewall', 'IDS/IPS', 'Endpoint Detection', 'Email Security', 'Network Monitor', 'SIEM', 'Threat Intel', 'Manual'])
    .withMessage('Invalid detection source')
];

// Statistics and analytics routes (no specific threat ID)
router.get('/stats', protect, requirePermission('threats:read'), getThreatStats);
router.get('/trending', protect, requirePermission('threats:read'), getTrendingThreats);
router.get('/top-sources', protect, requirePermission('threats:read'), getTopSources);
router.get('/timeline', protect, requirePermission('threats:read'), getThreatTimeline);
router.get('/export', protect, requirePermission('threats:read'), auditLog('THREATS_EXPORT'), exportThreats);

// Bulk operations
router.put('/bulk', protect, requirePermission('threats:write'), auditLog('THREATS_BULK_UPDATE'), bulkUpdateThreats);

// Main CRUD routes
router.route('/')
  .get(protect, requirePermission('threats:read'), getThreats)
  .post(protect, requirePermission('threats:write'), createThreatValidation, auditLog('THREAT_CREATE'), createThreat);

// Individual threat routes
router.route('/:id')
  .get(protect, requirePermission('threats:read'), getThreat)
  .put(protect, requirePermission('threats:write'), auditLog('THREAT_UPDATE'), updateThreat)
  .delete(protect, authorize('admin', 'soc_manager'), auditLog('THREAT_DELETE'), deleteThreat);

// Threat actions
router.post('/:id/block', protect, requirePermission('threats:write'), auditLog('THREAT_BLOCK'), blockThreat);
router.post('/:id/escalate', protect, requirePermission('threats:write'), auditLog('THREAT_ESCALATE'), escalateThreat);
router.post('/:id/resolve', protect, requirePermission('threats:write'), auditLog('THREAT_RESOLVE'), resolveThreat);

// Threat management
router.put('/:id/assign', protect, authorize('admin', 'soc_manager'), auditLog('THREAT_ASSIGN'), assignThreat);
router.post('/:id/star', protect, requirePermission('threats:read'), toggleStar);
router.post('/:id/flag', protect, requirePermission('threats:read'), toggleFlag);

// IOC management
router.post('/:id/iocs', protect, requirePermission('threats:write'), 
  [
    body('type')
      .isIn(['ipAddresses', 'domains', 'urls', 'fileHashes', 'emailAddresses', 'fileNames'])
      .withMessage('Invalid IOC type'),
    body('value')
      .isLength({ min: 1 })
      .withMessage('IOC value is required')
      .trim()
  ],
  auditLog('IOC_ADD'), 
  addIOC
);

module.exports = router;