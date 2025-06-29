// routes/assetRoutes.js - Asset Management Routes
const express = require('express');
const { body } = require('express-validator');
const {
  getAssets,
  getAsset,
  createAsset,
  updateAsset,
  deleteAsset,
  getAssetStats,
  updateSecurityScan,
  updatePatchStatus,
  bulkUpdateAssets,
  getAssetsByLocation,
  exportAssets
} = require('../controllers/assetController');

const { 
  protect, 
  requirePermission, 
  authorize,
  auditLog 
} = require('../middleware/authMiddleware');

const router = express.Router();

// Validation rules for asset creation
const createAssetValidation = [
  body('name')
    .isLength({ min: 1, max: 100 })
    .withMessage('Asset name is required and must be less than 100 characters')
    .trim(),
  body('type')
    .isIn([
      'Web Server', 'Database Server', 'Domain Controller', 'Email Server',
      'Firewall', 'Router', 'Switch', 'Workstation', 'Mobile Device',
      'Cloud Instance', 'Container', 'IoT Device', 'Network Printer', 'VPN Gateway'
    ])
    .withMessage('Invalid asset type'),
  body('ipAddress')
    .isIP(4)
    .withMessage('Valid IP address is required'),
  body('macAddress')
    .optional()
    .matches(/^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$/)
    .withMessage('Invalid MAC address format'),
  body('operatingSystem')
    .isLength({ min: 1 })
    .withMessage('Operating system is required')
    .trim(),
  body('location')
    .isLength({ min: 1 })
    .withMessage('Location is required')
    .trim(),
  body('owner')
    .isLength({ min: 1 })
    .withMessage('Owner is required')
    .trim(),
  body('criticality')
    .optional()
    .isIn(['Critical', 'High', 'Medium', 'Low'])
    .withMessage('Invalid criticality level'),
  body('status')
    .optional()
    .isIn(['Online', 'Offline', 'Warning', 'Maintenance', 'Decommissioned'])
    .withMessage('Invalid status'),
  body('dataClassification')
    .optional()
    .isIn(['Public', 'Internal', 'Confidential', 'Restricted'])
    .withMessage('Invalid data classification'),
  body('securityScore')
    .optional()
    .isInt({ min: 0, max: 100 })
    .withMessage('Security score must be between 0 and 100'),
  body('complianceScore')
    .optional()
    .isInt({ min: 0, max: 100 })
    .withMessage('Compliance score must be between 0 and 100'),
  body('patchLevel')
    .optional()
    .isInt({ min: 0, max: 100 })
    .withMessage('Patch level must be between 0 and 100'),
  body('uptime')
    .optional()
    .isInt({ min: 0, max: 100 })
    .withMessage('Uptime must be between 0 and 100'),
  body('discoveryMethod')
    .optional()
    .isIn(['Network Scan', 'Agent', 'Manual', 'Import', 'CMDB Sync'])
    .withMessage('Invalid discovery method')
];

// Validation rules for asset updates
const updateAssetValidation = [
  body('name')
    .optional()
    .isLength({ min: 1, max: 100 })
    .withMessage('Asset name must be less than 100 characters')
    .trim(),
  body('ipAddress')
    .optional()
    .isIP(4)
    .withMessage('Valid IP address is required'),
  body('macAddress')
    .optional()
    .matches(/^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$/)
    .withMessage('Invalid MAC address format'),
  body('operatingSystem')
    .optional()
    .isLength({ min: 1 })
    .withMessage('Operating system cannot be empty')
    .trim(),
  body('location')
    .optional()
    .isLength({ min: 1 })
    .withMessage('Location cannot be empty')
    .trim(),
  body('owner')
    .optional()
    .isLength({ min: 1 })
    .withMessage('Owner cannot be empty')
    .trim(),
  body('criticality')
    .optional()
    .isIn(['Critical', 'High', 'Medium', 'Low'])
    .withMessage('Invalid criticality level'),
  body('status')
    .optional()
    .isIn(['Online', 'Offline', 'Warning', 'Maintenance', 'Decommissioned'])
    .withMessage('Invalid status'),
  body('securityScore')
    .optional()
    .isInt({ min: 0, max: 100 })
    .withMessage('Security score must be between 0 and 100'),
  body('complianceScore')
    .optional()
    .isInt({ min: 0, max: 100 })
    .withMessage('Compliance score must be between 0 and 100'),
  body('patchLevel')
    .optional()
    .isInt({ min: 0, max: 100 })
    .withMessage('Patch level must be between 0 and 100')
];

// Validation for security scan updates
const securityScanValidation = [
  body('vulnerabilities.critical')
    .optional()
    .isInt({ min: 0 })
    .withMessage('Critical vulnerabilities count must be a non-negative integer'),
  body('vulnerabilities.high')
    .optional()
    .isInt({ min: 0 })
    .withMessage('High vulnerabilities count must be a non-negative integer'),
  body('vulnerabilities.medium')
    .optional()
    .isInt({ min: 0 })
    .withMessage('Medium vulnerabilities count must be a non-negative integer'),
  body('vulnerabilities.low')
    .optional()
    .isInt({ min: 0 })
    .withMessage('Low vulnerabilities count must be a non-negative integer'),
  body('securityScore')
    .optional()
    .isInt({ min: 0, max: 100 })
    .withMessage('Security score must be between 0 and 100'),
  body('complianceScore')
    .optional()
    .isInt({ min: 0, max: 100 })
    .withMessage('Compliance score must be between 0 and 100'),
  body('lastVulnScan')
    .optional()
    .isISO8601()
    .withMessage('Last vulnerability scan date must be a valid date')
];

// Validation for patch status updates
const patchStatusValidation = [
  body('patchLevel')
    .optional()
    .isInt({ min: 0, max: 100 })
    .withMessage('Patch level must be between 0 and 100'),
  body('lastPatchDate')
    .optional()
    .isISO8601()
    .withMessage('Last patch date must be a valid date'),
  body('pendingPatches')
    .optional()
    .isInt({ min: 0 })
    .withMessage('Pending patches count must be a non-negative integer')
];

// Statistics and analytics routes (no specific asset ID)
router.get('/stats', protect, requirePermission('assets:read'), getAssetStats);
router.get('/export', protect, requirePermission('assets:read'), auditLog('ASSETS_EXPORT'), exportAssets);

// Location-based routes
router.get('/location/:location', protect, requirePermission('assets:read'), getAssetsByLocation);

// Bulk operations
router.put('/bulk', protect, requirePermission('assets:write'), auditLog('ASSETS_BULK_UPDATE'), bulkUpdateAssets);

// Main CRUD routes
router.route('/')
  .get(protect, requirePermission('assets:read'), getAssets)
  .post(protect, requirePermission('assets:write'), createAssetValidation, auditLog('ASSET_CREATE'), createAsset);

// Individual asset routes
router.route('/:id')
  .get(protect, requirePermission('assets:read'), getAsset)
  .put(protect, requirePermission('assets:write'), updateAssetValidation, auditLog('ASSET_UPDATE'), updateAsset)
  .delete(protect, authorize('admin', 'soc_manager'), auditLog('ASSET_DELETE'), deleteAsset);

// Asset security and maintenance operations
router.post('/:id/scan', 
  protect, 
  requirePermission('assets:write'), 
  securityScanValidation,
  auditLog('ASSET_SECURITY_SCAN'), 
  updateSecurityScan
);

router.post('/:id/patch', 
  protect, 
  requirePermission('assets:write'), 
  patchStatusValidation,
  auditLog('ASSET_PATCH_UPDATE'), 
  updatePatchStatus
);

module.exports = router;