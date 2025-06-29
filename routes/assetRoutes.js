// // routes/assetRoutes.js - Asset Management Routes
// const express = require('express');
// const { body } = require('express-validator');
// const {
//   getAssets,
//   getAsset,
//   createAsset,
//   updateAsset,
//   deleteAsset,
//   getAssetStats,
//   updateSecurityScan,
//   updatePatchStatus,
//   bulkUpdateAssets,
//   getAssetsByLocation,
//   exportAssets
// } = require('../controllers/assetController');

// const { 
//   protect, 
//   requirePermission, 
//   authorize,
//   auditLog 
// } = require('../middleware/authMiddleware');

// const router = express.Router();

// // Validation rules for asset creation
// const createAssetValidation = [
//   body('name')
//     .isLength({ min: 1, max: 100 })
//     .withMessage('Asset name is required and must be less than 100 characters')
//     .trim(),
//   body('type')
//     .isIn([
//       'Web Server', 'Database Server', 'Domain Controller', 'Email Server',
//       'Firewall', 'Router', 'Switch', 'Workstation', 'Mobile Device',
//       'Cloud Instance', 'Container', 'IoT Device', 'Network Printer', 'VPN Gateway'
//     ])
//     .withMessage('Invalid asset type'),
//   body('ipAddress')
//     .isIP(4)
//     .withMessage('Valid IP address is required'),
//   body('macAddress')
//     .optional()
//     .matches(/^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$/)
//     .withMessage('Invalid MAC address format'),
//   body('operatingSystem')
//     .isLength({ min: 1 })
//     .withMessage('Operating system is required')
//     .trim(),
//   body('location')
//     .isLength({ min: 1 })
//     .withMessage('Location is required')
//     .trim(),
//   body('owner')
//     .isLength({ min: 1 })
//     .withMessage('Owner is required')
//     .trim(),
//   body('criticality')
//     .optional()
//     .isIn(['Critical', 'High', 'Medium', 'Low'])
//     .withMessage('Invalid criticality level'),
//   body('status')
//     .optional()
//     .isIn(['Online', 'Offline', 'Warning', 'Maintenance', 'Decommissioned'])
//     .withMessage('Invalid status'),
//   body('dataClassification')
//     .optional()
//     .isIn(['Public', 'Internal', 'Confidential', 'Restricted'])
//     .withMessage('Invalid data classification'),
//   body('securityScore')
//     .optional()
//     .isInt({ min: 0, max: 100 })
//     .withMessage('Security score must be between 0 and 100'),
//   body('complianceScore')
//     .optional()
//     .isInt({ min: 0, max: 100 })
//     .withMessage('Compliance score must be between 0 and 100'),
//   body('patchLevel')
//     .optional()
//     .isInt({ min: 0, max: 100 })
//     .withMessage('Patch level must be between 0 and 100'),
//   body('uptime')
//     .optional()
//     .isInt({ min: 0, max: 100 })
//     .withMessage('Uptime must be between 0 and 100'),
//   body('discoveryMethod')
//     .optional()
//     .isIn(['Network Scan', 'Agent', 'Manual', 'Import', 'CMDB Sync'])
//     .withMessage('Invalid discovery method')
// ];

// // Validation rules for asset updates
// const updateAssetValidation = [
//   body('name')
//     .optional()
//     .isLength({ min: 1, max: 100 })
//     .withMessage('Asset name must be less than 100 characters')
//     .trim(),
//   body('ipAddress')
//     .optional()
//     .isIP(4)
//     .withMessage('Valid IP address is required'),
//   body('macAddress')
//     .optional()
//     .matches(/^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$/)
//     .withMessage('Invalid MAC address format'),
//   body('operatingSystem')
//     .optional()
//     .isLength({ min: 1 })
//     .withMessage('Operating system cannot be empty')
//     .trim(),
//   body('location')
//     .optional()
//     .isLength({ min: 1 })
//     .withMessage('Location cannot be empty')
//     .trim(),
//   body('owner')
//     .optional()
//     .isLength({ min: 1 })
//     .withMessage('Owner cannot be empty')
//     .trim(),
//   body('criticality')
//     .optional()
//     .isIn(['Critical', 'High', 'Medium', 'Low'])
//     .withMessage('Invalid criticality level'),
//   body('status')
//     .optional()
//     .isIn(['Online', 'Offline', 'Warning', 'Maintenance', 'Decommissioned'])
//     .withMessage('Invalid status'),
//   body('securityScore')
//     .optional()
//     .isInt({ min: 0, max: 100 })
//     .withMessage('Security score must be between 0 and 100'),
//   body('complianceScore')
//     .optional()
//     .isInt({ min: 0, max: 100 })
//     .withMessage('Compliance score must be between 0 and 100'),
//   body('patchLevel')
//     .optional()
//     .isInt({ min: 0, max: 100 })
//     .withMessage('Patch level must be between 0 and 100')
// ];

// // Validation for security scan updates
// const securityScanValidation = [
//   body('vulnerabilities.critical')
//     .optional()
//     .isInt({ min: 0 })
//     .withMessage('Critical vulnerabilities count must be a non-negative integer'),
//   body('vulnerabilities.high')
//     .optional()
//     .isInt({ min: 0 })
//     .withMessage('High vulnerabilities count must be a non-negative integer'),
//   body('vulnerabilities.medium')
//     .optional()
//     .isInt({ min: 0 })
//     .withMessage('Medium vulnerabilities count must be a non-negative integer'),
//   body('vulnerabilities.low')
//     .optional()
//     .isInt({ min: 0 })
//     .withMessage('Low vulnerabilities count must be a non-negative integer'),
//   body('securityScore')
//     .optional()
//     .isInt({ min: 0, max: 100 })
//     .withMessage('Security score must be between 0 and 100'),
//   body('complianceScore')
//     .optional()
//     .isInt({ min: 0, max: 100 })
//     .withMessage('Compliance score must be between 0 and 100'),
//   body('lastVulnScan')
//     .optional()
//     .isISO8601()
//     .withMessage('Last vulnerability scan date must be a valid date')
// ];

// // Validation for patch status updates
// const patchStatusValidation = [
//   body('patchLevel')
//     .optional()
//     .isInt({ min: 0, max: 100 })
//     .withMessage('Patch level must be between 0 and 100'),
//   body('lastPatchDate')
//     .optional()
//     .isISO8601()
//     .withMessage('Last patch date must be a valid date'),
//   body('pendingPatches')
//     .optional()
//     .isInt({ min: 0 })
//     .withMessage('Pending patches count must be a non-negative integer')
// ];

// // Statistics and analytics routes (no specific asset ID)
// router.get('/stats', protect, requirePermission('assets:read'), getAssetStats);
// router.get('/export', protect, requirePermission('assets:read'), auditLog('ASSETS_EXPORT'), exportAssets);

// // Location-based routes
// router.get('/location/:location', protect, requirePermission('assets:read'), getAssetsByLocation);

// // Bulk operations
// router.put('/bulk', protect, requirePermission('assets:write'), auditLog('ASSETS_BULK_UPDATE'), bulkUpdateAssets);

// // Main CRUD routes
// router.route('/')
//   .get(protect, requirePermission('assets:read'), getAssets)
//   .post(protect, requirePermission('assets:write'), createAssetValidation, auditLog('ASSET_CREATE'), createAsset);

// // Individual asset routes
// router.route('/:id')
//   .get(protect, requirePermission('assets:read'), getAsset)
//   .put(protect, requirePermission('assets:write'), updateAssetValidation, auditLog('ASSET_UPDATE'), updateAsset)
//   .delete(protect, authorize('admin', 'soc_manager'), auditLog('ASSET_DELETE'), deleteAsset);

// // Asset security and maintenance operations
// router.post('/:id/scan', 
//   protect, 
//   requirePermission('assets:write'), 
//   securityScanValidation,
//   auditLog('ASSET_SECURITY_SCAN'), 
//   updateSecurityScan
// );

// router.post('/:id/patch', 
//   protect, 
//   requirePermission('assets:write'), 
//   patchStatusValidation,
//   auditLog('ASSET_PATCH_UPDATE'), 
//   updatePatchStatus
// );

// module.exports = router;



// routes/assetRoutes.js - Updated Asset Management Routes
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
  updateMetrics,
  bulkUpdateAssets,
  getAssetsByLocation,
  getAssetsByType,
  getNetworkTopology,
  updatePosition,
  addConnection,
  exportAssets,
  searchAssets,
  getAssetHealth,
  updateSoftwareInventory,
  updateServices,
  updateSecurityControls
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
      'firewall', 'switch', 'router', 'workstation', 'server', 
      'mobile_device', 'printer', 'cloud_instance', 'container', 
      'iot_device', 'vpn_gateway', 'access_point'
    ])
    .withMessage('Invalid asset type'),
  body('ipAddress')
    .isIP(4)
    .withMessage('Valid IP address is required'),
  body('macAddress')
    .optional()
    .matches(/^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$/)
    .withMessage('Invalid MAC address format'),
  body('hostname')
    .optional()
    .isLength({ min: 1, max: 255 })
    .withMessage('Hostname must be less than 255 characters')
    .trim(),
  body('operatingSystem')
    .optional()
    .isLength({ min: 1 })
    .withMessage('Operating system cannot be empty')
    .trim(),
  body('osVersion')
    .optional()
    .isLength({ min: 1 })
    .withMessage('OS version cannot be empty')
    .trim(),
  body('location')
    .isLength({ min: 1 })
    .withMessage('Location is required')
    .trim(),
  body('department')
    .optional()
    .isLength({ min: 1 })
    .withMessage('Department cannot be empty')
    .trim(),
  body('owner')
    .isLength({ min: 1 })
    .withMessage('Owner is required')
    .trim(),
  body('ownerContact')
    .optional()
    .isLength({ min: 1 })
    .withMessage('Owner contact cannot be empty')
    .trim(),
  body('criticality')
    .optional()
    .isIn(['critical', 'high', 'medium', 'low'])
    .withMessage('Invalid criticality level'),
  body('status')
    .optional()
    .isIn(['online', 'offline', 'warning', 'maintenance', 'decommissioned'])
    .withMessage('Invalid status'),
  body('dataClassification')
    .optional()
    .isIn(['public', 'internal', 'confidential', 'restricted'])
    .withMessage('Invalid data classification'),
  body('riskLevel')
    .optional()
    .isIn(['very_low', 'low', 'medium', 'high', 'critical'])
    .withMessage('Invalid risk level'),
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
    .isInt({ min: 0 })
    .withMessage('Uptime must be a non-negative number'),
  body('discoveryMethod')
    .optional()
    .isIn(['network_scan', 'agent', 'manual', 'import', 'cmdb_sync'])
    .withMessage('Invalid discovery method'),
  body('businessFunction')
    .optional()
    .isLength({ min: 1 })
    .withMessage('Business function cannot be empty')
    .trim(),
  body('position.x')
    .optional()
    .isNumeric()
    .withMessage('Position X must be a number'),
  body('position.y')
    .optional()
    .isNumeric()
    .withMessage('Position Y must be a number'),
  body('metadata.cpu')
    .optional()
    .isInt({ min: 0, max: 100 })
    .withMessage('CPU usage must be between 0 and 100'),
  body('metadata.memory')
    .optional()
    .isInt({ min: 0, max: 100 })
    .withMessage('Memory usage must be between 0 and 100'),
  body('metadata.storage')
    .optional()
    .isInt({ min: 0, max: 100 })
    .withMessage('Storage usage must be between 0 and 100'),
  body('metadata.networkLoad')
    .optional()
    .isInt({ min: 0, max: 100 })
    .withMessage('Network load must be between 0 and 100'),
  body('metadata.manufacturer')
    .optional()
    .isLength({ min: 1 })
    .withMessage('Manufacturer cannot be empty')
    .trim(),
  body('metadata.model')
    .optional()
    .isLength({ min: 1 })
    .withMessage('Model cannot be empty')
    .trim(),
  body('metadata.serialNumber')
    .optional()
    .isLength({ min: 1 })
    .withMessage('Serial number cannot be empty')
    .trim(),
  body('metadata.firmware')
    .optional()
    .isLength({ min: 1 })
    .withMessage('Firmware cannot be empty')
    .trim(),
  body('metadata.version')
    .optional()
    .isLength({ min: 1 })
    .withMessage('Version cannot be empty')
    .trim()
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
  body('hostname')
    .optional()
    .isLength({ min: 1, max: 255 })
    .withMessage('Hostname must be less than 255 characters')
    .trim(),
  body('operatingSystem')
    .optional()
    .isLength({ min: 1 })
    .withMessage('Operating system cannot be empty')
    .trim(),
  body('osVersion')
    .optional()
    .isLength({ min: 1 })
    .withMessage('OS version cannot be empty')
    .trim(),
  body('location')
    .optional()
    .isLength({ min: 1 })
    .withMessage('Location cannot be empty')
    .trim(),
  body('department')
    .optional()
    .isLength({ min: 1 })
    .withMessage('Department cannot be empty')
    .trim(),
  body('owner')
    .optional()
    .isLength({ min: 1 })
    .withMessage('Owner cannot be empty')
    .trim(),
  body('ownerContact')
    .optional()
    .isLength({ min: 1 })
    .withMessage('Owner contact cannot be empty')
    .trim(),
  body('criticality')
    .optional()
    .isIn(['critical', 'high', 'medium', 'low'])
    .withMessage('Invalid criticality level'),
  body('status')
    .optional()
    .isIn(['online', 'offline', 'warning', 'maintenance', 'decommissioned'])
    .withMessage('Invalid status'),
  body('riskLevel')
    .optional()
    .isIn(['very_low', 'low', 'medium', 'high', 'critical'])
    .withMessage('Invalid risk level'),
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
  body('businessFunction')
    .optional()
    .isLength({ min: 1 })
    .withMessage('Business function cannot be empty')
    .trim()
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
    .withMessage('Last vulnerability scan date must be a valid date'),
  body('nextVulnScan')
    .optional()
    .isISO8601()
    .withMessage('Next vulnerability scan date must be a valid date')
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

// Validation for performance metrics updates
const metricsValidation = [
  body('cpu')
    .optional()
    .isInt({ min: 0, max: 100 })
    .withMessage('CPU usage must be between 0 and 100'),
  body('memory')
    .optional()
    .isInt({ min: 0, max: 100 })
    .withMessage('Memory usage must be between 0 and 100'),
  body('storage')
    .optional()
    .isInt({ min: 0, max: 100 })
    .withMessage('Storage usage must be between 0 and 100'),
  body('networkLoad')
    .optional()
    .isInt({ min: 0, max: 100 })
    .withMessage('Network load must be between 0 and 100'),
  body('throughput')
    .optional()
    .isLength({ min: 1 })
    .withMessage('Throughput cannot be empty')
    .trim(),
  body('bandwidth')
    .optional()
    .isLength({ min: 1 })
    .withMessage('Bandwidth cannot be empty')
    .trim()
];

// Validation for position updates
const positionValidation = [
  body('x')
    .isNumeric()
    .withMessage('X coordinate must be a number'),
  body('y')
    .isNumeric()
    .withMessage('Y coordinate must be a number')
];

// Validation for connection creation
const connectionValidation = [
  body('targetAssetId')
    .isLength({ min: 1 })
    .withMessage('Target asset ID is required')
    .trim(),
  body('relationship')
    .optional()
    .isIn(['depends_on', 'supports', 'connected_to', 'hosted_on'])
    .withMessage('Invalid relationship type')
];

// Validation for software inventory
const softwareValidation = [
  body('software')
    .isArray()
    .withMessage('Software must be an array'),
  body('software.*.name')
    .isLength({ min: 1 })
    .withMessage('Software name is required')
    .trim(),
  body('software.*.version')
    .optional()
    .isLength({ min: 1 })
    .withMessage('Software version cannot be empty')
    .trim(),
  body('software.*.vendor')
    .optional()
    .isLength({ min: 1 })
    .withMessage('Software vendor cannot be empty')
    .trim(),
  body('software.*.licenseType')
    .optional()
    .isIn(['Commercial', 'Open Source', 'Freeware', 'Trial'])
    .withMessage('Invalid license type'),
  body('software.*.installDate')
    .optional()
    .isISO8601()
    .withMessage('Install date must be a valid date'),
  body('software.*.lastUpdate')
    .optional()
    .isISO8601()
    .withMessage('Last update date must be a valid date')
];

// Validation for services
const servicesValidation = [
  body('services')
    .isArray()
    .withMessage('Services must be an array'),
  body('services.*.name')
    .isLength({ min: 1 })
    .withMessage('Service name is required')
    .trim(),
  body('services.*.port')
    .optional()
    .isInt({ min: 1, max: 65535 })
    .withMessage('Port must be between 1 and 65535'),
  body('services.*.protocol')
    .optional()
    .isIn(['TCP', 'UDP'])
    .withMessage('Protocol must be TCP or UDP'),
  body('services.*.status')
    .optional()
    .isIn(['running', 'stopped', 'failed'])
    .withMessage('Invalid service status'),
  body('services.*.version')
    .optional()
    .isLength({ min: 1 })
    .withMessage('Service version cannot be empty')
    .trim()
];

// Statistics and analytics routes (no specific asset ID)
router.get('/stats', protect, requirePermission('assets:read'), getAssetStats);
router.get('/export', protect, requirePermission('assets:read'), auditLog('ASSETS_EXPORT'), exportAssets);
router.get('/search', protect, requirePermission('assets:read'), searchAssets);
router.get('/topology', protect, requirePermission('assets:read'), getNetworkTopology);

// Location-based routes
router.get('/location/:location', protect, requirePermission('assets:read'), getAssetsByLocation);

// Type-based routes
router.get('/type/:type', protect, requirePermission('assets:read'), getAssetsByType);

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

// Asset health and monitoring
router.get('/:id/health', protect, requirePermission('assets:read'), getAssetHealth);

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

// Performance metrics update
router.post('/:id/metrics',
  protect,
  requirePermission('assets:write'),
  metricsValidation,
  auditLog('ASSET_METRICS_UPDATE'),
  updateMetrics
);

// Network topology operations
router.put('/:id/position',
  protect,
  requirePermission('assets:write'),
  positionValidation,
  auditLog('ASSET_POSITION_UPDATE'),
  updatePosition
);

router.post('/:id/connections',
  protect,
  requirePermission('assets:write'),
  connectionValidation,
  auditLog('ASSET_CONNECTION_ADD'),
  addConnection
);

// Asset inventory management
router.put('/:id/software',
  protect,
  requirePermission('assets:write'),
  softwareValidation,
  auditLog('ASSET_SOFTWARE_UPDATE'),
  updateSoftwareInventory
);

router.put('/:id/services',
  protect,
  requirePermission('assets:write'),
  servicesValidation,
  auditLog('ASSET_SERVICES_UPDATE'),
  updateServices
);

router.put('/:id/security-controls',
  protect,
  requirePermission('assets:write'),
  auditLog('ASSET_SECURITY_CONTROLS_UPDATE'),
  updateSecurityControls
);

module.exports = router;