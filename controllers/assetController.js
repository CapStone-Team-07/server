// // controllers/assetController.js - Asset Management Controller
// const Asset = require('../models/Asset');
// const User = require('../models/User');
// const { validationResult } = require('express-validator');

// // @desc    Get all assets with filtering, sorting, and pagination
// // @route   GET /api/assets
// // @access  Private
// exports.getAssets = async (req, res) => {
//   try {
//     // Build query object
//     let query = {};
    
//     // Filtering
//     const { 
//       type, 
//       status, 
//       criticality,
//       riskLevel,
//       location,
//       department,
//       owner,
//       operatingSystem,
//       dataClassification,
//       tags,
//       vulnerabilityCountMin,
//       vulnerabilityCountMax,
//       securityScoreMin,
//       securityScoreMax,
//       complianceScoreMin,
//       complianceScoreMax,
//       patchLevelMin,
//       patchLevelMax,
//       lastSeenFrom,
//       lastSeenTo,
//       search,
//       discoveryMethod
//     } = req.query;

//     // Status filtering
//     if (status) {
//       query.status = Array.isArray(status) ? { $in: status } : status;
//     }
    
//     // Type filtering
//     if (type) {
//       query.type = Array.isArray(type) ? { $in: type } : type;
//     }
    
//     // Criticality filtering
//     if (criticality) {
//       query.criticality = Array.isArray(criticality) ? { $in: criticality } : criticality;
//     }
    
//     // Risk level filtering
//     if (riskLevel) {
//       query.riskLevel = Array.isArray(riskLevel) ? { $in: riskLevel } : riskLevel;
//     }
    
//     // Location filtering
//     if (location) {
//       query.location = Array.isArray(location) ? { $in: location } : location;
//     }
    
//     // Department filtering
//     if (department) {
//       query.department = Array.isArray(department) ? { $in: department } : department;
//     }
    
//     // Owner filtering
//     if (owner) {
//       query.owner = { $regex: owner, $options: 'i' };
//     }
    
//     // Operating system filtering
//     if (operatingSystem) {
//       query.operatingSystem = { $regex: operatingSystem, $options: 'i' };
//     }
    
//     // Data classification filtering
//     if (dataClassification) {
//       query.dataClassification = Array.isArray(dataClassification) ? { $in: dataClassification } : dataClassification;
//     }
    
//     // Discovery method filtering
//     if (discoveryMethod) {
//       query.discoveryMethod = Array.isArray(discoveryMethod) ? { $in: discoveryMethod } : discoveryMethod;
//     }
    
//     // Tags filtering
//     if (tags) {
//       const tagArray = Array.isArray(tags) ? tags : [tags];
//       query.tags = { $in: tagArray };
//     }
    
//     // Vulnerability count filtering
//     if (vulnerabilityCountMin || vulnerabilityCountMax) {
//       const vulnerabilityQuery = {};
//       if (vulnerabilityCountMin) vulnerabilityQuery.$gte = parseInt(vulnerabilityCountMin);
//       if (vulnerabilityCountMax) vulnerabilityQuery.$lte = parseInt(vulnerabilityCountMax);
      
//       query.$expr = {
//         $and: [
//           query.$expr || {},
//           {
//             [`$${Object.keys(vulnerabilityQuery)[0]}`]: [
//               { $add: ['$vulnerabilities.critical', '$vulnerabilities.high', '$vulnerabilities.medium', '$vulnerabilities.low'] },
//               Object.values(vulnerabilityQuery)[0]
//             ]
//           }
//         ]
//       };
//     }
    
//     // Security score filtering
//     if (securityScoreMin || securityScoreMax) {
//       query.securityScore = {};
//       if (securityScoreMin) query.securityScore.$gte = parseInt(securityScoreMin);
//       if (securityScoreMax) query.securityScore.$lte = parseInt(securityScoreMax);
//     }
    
//     // Compliance score filtering
//     if (complianceScoreMin || complianceScoreMax) {
//       query.complianceScore = {};
//       if (complianceScoreMin) query.complianceScore.$gte = parseInt(complianceScoreMin);
//       if (complianceScoreMax) query.complianceScore.$lte = parseInt(complianceScoreMax);
//     }
    
//     // Patch level filtering
//     if (patchLevelMin || patchLevelMax) {
//       query.patchLevel = {};
//       if (patchLevelMin) query.patchLevel.$gte = parseInt(patchLevelMin);
//       if (patchLevelMax) query.patchLevel.$lte = parseInt(patchLevelMax);
//     }
    
//     // Last seen date filtering
//     if (lastSeenFrom || lastSeenTo) {
//       query.lastSeen = {};
//       if (lastSeenFrom) query.lastSeen.$gte = new Date(lastSeenFrom);
//       if (lastSeenTo) query.lastSeen.$lte = new Date(lastSeenTo);
//     }
    
//     // Search functionality
//     if (search) {
//       query.$or = [
//         { name: { $regex: search, $options: 'i' } },
//         { assetId: { $regex: search, $options: 'i' } },
//         { ipAddress: { $regex: search, $options: 'i' } },
//         { macAddress: { $regex: search, $options: 'i' } },
//         { hostname: { $regex: search, $options: 'i' } },
//         { owner: { $regex: search, $options: 'i' } },
//         { 'hardware.manufacturer': { $regex: search, $options: 'i' } },
//         { 'hardware.model': { $regex: search, $options: 'i' } }
//       ];
//     }

//     // Sorting
//     let sortBy = {};
//     const { sort, order } = req.query;
    
//     if (sort) {
//       sortBy[sort] = order === 'asc' ? 1 : -1;
//     } else {
//       sortBy.lastSeen = -1; // Default sort by last seen
//     }

//     // Pagination
//     const page = parseInt(req.query.page) || 1;
//     const limit = Math.min(parseInt(req.query.limit) || 25, 100); // Max 100 per page
//     const skip = (page - 1) * limit;

//     // Execute query
//     const assets = await Asset.find(query)
//       .populate('discoveredBy', 'username firstName lastName fullName')
//       .populate('lastUpdatedBy', 'username firstName lastName fullName')
//       .sort(sortBy)
//       .skip(skip)
//       .limit(limit)
//       .lean();

//     // Get total count for pagination
//     const total = await Asset.countDocuments(query);
//     const totalPages = Math.ceil(total / limit);

//     res.status(200).json({
//       success: true,
//       count: assets.length,
//       total,
//       page,
//       totalPages,
//       limit,
//       assets
//     });
//   } catch (error) {
//     console.error('Get assets error:', error);
//     res.status(500).json({
//       success: false,
//       message: 'Error retrieving assets'
//     });
//   }
// };

// // @desc    Get single asset
// // @route   GET /api/assets/:id
// // @access  Private
// exports.getAsset = async (req, res) => {
//   try {
//     const asset = await Asset.findById(req.params.id)
//       .populate('discoveredBy', 'username firstName lastName fullName email role')
//       .populate('lastUpdatedBy', 'username firstName lastName fullName email role')
//       .populate('dependencies.assetId', 'name assetId type status');

//     if (!asset) {
//       return res.status(404).json({
//         success: false,
//         message: 'Asset not found'
//       });
//     }

//     res.status(200).json({
//       success: true,
//       asset
//     });
//   } catch (error) {
//     console.error('Get asset error:', error);
//     res.status(500).json({
//       success: false,
//       message: 'Error retrieving asset'
//     });
//   }
// };

// // @desc    Create new asset
// // @route   POST /api/assets
// // @access  Private
// exports.createAsset = async (req, res) => {
//   try {
//     // Check for validation errors
//     const errors = validationResult(req);
//     if (!errors.isEmpty()) {
//       return res.status(400).json({
//         success: false,
//         message: 'Validation failed',
//         errors: errors.array()
//       });
//     }

//     // Add discovery information
//     req.body.discoveredBy = req.user._id;
//     req.body.lastUpdatedBy = req.user._id;
    
//     // Set default discovery method if not provided
//     if (!req.body.discoveryMethod) {
//       req.body.discoveryMethod = 'Manual';
//     }

//     const asset = await Asset.create(req.body);

//     // Populate the created asset
//     const populatedAsset = await Asset.findById(asset._id)
//       .populate('discoveredBy', 'username firstName lastName fullName')
//       .populate('lastUpdatedBy', 'username firstName lastName fullName');

//     res.status(201).json({
//       success: true,
//       asset: populatedAsset
//     });
//   } catch (error) {
//     console.error('Create asset error:', error);
//     res.status(500).json({
//       success: false,
//       message: 'Error creating asset'
//     });
//   }
// };

// // @desc    Update asset
// // @route   PUT /api/assets/:id
// // @access  Private
// exports.updateAsset = async (req, res) => {
//   try {
//     let asset = await Asset.findById(req.params.id);

//     if (!asset) {
//       return res.status(404).json({
//         success: false,
//         message: 'Asset not found'
//       });
//     }

//     // Add update information
//     req.body.lastUpdatedBy = req.user._id;

//     // Remove fields that shouldn't be updated directly
//     delete req.body.assetId;
//     delete req.body.discoveredBy;

//     asset = await Asset.findByIdAndUpdate(
//       req.params.id,
//       req.body,
//       {
//         new: true,
//         runValidators: true
//       }
//     ).populate('discoveredBy lastUpdatedBy', 'username firstName lastName fullName');

//     res.status(200).json({
//       success: true,
//       asset
//     });
//   } catch (error) {
//     console.error('Update asset error:', error);
//     res.status(500).json({
//       success: false,
//       message: 'Error updating asset'
//     });
//   }
// };

// // @desc    Delete asset
// // @route   DELETE /api/assets/:id
// // @access  Private (Admin/SOC Manager only)
// exports.deleteAsset = async (req, res) => {
//   try {
//     const asset = await Asset.findById(req.params.id);

//     if (!asset) {
//       return res.status(404).json({
//         success: false,
//         message: 'Asset not found'
//       });
//     }

//     await asset.remove();

//     res.status(200).json({
//       success: true,
//       message: 'Asset deleted successfully'
//     });
//   } catch (error) {
//     console.error('Delete asset error:', error);
//     res.status(500).json({
//       success: false,
//       message: 'Error deleting asset'
//     });
//   }
// };

// // @desc    Get asset statistics
// // @route   GET /api/assets/stats
// // @access  Private
// exports.getAssetStats = async (req, res) => {
//   try {
//     // Build filter based on query params
//     let filter = {};
    
//     if (req.query.type) {
//       filter.type = req.query.type;
//     }
    
//     if (req.query.location) {
//       filter.location = req.query.location;
//     }
    
//     if (req.query.dateFrom || req.query.dateTo) {
//       filter.lastSeen = {};
//       if (req.query.dateFrom) filter.lastSeen.$gte = new Date(req.query.dateFrom);
//       if (req.query.dateTo) filter.lastSeen.$lte = new Date(req.query.dateTo);
//     }

//     const stats = await Asset.getAssetStatistics(filter);
    
//     // Additional aggregations
//     const additionalStats = await Asset.aggregate([
//       { $match: filter },
//       {
//         $group: {
//           _id: null,
//           avgRiskScore: { $avg: { $toInt: '$riskLevel' } },
//           totalPatching: { $avg: '$patchLevel' },
//           assetsByType: {
//             $push: {
//               type: '$type',
//               criticality: '$criticality'
//             }
//           },
//           assetsByLocation: {
//             $push: {
//               location: '$location',
//               status: '$status'
//             }
//           }
//         }
//       }
//     ]);

//     // Count by status
//     const statusCounts = await Asset.aggregate([
//       { $match: filter },
//       {
//         $group: {
//           _id: '$status',
//           count: { $sum: 1 }
//         }
//       }
//     ]);

//     // Count by criticality
//     const criticalityCounts = await Asset.aggregate([
//       { $match: filter },
//       {
//         $group: {
//           _id: '$criticality',
//           count: { $sum: 1 }
//         }
//       }
//     ]);

//     // Count by type
//     const typeCounts = await Asset.aggregate([
//       { $match: filter },
//       {
//         $group: {
//           _id: '$type',
//           count: { $sum: 1 }
//         }
//       }
//     ]);

//     const combinedStats = {
//       ...stats,
//       statusBreakdown: statusCounts.reduce((acc, item) => {
//         acc[item._id] = item.count;
//         return acc;
//       }, {}),
//       criticalityBreakdown: criticalityCounts.reduce((acc, item) => {
//         acc[item._id] = item.count;
//         return acc;
//       }, {}),
//       typeBreakdown: typeCounts.reduce((acc, item) => {
//         acc[item._id] = item.count;
//         return acc;
//       }, {}),
//       additionalMetrics: additionalStats[0] || {}
//     };
    
//     res.status(200).json({
//       success: true,
//       stats: combinedStats
//     });
//   } catch (error) {
//     console.error('Get asset stats error:', error);
//     res.status(500).json({
//       success: false,
//       message: 'Error retrieving asset statistics'
//     });
//   }
// };

// // @desc    Update asset security scan results
// // @route   POST /api/assets/:id/scan
// // @access  Private
// exports.updateSecurityScan = async (req, res) => {
//   try {
//     const asset = await Asset.findById(req.params.id);

//     if (!asset) {
//       return res.status(404).json({
//         success: false,
//         message: 'Asset not found'
//       });
//     }

//     const { vulnerabilities, securityScore, complianceScore, lastVulnScan } = req.body;

//     // Update security-related fields
//     const updateData = {
//       lastUpdatedBy: req.user._id,
//       lastVulnScan: lastVulnScan || new Date()
//     };

//     if (vulnerabilities) {
//       updateData.vulnerabilities = vulnerabilities;
//     }

//     if (securityScore !== undefined) {
//       updateData.securityScore = securityScore;
//     }

//     if (complianceScore !== undefined) {
//       updateData.complianceScore = complianceScore;
//     }

//     // Calculate risk score if needed
//     if (vulnerabilities || securityScore) {
//       const updatedAsset = await Asset.findByIdAndUpdate(
//         req.params.id,
//         updateData,
//         { new: true }
//       );
//       updateData.riskLevel = calculateRiskLevel(updatedAsset);
//     }

//     const updatedAsset = await Asset.findByIdAndUpdate(
//       req.params.id,
//       updateData,
//       { new: true, runValidators: true }
//     ).populate('lastUpdatedBy', 'username firstName lastName fullName');

//     res.status(200).json({
//       success: true,
//       message: 'Security scan results updated successfully',
//       asset: updatedAsset
//     });
//   } catch (error) {
//     console.error('Update security scan error:', error);
//     res.status(500).json({
//       success: false,
//       message: 'Error updating security scan results'
//     });
//   }
// };

// // @desc    Update asset patch status
// // @route   POST /api/assets/:id/patch
// // @access  Private
// exports.updatePatchStatus = async (req, res) => {
//   try {
//     const asset = await Asset.findById(req.params.id);

//     if (!asset) {
//       return res.status(404).json({
//         success: false,
//         message: 'Asset not found'
//       });
//     }

//     const { patchLevel, lastPatchDate, pendingPatches } = req.body;

//     const updateData = {
//       lastUpdatedBy: req.user._id
//     };

//     if (patchLevel !== undefined) {
//       updateData.patchLevel = patchLevel;
//     }

//     if (lastPatchDate) {
//       updateData.lastPatchDate = new Date(lastPatchDate);
//     }

//     if (pendingPatches !== undefined) {
//       updateData.pendingPatches = pendingPatches;
//     }

//     const updatedAsset = await Asset.findByIdAndUpdate(
//       req.params.id,
//       updateData,
//       { new: true, runValidators: true }
//     ).populate('lastUpdatedBy', 'username firstName lastName fullName');

//     res.status(200).json({
//       success: true,
//       message: 'Patch status updated successfully',
//       asset: updatedAsset
//     });
//   } catch (error) {
//     console.error('Update patch status error:', error);
//     res.status(500).json({
//       success: false,
//       message: 'Error updating patch status'
//     });
//   }
// };

// // @desc    Bulk update assets
// // @route   PUT /api/assets/bulk
// // @access  Private
// exports.bulkUpdateAssets = async (req, res) => {
//   try {
//     const { assetIds, updates } = req.body;

//     if (!assetIds || !Array.isArray(assetIds) || assetIds.length === 0) {
//       return res.status(400).json({
//         success: false,
//         message: 'Asset IDs array is required'
//       });
//     }

//     if (!updates || Object.keys(updates).length === 0) {
//       return res.status(400).json({
//         success: false,
//         message: 'Updates object is required'
//       });
//     }

//     // Remove fields that shouldn't be bulk updated
//     delete updates.assetId;
//     delete updates.discoveredBy;

//     // Add update information
//     updates.lastUpdatedBy = req.user._id;

//     const result = await Asset.updateMany(
//       { _id: { $in: assetIds } },
//       { $set: updates }
//     );

//     res.status(200).json({
//       success: true,
//       message: `${result.modifiedCount} assets updated successfully`,
//       modifiedCount: result.modifiedCount
//     });
//   } catch (error) {
//     console.error('Bulk update assets error:', error);
//     res.status(500).json({
//       success: false,
//       message: 'Error bulk updating assets'
//     });
//   }
// };

// // @desc    Get assets by location
// // @route   GET /api/assets/location/:location
// // @access  Private
// exports.getAssetsByLocation = async (req, res) => {
//   try {
//     const { location } = req.params;
//     const { status, type } = req.query;

//     let query = { location };

//     if (status) {
//       query.status = status;
//     }

//     if (type) {
//       query.type = type;
//     }

//     const assets = await Asset.find(query)
//       .populate('lastUpdatedBy', 'username firstName lastName')
//       .sort({ name: 1 });

//     res.status(200).json({
//       success: true,
//       count: assets.length,
//       location,
//       assets
//     });
//   } catch (error) {
//     console.error('Get assets by location error:', error);
//     res.status(500).json({
//       success: false,
//       message: 'Error retrieving assets by location'
//     });
//   }
// };

// // @desc    Export assets to CSV
// // @route   GET /api/assets/export
// // @access  Private
// exports.exportAssets = async (req, res) => {
//   try {
//     // Build query (similar to getAssets)
//     let query = {};
    
//     const { 
//       type, 
//       status, 
//       criticality,
//       location,
//       dateFrom,
//       dateTo
//     } = req.query;

//     if (type) query.type = Array.isArray(type) ? { $in: type } : type;
//     if (status) query.status = Array.isArray(status) ? { $in: status } : status;
//     if (criticality) query.criticality = Array.isArray(criticality) ? { $in: criticality } : criticality;
//     if (location) query.location = Array.isArray(location) ? { $in: location } : location;
    
//     if (dateFrom || dateTo) {
//       query.lastSeen = {};
//       if (dateFrom) query.lastSeen.$gte = new Date(dateFrom);
//       if (dateTo) query.lastSeen.$lte = new Date(dateTo);
//     }

//     const assets = await Asset.find(query)
//       .populate('discoveredBy lastUpdatedBy', 'username firstName lastName')
//       .sort({ name: 1 })
//       .lean();

//     // Convert to CSV format
//     const csvHeaders = [
//       'Asset ID',
//       'Name',
//       'Type',
//       'Status',
//       'IP Address',
//       'MAC Address',
//       'Operating System',
//       'Location',
//       'Owner',
//       'Criticality',
//       'Security Score',
//       'Compliance Score',
//       'Patch Level',
//       'Risk Level',
//       'Total Vulnerabilities',
//       'Last Seen',
//       'Discovered By'
//     ];

//     const csvRows = assets.map(asset => [
//       asset.assetId,
//       `"${asset.name}"`,
//       asset.type,
//       asset.status,
//       asset.ipAddress,
//       asset.macAddress || '',
//       `"${asset.operatingSystem}"`,
//       `"${asset.location}"`,
//       `"${asset.owner}"`,
//       asset.criticality,
//       asset.securityScore,
//       asset.complianceScore,
//       asset.patchLevel,
//       asset.riskLevel,
//       (asset.vulnerabilities.critical + asset.vulnerabilities.high + asset.vulnerabilities.medium + asset.vulnerabilities.low),
//       new Date(asset.lastSeen).toISOString(),
//       asset.discoveredBy ? `"${asset.discoveredBy.firstName} ${asset.discoveredBy.lastName}"` : ''
//     ]);

//     const csvContent = [csvHeaders.join(','), ...csvRows.map(row => row.join(','))].join('\n');

//     res.setHeader('Content-Type', 'text/csv');
//     res.setHeader('Content-Disposition', `attachment; filename="assets-export-${new Date().toISOString().split('T')[0]}.csv"`);
//     res.status(200).send(csvContent);
//   } catch (error) {
//     console.error('Export assets error:', error);
//     res.status(500).json({
//       success: false,
//       message: 'Error exporting assets'
//     });
//   }
// };

// // Helper function to calculate risk level based on asset data
// const calculateRiskLevel = (asset) => {
//   let riskScore = 0;
  
//   // Criticality weight (40%)
//   const criticalityWeight = {
//     'Critical': 40,
//     'High': 30,
//     'Medium': 20,
//     'Low': 10
//   };
//   riskScore += criticalityWeight[asset.criticality] || 20;
  
//   // Vulnerability weight (30%)
//   const vulnScore = (asset.vulnerabilities.critical * 10) + 
//                    (asset.vulnerabilities.high * 5) + 
//                    (asset.vulnerabilities.medium * 2) + 
//                    (asset.vulnerabilities.low * 1);
//   riskScore += Math.min(vulnScore, 30);
  
//   // Patch level weight (20%)
//   riskScore += (100 - asset.patchLevel) * 0.2;
  
//   // Security score weight (10%)
//   riskScore += (100 - asset.securityScore) * 0.1;
  
//   // Determine risk level based on score
//   if (riskScore >= 80) return 'Critical';
//   if (riskScore >= 60) return 'High';
//   if (riskScore >= 40) return 'Medium';
//   if (riskScore >= 20) return 'Low';
//   return 'Very Low';
// };



// controllers/assetController.js - Updated Asset Management Controller
const Asset = require('../models/Asset');
const User = require('../models/User');
const { validationResult } = require('express-validator');

// @desc    Get all assets with filtering, sorting, and pagination
// @route   GET /api/assets
// @access  Private
exports.getAssets = async (req, res) => {
  try {
    // Build query object
    let query = {};
    
    // Filtering
    const { 
      type, 
      status, 
      criticality,
      riskLevel,
      location,
      department,
      owner,
      operatingSystem,
      dataClassification,
      tags,
      vulnerabilityCountMin,
      vulnerabilityCountMax,
      securityScoreMin,
      securityScoreMax,
      complianceScoreMin,
      complianceScoreMax,
      patchLevelMin,
      patchLevelMax,
      lastSeenFrom,
      lastSeenTo,
      search,
      discoveryMethod,
      businessFunction,
      manufacturer,
      model,
      cpuMin,
      cpuMax,
      memoryMin,
      memoryMax,
      storageMin,
      storageMax,
      networkLoadMin,
      networkLoadMax,
      healthScoreMin,
      healthScoreMax
    } = req.query;

    // Status filtering
    if (status) {
      query.status = Array.isArray(status) ? { $in: status } : status;
    }
    
    // Type filtering
    if (type) {
      query.type = Array.isArray(type) ? { $in: type } : type;
    }
    
    // Criticality filtering
    if (criticality) {
      query.criticality = Array.isArray(criticality) ? { $in: criticality } : criticality;
    }
    
    // Risk level filtering
    if (riskLevel) {
      query.riskLevel = Array.isArray(riskLevel) ? { $in: riskLevel } : riskLevel;
    }
    
    // Location filtering
    if (location) {
      query.location = Array.isArray(location) ? { $in: location } : location;
    }
    
    // Department filtering
    if (department) {
      query.department = Array.isArray(department) ? { $in: department } : department;
    }
    
    // Owner filtering
    if (owner) {
      query.owner = { $regex: owner, $options: 'i' };
    }
    
    // Operating system filtering
    if (operatingSystem) {
      query.operatingSystem = { $regex: operatingSystem, $options: 'i' };
    }
    
    // Data classification filtering
    if (dataClassification) {
      query.dataClassification = Array.isArray(dataClassification) ? { $in: dataClassification } : dataClassification;
    }
    
    // Discovery method filtering
    if (discoveryMethod) {
      query.discoveryMethod = Array.isArray(discoveryMethod) ? { $in: discoveryMethod } : discoveryMethod;
    }
    
    // Business function filtering
    if (businessFunction) {
      query.businessFunction = { $regex: businessFunction, $options: 'i' };
    }
    
    // Manufacturer filtering
    if (manufacturer) {
      query['metadata.manufacturer'] = { $regex: manufacturer, $options: 'i' };
    }
    
    // Model filtering
    if (model) {
      query['metadata.model'] = { $regex: model, $options: 'i' };
    }
    
    // Tags filtering
    if (tags) {
      const tagArray = Array.isArray(tags) ? tags : [tags];
      query.tags = { $in: tagArray };
    }
    
    // Vulnerability count filtering
    if (vulnerabilityCountMin || vulnerabilityCountMax) {
      const vulnerabilityQuery = {};
      if (vulnerabilityCountMin) vulnerabilityQuery.$gte = parseInt(vulnerabilityCountMin);
      if (vulnerabilityCountMax) vulnerabilityQuery.$lte = parseInt(vulnerabilityCountMax);
      
      query.$expr = {
        $and: [
          query.$expr || {},
          {
            [`$${Object.keys(vulnerabilityQuery)[0]}`]: [
              { $add: ['$vulnerabilities.critical', '$vulnerabilities.high', '$vulnerabilities.medium', '$vulnerabilities.low'] },
              Object.values(vulnerabilityQuery)[0]
            ]
          }
        ]
      };
    }
    
    // Security score filtering
    if (securityScoreMin || securityScoreMax) {
      query.securityScore = {};
      if (securityScoreMin) query.securityScore.$gte = parseInt(securityScoreMin);
      if (securityScoreMax) query.securityScore.$lte = parseInt(securityScoreMax);
    }
    
    // Compliance score filtering
    if (complianceScoreMin || complianceScoreMax) {
      query.complianceScore = {};
      if (complianceScoreMin) query.complianceScore.$gte = parseInt(complianceScoreMin);
      if (complianceScoreMax) query.complianceScore.$lte = parseInt(complianceScoreMax);
    }
    
    // Patch level filtering
    if (patchLevelMin || patchLevelMax) {
      query.patchLevel = {};
      if (patchLevelMin) query.patchLevel.$gte = parseInt(patchLevelMin);
      if (patchLevelMax) query.patchLevel.$lte = parseInt(patchLevelMax);
    }
    
    // Performance metrics filtering
    if (cpuMin || cpuMax) {
      query['metadata.cpu'] = {};
      if (cpuMin) query['metadata.cpu'].$gte = parseInt(cpuMin);
      if (cpuMax) query['metadata.cpu'].$lte = parseInt(cpuMax);
    }
    
    if (memoryMin || memoryMax) {
      query['metadata.memory'] = {};
      if (memoryMin) query['metadata.memory'].$gte = parseInt(memoryMin);
      if (memoryMax) query['metadata.memory'].$lte = parseInt(memoryMax);
    }
    
    if (storageMin || storageMax) {
      query['metadata.storage'] = {};
      if (storageMin) query['metadata.storage'].$gte = parseInt(storageMin);
      if (storageMax) query['metadata.storage'].$lte = parseInt(storageMax);
    }
    
    if (networkLoadMin || networkLoadMax) {
      query['metadata.networkLoad'] = {};
      if (networkLoadMin) query['metadata.networkLoad'].$gte = parseInt(networkLoadMin);
      if (networkLoadMax) query['metadata.networkLoad'].$lte = parseInt(networkLoadMax);
    }
    
    // Last seen date filtering
    if (lastSeenFrom || lastSeenTo) {
      query.lastSeen = {};
      if (lastSeenFrom) query.lastSeen.$gte = new Date(lastSeenFrom);
      if (lastSeenTo) query.lastSeen.$lte = new Date(lastSeenTo);
    }
    
    // Search functionality - updated for new schema
    if (search) {
      query.$or = [
        { name: { $regex: search, $options: 'i' } },
        { assetId: { $regex: search, $options: 'i' } },
        { ipAddress: { $regex: search, $options: 'i' } },
        { macAddress: { $regex: search, $options: 'i' } },
        { hostname: { $regex: search, $options: 'i' } },
        { owner: { $regex: search, $options: 'i' } },
        { 'metadata.manufacturer': { $regex: search, $options: 'i' } },
        { 'metadata.model': { $regex: search, $options: 'i' } },
        { 'metadata.serialNumber': { $regex: search, $options: 'i' } },
        { operatingSystem: { $regex: search, $options: 'i' } },
        { location: { $regex: search, $options: 'i' } }
      ];
    }

    // Sorting
    let sortBy = {};
    const { sort, order } = req.query;
    
    if (sort) {
      sortBy[sort] = order === 'asc' ? 1 : -1;
    } else {
      sortBy.lastSeen = -1; // Default sort by last seen
    }

    // Pagination
    const page = parseInt(req.query.page) || 1;
    const limit = Math.min(parseInt(req.query.limit) || 25, 100); // Max 100 per page
    const skip = (page - 1) * limit;

    // Execute query
    const assets = await Asset.find(query)
      .populate('discoveredBy', 'username firstName lastName fullName')
      .populate('lastUpdatedBy', 'username firstName lastName fullName')
      .sort(sortBy)
      .skip(skip)
      .limit(limit)
      .lean();

    // Get total count for pagination
    const total = await Asset.countDocuments(query);
    const totalPages = Math.ceil(total / limit);

    res.status(200).json({
      success: true,
      count: assets.length,
      total,
      page,
      totalPages,
      limit,
      assets
    });
  } catch (error) {
    console.error('Get assets error:', error);
    res.status(500).json({
      success: false,
      message: 'Error retrieving assets'
    });
  }
};

// @desc    Get single asset
// @route   GET /api/assets/:id
// @access  Private
exports.getAsset = async (req, res) => {
  try {
    const asset = await Asset.findById(req.params.id)
      .populate('discoveredBy', 'username firstName lastName fullName email role')
      .populate('lastUpdatedBy', 'username firstName lastName fullName email role')
      .populate('dependencies.assetId', 'name assetId type status');

    if (!asset) {
      return res.status(404).json({
        success: false,
        message: 'Asset not found'
      });
    }

    res.status(200).json({
      success: true,
      asset
    });
  } catch (error) {
    console.error('Get asset error:', error);
    res.status(500).json({
      success: false,
      message: 'Error retrieving asset'
    });
  }
};

// @desc    Create new asset
// @route   POST /api/assets
// @access  Private
exports.createAsset = async (req, res) => {
  try {
    // Check for validation errors
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        success: false,
        message: 'Validation failed',
        errors: errors.array()
      });
    }

    // Add discovery information
    req.body.discoveredBy = req.user._id;
    req.body.lastUpdatedBy = req.user._id;
    
    // Set default discovery method if not provided
    if (!req.body.discoveryMethod) {
      req.body.discoveryMethod = 'manual';
    }

    // Set default position for topology
    if (!req.body.position) {
      req.body.position = { x: 0, y: 0 };
    }

    const asset = await Asset.create(req.body);

    // Populate the created asset
    const populatedAsset = await Asset.findById(asset._id)
      .populate('discoveredBy', 'username firstName lastName fullName')
      .populate('lastUpdatedBy', 'username firstName lastName fullName');

    res.status(201).json({
      success: true,
      asset: populatedAsset
    });
  } catch (error) {
    console.error('Create asset error:', error);
    res.status(500).json({
      success: false,
      message: 'Error creating asset'
    });
  }
};

// @desc    Update asset
// @route   PUT /api/assets/:id
// @access  Private
exports.updateAsset = async (req, res) => {
  try {
    let asset = await Asset.findById(req.params.id);

    if (!asset) {
      return res.status(404).json({
        success: false,
        message: 'Asset not found'
      });
    }

    // Add update information
    req.body.lastUpdatedBy = req.user._id;

    // Remove fields that shouldn't be updated directly
    delete req.body.assetId;
    delete req.body.discoveredBy;

    asset = await Asset.findByIdAndUpdate(
      req.params.id,
      req.body,
      {
        new: true,
        runValidators: true
      }
    ).populate('discoveredBy lastUpdatedBy', 'username firstName lastName fullName');

    res.status(200).json({
      success: true,
      asset
    });
  } catch (error) {
    console.error('Update asset error:', error);
    res.status(500).json({
      success: false,
      message: 'Error updating asset'
    });
  }
};

// @desc    Delete asset
// @route   DELETE /api/assets/:id
// @access  Private (Admin/SOC Manager only)
exports.deleteAsset = async (req, res) => {
  try {
    const asset = await Asset.findById(req.params.id);

    if (!asset) {
      return res.status(404).json({
        success: false,
        message: 'Asset not found'
      });
    }

    await Asset.findByIdAndDelete(req.params.id);

    res.status(200).json({
      success: true,
      message: 'Asset deleted successfully'
    });
  } catch (error) {
    console.error('Delete asset error:', error);
    res.status(500).json({
      success: false,
      message: 'Error deleting asset'
    });
  }
};

// @desc    Get asset statistics
// @route   GET /api/assets/stats
// @access  Private
exports.getAssetStats = async (req, res) => {
  try {
    // Build filter based on query params
    let filter = {};
    
    if (req.query.type) {
      filter.type = req.query.type;
    }
    
    if (req.query.location) {
      filter.location = req.query.location;
    }
    
    if (req.query.dateFrom || req.query.dateTo) {
      filter.lastSeen = {};
      if (req.query.dateFrom) filter.lastSeen.$gte = new Date(req.query.dateFrom);
      if (req.query.dateTo) filter.lastSeen.$lte = new Date(req.query.dateTo);
    }

    const stats = await Asset.getAssetStatistics(filter);
    
    // Additional aggregations
    const additionalStats = await Asset.aggregate([
      { $match: filter },
      {
        $group: {
          _id: null,
          avgRiskScore: { $avg: '$riskLevel' },
          totalPatching: { $avg: '$patchLevel' },
          avgHealthScore: { $avg: '$healthScore' },
          assetsByType: {
            $push: {
              type: '$type',
              criticality: '$criticality'
            }
          },
          assetsByLocation: {
            $push: {
              location: '$location',
              status: '$status'
            }
          }
        }
      }
    ]);

    // Count by status
    const statusCounts = await Asset.aggregate([
      { $match: filter },
      {
        $group: {
          _id: '$status',
          count: { $sum: 1 }
        }
      }
    ]);

    // Count by criticality
    const criticalityCounts = await Asset.aggregate([
      { $match: filter },
      {
        $group: {
          _id: '$criticality',
          count: { $sum: 1 }
        }
      }
    ]);

    // Count by type
    const typeCounts = await Asset.aggregate([
      { $match: filter },
      {
        $group: {
          _id: '$type',
          count: { $sum: 1 }
        }
      }
    ]);

    // Count by risk level
    const riskLevelCounts = await Asset.aggregate([
      { $match: filter },
      {
        $group: {
          _id: '$riskLevel',
          count: { $sum: 1 }
        }
      }
    ]);

    const combinedStats = {
      ...stats,
      statusBreakdown: statusCounts.reduce((acc, item) => {
        acc[item._id] = item.count;
        return acc;
      }, {}),
      criticalityBreakdown: criticalityCounts.reduce((acc, item) => {
        acc[item._id] = item.count;
        return acc;
      }, {}),
      typeBreakdown: typeCounts.reduce((acc, item) => {
        acc[item._id] = item.count;
        return acc;
      }, {}),
      riskLevelBreakdown: riskLevelCounts.reduce((acc, item) => {
        acc[item._id] = item.count;
        return acc;
      }, {}),
      additionalMetrics: additionalStats[0] || {}
    };
    
    res.status(200).json({
      success: true,
      stats: combinedStats
    });
  } catch (error) {
    console.error('Get asset stats error:', error);
    res.status(500).json({
      success: false,
      message: 'Error retrieving asset statistics'
    });
  }
};

// @desc    Update asset security scan results
// @route   POST /api/assets/:id/scan
// @access  Private
exports.updateSecurityScan = async (req, res) => {
  try {
    const asset = await Asset.findById(req.params.id);

    if (!asset) {
      return res.status(404).json({
        success: false,
        message: 'Asset not found'
      });
    }

    const { vulnerabilities, securityScore, complianceScore, lastVulnScan, nextVulnScan } = req.body;

    // Update security-related fields
    const updateData = {
      lastUpdatedBy: req.user._id,
      lastVulnScan: lastVulnScan || new Date()
    };

    if (vulnerabilities) {
      updateData.vulnerabilities = vulnerabilities;
      // Update total vulnerabilities
      updateData['vulnerabilities.total'] = 
        (vulnerabilities.critical || 0) + 
        (vulnerabilities.high || 0) + 
        (vulnerabilities.medium || 0) + 
        (vulnerabilities.low || 0);
    }

    if (securityScore !== undefined) {
      updateData.securityScore = securityScore;
    }

    if (complianceScore !== undefined) {
      updateData.complianceScore = complianceScore;
    }

    if (nextVulnScan) {
      updateData.nextVulnScan = new Date(nextVulnScan);
    }

    const updatedAsset = await Asset.findByIdAndUpdate(
      req.params.id,
      updateData,
      { new: true, runValidators: true }
    ).populate('lastUpdatedBy', 'username firstName lastName fullName');

    // Recalculate risk score
    const riskScore = updatedAsset.calculateRiskScore();
    if (riskScore >= 80) updatedAsset.riskLevel = 'critical';
    else if (riskScore >= 60) updatedAsset.riskLevel = 'high';
    else if (riskScore >= 40) updatedAsset.riskLevel = 'medium';
    else if (riskScore >= 20) updatedAsset.riskLevel = 'low';
    else updatedAsset.riskLevel = 'very_low';

    await updatedAsset.save();

    res.status(200).json({
      success: true,
      message: 'Security scan results updated successfully',
      asset: updatedAsset
    });
  } catch (error) {
    console.error('Update security scan error:', error);
    res.status(500).json({
      success: false,
      message: 'Error updating security scan results'
    });
  }
};

// @desc    Update asset patch status
// @route   POST /api/assets/:id/patch
// @access  Private
exports.updatePatchStatus = async (req, res) => {
  try {
    const asset = await Asset.findById(req.params.id);

    if (!asset) {
      return res.status(404).json({
        success: false,
        message: 'Asset not found'
      });
    }

    const { patchLevel, lastPatchDate, pendingPatches } = req.body;

    const updateData = {
      lastUpdatedBy: req.user._id
    };

    if (patchLevel !== undefined) {
      updateData.patchLevel = patchLevel;
    }

    if (lastPatchDate) {
      updateData.lastPatchDate = new Date(lastPatchDate);
    }

    if (pendingPatches !== undefined) {
      updateData.pendingPatches = pendingPatches;
    }

    const updatedAsset = await Asset.findByIdAndUpdate(
      req.params.id,
      updateData,
      { new: true, runValidators: true }
    ).populate('lastUpdatedBy', 'username firstName lastName fullName');

    res.status(200).json({
      success: true,
      message: 'Patch status updated successfully',
      asset: updatedAsset
    });
  } catch (error) {
    console.error('Update patch status error:', error);
    res.status(500).json({
      success: false,
      message: 'Error updating patch status'
    });
  }
};

// @desc    Update asset performance metrics
// @route   POST /api/assets/:id/metrics
// @access  Private
exports.updateMetrics = async (req, res) => {
  try {
    const asset = await Asset.findById(req.params.id);

    if (!asset) {
      return res.status(404).json({
        success: false,
        message: 'Asset not found'
      });
    }

    const { cpu, memory, storage, networkLoad, throughput, bandwidth } = req.body;

    // Use the instance method to update metrics
    const updatedAsset = await asset.updateMetrics({
      cpu,
      memory,
      storage,
      networkLoad
    });

    // Update additional network metrics if provided
    if (throughput || bandwidth) {
      const metadataUpdate = {};
      if (throughput) metadataUpdate['metadata.throughput'] = throughput;
      if (bandwidth) metadataUpdate['metadata.bandwidth'] = bandwidth;
      
      await Asset.findByIdAndUpdate(req.params.id, metadataUpdate);
    }

    res.status(200).json({
      success: true,
      message: 'Performance metrics updated successfully',
      asset: updatedAsset
    });
  } catch (error) {
    console.error('Update metrics error:', error);
    res.status(500).json({
      success: false,
      message: 'Error updating performance metrics'
    });
  }
};

// @desc    Bulk update assets
// @route   PUT /api/assets/bulk
// @access  Private
exports.bulkUpdateAssets = async (req, res) => {
  try {
    const { assetIds, updates } = req.body;

    if (!assetIds || !Array.isArray(assetIds) || assetIds.length === 0) {
      return res.status(400).json({
        success: false,
        message: 'Asset IDs array is required'
      });
    }

    if (!updates || Object.keys(updates).length === 0) {
      return res.status(400).json({
        success: false,
        message: 'Updates object is required'
      });
    }

    // Remove fields that shouldn't be bulk updated
    delete updates.assetId;
    delete updates.discoveredBy;

    // Add update information
    updates.lastUpdatedBy = req.user._id;

    const result = await Asset.updateMany(
      { _id: { $in: assetIds } },
      { $set: updates }
    );

    res.status(200).json({
      success: true,
      message: `${result.modifiedCount} assets updated successfully`,
      modifiedCount: result.modifiedCount
    });
  } catch (error) {
    console.error('Bulk update assets error:', error);
    res.status(500).json({
      success: false,
      message: 'Error bulk updating assets'
    });
  }
};

// @desc    Get assets by location
// @route   GET /api/assets/location/:location
// @access  Private
exports.getAssetsByLocation = async (req, res) => {
  try {
    const { location } = req.params;
    const { status, type } = req.query;

    let query = { location };

    if (status) {
      query.status = status;
    }

    if (type) {
      query.type = type;
    }

    const assets = await Asset.find(query)
      .populate('lastUpdatedBy', 'username firstName lastName')
      .sort({ name: 1 });

    res.status(200).json({
      success: true,
      count: assets.length,
      location,
      assets
    });
  } catch (error) {
    console.error('Get assets by location error:', error);
    res.status(500).json({
      success: false,
      message: 'Error retrieving assets by location'
    });
  }
};

// @desc    Get network topology data
// @route   GET /api/assets/topology
// @access  Private
exports.getNetworkTopology = async (req, res) => {
  try {
    const { location, type } = req.query;
    
    let filter = {};
    if (location) filter.location = location;
    if (type) filter.type = type;

    const topologyData = await Asset.getNetworkTopology(filter);

    res.status(200).json({
      success: true,
      count: topologyData.length,
      topology: topologyData
    });
  } catch (error) {
    console.error('Get network topology error:', error);
    res.status(500).json({
      success: false,
      message: 'Error retrieving network topology'
    });
  }
};

// @desc    Update asset position in topology
// @route   PUT /api/assets/:id/position
// @access  Private
exports.updatePosition = async (req, res) => {
  try {
    const { x, y } = req.body;

    if (x === undefined || y === undefined) {
      return res.status(400).json({
        success: false,
        message: 'Position coordinates (x, y) are required'
      });
    }

    const asset = await Asset.findByIdAndUpdate(
      req.params.id,
      { 
        position: { x, y },
        lastUpdatedBy: req.user._id
      },
      { new: true }
    );

    if (!asset) {
      return res.status(404).json({
        success: false,
        message: 'Asset not found'
      });
    }

    res.status(200).json({
      success: true,
      message: 'Asset position updated successfully',
      position: asset.position
    });
  } catch (error) {
    console.error('Update position error:', error);
    res.status(500).json({
      success: false,
      message: 'Error updating asset position'
    });
  }
};

// @desc    Add connection between assets
// @route   POST /api/assets/:id/connections
// @access  Private
exports.addConnection = async (req, res) => {
  try {
    const { targetAssetId, relationship } = req.body;

    if (!targetAssetId) {
      return res.status(400).json({
        success: false,
        message: 'Target asset ID is required'
      });
    }

    const asset = await Asset.findById(req.params.id);
    if (!asset) {
      return res.status(404).json({
        success: false,
        message: 'Asset not found'
      });
    }

    // Verify target asset exists
    const targetAsset = await Asset.findOne({ assetId: targetAssetId });
    if (!targetAsset) {
      return res.status(404).json({
        success: false,
        message: 'Target asset not found'
      });
    }

    await asset.addConnection(targetAssetId, relationship);

    res.status(200).json({
      success: true,
      message: 'Connection added successfully',
      connections: asset.connections,
      dependencies: asset.dependencies
    });
  } catch (error) {
    console.error('Add connection error:', error);
    res.status(500).json({
      success: false,
      message: 'Error adding connection'
    });
  }
};

// @desc    Export assets to CSV
// @route   GET /api/assets/export
// @access  Private
exports.exportAssets = async (req, res) => {
  try {
    // Build query (similar to getAssets)
    let query = {};
    
    const { 
      type, 
      status, 
      criticality,
      location,
      dateFrom,
      dateTo
    } = req.query;

    if (type) query.type = Array.isArray(type) ? { $in: type } : type;
    if (status) query.status = Array.isArray(status) ? { $in: status } : status;
    if (criticality) query.criticality = Array.isArray(criticality) ? { $in: criticality } : criticality;
    if (location) query.location = Array.isArray(location) ? { $in: location } : location;
    
    if (dateFrom || dateTo) {
      query.lastSeen = {};
      if (dateFrom) query.lastSeen.$gte = new Date(dateFrom);
      if (dateTo) query.lastSeen.$lte = new Date(dateTo);
    }

    const assets = await Asset.find(query)
      .populate('discoveredBy lastUpdatedBy', 'username firstName lastName')
      .sort({ name: 1 })
      .lean();

    // Convert to CSV format - updated for new schema
    const csvHeaders = [
      'Asset ID',
      'Name',
      'Type',
      'Status',
      'IP Address',
      'MAC Address',
      'Hostname',
      'Operating System',
      'OS Version',
      'Location',
      'Owner',
      'Criticality',
      'Risk Level',
      'Security Score',
      'Compliance Score',
      'Patch Level',
      'Total Vulnerabilities',
      'CPU Usage',
      'Memory Usage',
      'Storage Usage',
      'Network Load',
      'Health Score',
      'Manufacturer',
      'Model',
      'Serial Number',
      'Last Seen',
      'Discovered By'
    ];

    const csvRows = assets.map(asset => [
      asset.assetId,
      `"${asset.name}"`,
      asset.type,
      asset.status,
      asset.ipAddress,
      asset.macAddress || '',
      asset.hostname || '',
      `"${asset.operatingSystem || ''}"`,
      `"${asset.osVersion || ''}"`,
      `"${asset.location}"`,
      `"${asset.owner}"`,
      asset.criticality,
      asset.riskLevel,
      asset.securityScore,
      asset.complianceScore,
      asset.patchLevel,
      (asset.vulnerabilities.critical + asset.vulnerabilities.high + asset.vulnerabilities.medium + asset.vulnerabilities.low),
      asset.metadata?.cpu || 0,
      asset.metadata?.memory || 0,
      asset.metadata?.storage || 0,
      asset.metadata?.networkLoad || 0,
      asset.healthScore || 0,
      `"${asset.metadata?.manufacturer || ''}"`,
      `"${asset.metadata?.model || ''}"`,
      `"${asset.metadata?.serialNumber || ''}"`,
      new Date(asset.lastSeen).toISOString(),
      asset.discoveredBy ? `"${asset.discoveredBy.firstName} ${asset.discoveredBy.lastName}"` : ''
    ]);

    const csvContent = [csvHeaders.join(','), ...csvRows.map(row => row.join(','))].join('\n');

    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', `attachment; filename="assets-export-${new Date().toISOString().split('T')[0]}.csv"`);
    res.status(200).send(csvContent);
  } catch (error) {
    console.error('Export assets error:', error);
    res.status(500).json({
      success: false,
      message: 'Error exporting assets'
    });
  }
};

// @desc    Search assets
// @route   GET /api/assets/search
// @access  Private
exports.searchAssets = async (req, res) => {
  try {
    const { q: searchTerm, type, status, location, limit = 20 } = req.query;

    if (!searchTerm) {
      return res.status(400).json({
        success: false,
        message: 'Search term is required'
      });
    }

    const filters = {};
    if (type) filters.type = type;
    if (status) filters.status = status;
    if (location) filters.location = location;

    const assets = await Asset.searchAssets(searchTerm, filters)
      .limit(parseInt(limit))
      .populate('lastUpdatedBy', 'username firstName lastName');

    res.status(200).json({
      success: true,
      count: assets.length,
      searchTerm,
      assets
    });
  } catch (error) {
    console.error('Search assets error:', error);
    res.status(500).json({
      success: false,
      message: 'Error searching assets'
    });
  }
};

// @desc    Get asset health status
// @route   GET /api/assets/:id/health
// @access  Private
exports.getAssetHealth = async (req, res) => {
  try {
    const asset = await Asset.findById(req.params.id);

    if (!asset) {
      return res.status(404).json({
        success: false,
        message: 'Asset not found'
      });
    }

    const healthData = {
      assetId: asset.assetId,
      name: asset.name,
      status: asset.status,
      healthScore: asset.healthScore,
      uptime: asset.uptime,
      lastSeen: asset.lastSeen,
      daysSinceLastSeen: asset.daysSinceLastSeen,
      performance: {
        cpu: asset.metadata.cpu,
        memory: asset.metadata.memory,
        storage: asset.metadata.storage,
        networkLoad: asset.metadata.networkLoad
      },
      security: {
        securityScore: asset.securityScore,
        complianceScore: asset.complianceScore,
        vulnerabilities: asset.vulnerabilities,
        riskLevel: asset.riskLevel
      },
      maintenance: {
        patchLevel: asset.patchLevel,
        lastPatchDate: asset.lastPatchDate,
        pendingPatches: asset.pendingPatches,
        lastVulnScan: asset.lastVulnScan,
        nextVulnScan: asset.nextVulnScan
      }
    };

    res.status(200).json({
      success: true,
      health: healthData
    });
  } catch (error) {
    console.error('Get asset health error:', error);
    res.status(500).json({
      success: false,
      message: 'Error retrieving asset health'
    });
  }
};

// @desc    Get assets by type
// @route   GET /api/assets/type/:type
// @access  Private
exports.getAssetsByType = async (req, res) => {
  try {
    const { type } = req.params;
    const { status, location, criticality } = req.query;

    let query = { type };

    if (status) query.status = status;
    if (location) query.location = location;
    if (criticality) query.criticality = criticality;

    const assets = await Asset.find(query)
      .populate('lastUpdatedBy', 'username firstName lastName')
      .sort({ name: 1 });

    // Get type statistics
    const typeStats = await Asset.aggregate([
      { $match: { type } },
      {
        $group: {
          _id: null,
          total: { $sum: 1 },
          online: { $sum: { $cond: [{ $eq: ['$status', 'online'] }, 1, 0] } },
          offline: { $sum: { $cond: [{ $eq: ['$status', 'offline'] }, 1, 0] } },
          avgHealthScore: { $avg: '$healthScore' },
          avgSecurityScore: { $avg: '$securityScore' },
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
    ]);

    res.status(200).json({
      success: true,
      count: assets.length,
      type,
      stats: typeStats[0] || {},
      assets
    });
  } catch (error) {
    console.error('Get assets by type error:', error);
    res.status(500).json({
      success: false,
      message: 'Error retrieving assets by type'
    });
  }
};

// @desc    Update asset software inventory
// @route   PUT /api/assets/:id/software
// @access  Private
exports.updateSoftwareInventory = async (req, res) => {
  try {
    const { software } = req.body;

    if (!software || !Array.isArray(software)) {
      return res.status(400).json({
        success: false,
        message: 'Software array is required'
      });
    }

    const asset = await Asset.findByIdAndUpdate(
      req.params.id,
      { 
        software,
        lastUpdatedBy: req.user._id
      },
      { new: true, runValidators: true }
    ).populate('lastUpdatedBy', 'username firstName lastName');

    if (!asset) {
      return res.status(404).json({
        success: false,
        message: 'Asset not found'
      });
    }

    res.status(200).json({
      success: true,
      message: 'Software inventory updated successfully',
      software: asset.software
    });
  } catch (error) {
    console.error('Update software inventory error:', error);
    res.status(500).json({
      success: false,
      message: 'Error updating software inventory'
    });
  }
};

// @desc    Update asset services
// @route   PUT /api/assets/:id/services
// @access  Private
exports.updateServices = async (req, res) => {
  try {
    const { services } = req.body;

    if (!services || !Array.isArray(services)) {
      return res.status(400).json({
        success: false,
        message: 'Services array is required'
      });
    }

    const asset = await Asset.findByIdAndUpdate(
      req.params.id,
      { 
        services,
        lastUpdatedBy: req.user._id
      },
      { new: true, runValidators: true }
    ).populate('lastUpdatedBy', 'username firstName lastName');

    if (!asset) {
      return res.status(404).json({
        success: false,
        message: 'Asset not found'
      });
    }

    res.status(200).json({
      success: true,
      message: 'Services updated successfully',
      services: asset.services
    });
  } catch (error) {
    console.error('Update services error:', error);
    res.status(500).json({
      success: false,
      message: 'Error updating services'
    });
  }
};

// @desc    Update asset security controls
// @route   PUT /api/assets/:id/security-controls
// @access  Private
exports.updateSecurityControls = async (req, res) => {
  try {
    const { securityControls } = req.body;

    if (!securityControls) {
      return res.status(400).json({
        success: false,
        message: 'Security controls data is required'
      });
    }

    const asset = await Asset.findByIdAndUpdate(
      req.params.id,
      { 
        securityControls,
        lastUpdatedBy: req.user._id
      },
      { new: true, runValidators: true }
    ).populate('lastUpdatedBy', 'username firstName lastName');

    if (!asset) {
      return res.status(404).json({
        success: false,
        message: 'Asset not found'
      });
    }

    res.status(200).json({
      success: true,
      message: 'Security controls updated successfully',
      securityControls: asset.securityControls
    });
  } catch (error) {
    console.error('Update security controls error:', error);
    res.status(500).json({
      success: false,
      message: 'Error updating security controls'
    });
  }
};