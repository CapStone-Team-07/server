// controllers/assetController.js - Asset Management Controller
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
      discoveryMethod
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
    
    // Last seen date filtering
    if (lastSeenFrom || lastSeenTo) {
      query.lastSeen = {};
      if (lastSeenFrom) query.lastSeen.$gte = new Date(lastSeenFrom);
      if (lastSeenTo) query.lastSeen.$lte = new Date(lastSeenTo);
    }
    
    // Search functionality
    if (search) {
      query.$or = [
        { name: { $regex: search, $options: 'i' } },
        { assetId: { $regex: search, $options: 'i' } },
        { ipAddress: { $regex: search, $options: 'i' } },
        { macAddress: { $regex: search, $options: 'i' } },
        { hostname: { $regex: search, $options: 'i' } },
        { owner: { $regex: search, $options: 'i' } },
        { 'hardware.manufacturer': { $regex: search, $options: 'i' } },
        { 'hardware.model': { $regex: search, $options: 'i' } }
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
      req.body.discoveryMethod = 'Manual';
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

    await asset.remove();

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
          avgRiskScore: { $avg: { $toInt: '$riskLevel' } },
          totalPatching: { $avg: '$patchLevel' },
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

    const { vulnerabilities, securityScore, complianceScore, lastVulnScan } = req.body;

    // Update security-related fields
    const updateData = {
      lastUpdatedBy: req.user._id,
      lastVulnScan: lastVulnScan || new Date()
    };

    if (vulnerabilities) {
      updateData.vulnerabilities = vulnerabilities;
    }

    if (securityScore !== undefined) {
      updateData.securityScore = securityScore;
    }

    if (complianceScore !== undefined) {
      updateData.complianceScore = complianceScore;
    }

    // Calculate risk score if needed
    if (vulnerabilities || securityScore) {
      const updatedAsset = await Asset.findByIdAndUpdate(
        req.params.id,
        updateData,
        { new: true }
      );
      updateData.riskLevel = calculateRiskLevel(updatedAsset);
    }

    const updatedAsset = await Asset.findByIdAndUpdate(
      req.params.id,
      updateData,
      { new: true, runValidators: true }
    ).populate('lastUpdatedBy', 'username firstName lastName fullName');

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

    // Convert to CSV format
    const csvHeaders = [
      'Asset ID',
      'Name',
      'Type',
      'Status',
      'IP Address',
      'MAC Address',
      'Operating System',
      'Location',
      'Owner',
      'Criticality',
      'Security Score',
      'Compliance Score',
      'Patch Level',
      'Risk Level',
      'Total Vulnerabilities',
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
      `"${asset.operatingSystem}"`,
      `"${asset.location}"`,
      `"${asset.owner}"`,
      asset.criticality,
      asset.securityScore,
      asset.complianceScore,
      asset.patchLevel,
      asset.riskLevel,
      (asset.vulnerabilities.critical + asset.vulnerabilities.high + asset.vulnerabilities.medium + asset.vulnerabilities.low),
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

// Helper function to calculate risk level based on asset data
const calculateRiskLevel = (asset) => {
  let riskScore = 0;
  
  // Criticality weight (40%)
  const criticalityWeight = {
    'Critical': 40,
    'High': 30,
    'Medium': 20,
    'Low': 10
  };
  riskScore += criticalityWeight[asset.criticality] || 20;
  
  // Vulnerability weight (30%)
  const vulnScore = (asset.vulnerabilities.critical * 10) + 
                   (asset.vulnerabilities.high * 5) + 
                   (asset.vulnerabilities.medium * 2) + 
                   (asset.vulnerabilities.low * 1);
  riskScore += Math.min(vulnScore, 30);
  
  // Patch level weight (20%)
  riskScore += (100 - asset.patchLevel) * 0.2;
  
  // Security score weight (10%)
  riskScore += (100 - asset.securityScore) * 0.1;
  
  // Determine risk level based on score
  if (riskScore >= 80) return 'Critical';
  if (riskScore >= 60) return 'High';
  if (riskScore >= 40) return 'Medium';
  if (riskScore >= 20) return 'Low';
  return 'Very Low';
};