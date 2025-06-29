// controllers/threatController.js - Threat Management Controller
const Threat = require('../models/Threat');
const User = require('../models/User');
const { validationResult } = require('express-validator');

// @desc    Get all threats with filtering, sorting, and pagination
// @route   GET /api/threats
// @access  Private
exports.getThreats = async (req, res) => {
  try {
    // Build query object
    let query = {};
    
    // Filtering
    const { 
      severity, 
      status, 
      category, 
      source, 
      analyst, 
      country,
      riskScoreMin,
      riskScoreMax,
      dateFrom,
      dateTo,
      search,
      starred,
      flagged
    } = req.query;

    if (severity) {
      query.severity = Array.isArray(severity) ? { $in: severity } : severity;
    }
    
    if (status) {
      query.status = Array.isArray(status) ? { $in: status } : status;
    }
    
    if (category) {
      query.category = Array.isArray(category) ? { $in: category } : category;
    }
    
    if (source) {
      query.source = Array.isArray(source) ? { $in: source } : source;
    }
    
    if (analyst) {
      query.analyst = analyst;
    }
    
    if (country) {
      query.country = Array.isArray(country) ? { $in: country } : country;
    }
    
    if (riskScoreMin || riskScoreMax) {
      query.riskScore = {};
      if (riskScoreMin) query.riskScore.$gte = parseInt(riskScoreMin);
      if (riskScoreMax) query.riskScore.$lte = parseInt(riskScoreMax);
    }
    
    if (dateFrom || dateTo) {
      query.firstSeen = {};
      if (dateFrom) query.firstSeen.$gte = new Date(dateFrom);
      if (dateTo) query.firstSeen.$lte = new Date(dateTo);
    }
    
    if (starred === 'true') {
      query.starred = true;
    }
    
    if (flagged === 'true') {
      query.flagged = true;
    }
    
    // Search functionality
    if (search) {
      query.$or = [
        { title: { $regex: search, $options: 'i' } },
        { description: { $regex: search, $options: 'i' } },
        { threatId: { $regex: search, $options: 'i' } },
        { sourceIP: { $regex: search, $options: 'i' } },
        { targetIP: { $regex: search, $options: 'i' } },
        { 'iocs.ipAddresses': { $regex: search, $options: 'i' } },
        { 'iocs.domains': { $regex: search, $options: 'i' } }
      ];
    }

    // Sorting
    let sortBy = {};
    const { sort, order } = req.query;
    
    if (sort) {
      sortBy[sort] = order === 'asc' ? 1 : -1;
    } else {
      sortBy.firstSeen = -1; // Default sort by newest first
    }

    // Pagination
    const page = parseInt(req.query.page) || 1;
    const limit = Math.min(parseInt(req.query.limit) || 25, 100); // Max 100 per page
    const skip = (page - 1) * limit;

    // Execute query
    const threats = await Threat.find(query)
      .populate('analyst', 'username firstName lastName fullName')
      .populate('escalatedTo', 'username firstName lastName fullName')
      .populate('actions.user', 'username firstName lastName fullName')
      .sort(sortBy)
      .skip(skip)
      .limit(limit)
      .lean();

    // Get total count for pagination
    const total = await Threat.countDocuments(query);
    const totalPages = Math.ceil(total / limit);

    res.status(200).json({
      success: true,
      count: threats.length,
      total,
      page,
      totalPages,
      limit,
      threats
    });
  } catch (error) {
    console.error('Get threats error:', error);
    res.status(500).json({
      success: false,
      message: 'Error retrieving threats'
    });
  }
};

// @desc    Get single threat
// @route   GET /api/threats/:id
// @access  Private
exports.getThreat = async (req, res) => {
  try {
    const threat = await Threat.findById(req.params.id)
      .populate('analyst', 'username firstName lastName fullName email role')
      .populate('escalatedTo', 'username firstName lastName fullName email role')
      .populate('actions.user', 'username firstName lastName fullName')
      .populate('blockedBy escalatedBy resolvedBy', 'username firstName lastName fullName');

    if (!threat) {
      return res.status(404).json({
        success: false,
        message: 'Threat not found'
      });
    }

    // Increment view count
    threat.metrics.viewCount += 1;
    threat.metrics.lastViewed = new Date();
    await threat.save();

    res.status(200).json({
      success: true,
      threat
    });
  } catch (error) {
    console.error('Get threat error:', error);
    res.status(500).json({
      success: false,
      message: 'Error retrieving threat'
    });
  }
};

// @desc    Create new threat
// @route   POST /api/threats
// @access  Private
exports.createThreat = async (req, res) => {
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

    // Add user as analyst
    req.body.analyst = req.user._id;
    req.body.analystName = req.user.fullName || req.user.username;

    const threat = await Threat.create(req.body);

    // Populate the created threat
    const populatedThreat = await Threat.findById(threat._id)
      .populate('analyst', 'username firstName lastName fullName');

    res.status(201).json({
      success: true,
      threat: populatedThreat
    });
  } catch (error) {
    console.error('Create threat error:', error);
    res.status(500).json({
      success: false,
      message: 'Error creating threat'
    });
  }
};

// @desc    Update threat
// @route   PUT /api/threats/:id
// @access  Private
exports.updateThreat = async (req, res) => {
  try {
    let threat = await Threat.findById(req.params.id);

    if (!threat) {
      return res.status(404).json({
        success: false,
        message: 'Threat not found'
      });
    }

    // Check permissions - only assigned analyst, escalated user, or admin can update
    if (threat.analyst.toString() !== req.user._id.toString() && 
        req.user.role !== 'admin' && 
        req.user.role !== 'soc_manager') {
      return res.status(403).json({
        success: false,
        message: 'Not authorized to update this threat'
      });
    }

    // Remove fields that shouldn't be updated directly
    delete req.body.threatId;
    delete req.body.analyst;
    delete req.body.actions;

    threat = await Threat.findByIdAndUpdate(
      req.params.id,
      req.body,
      {
        new: true,
        runValidators: true
      }
    ).populate('analyst', 'username firstName lastName fullName');

    res.status(200).json({
      success: true,
      threat
    });
  } catch (error) {
    console.error('Update threat error:', error);
    res.status(500).json({
      success: false,
      message: 'Error updating threat'
    });
  }
};

// @desc    Delete threat
// @route   DELETE /api/threats/:id
// @access  Private (Admin/SOC Manager only)
exports.deleteThreat = async (req, res) => {
  try {
    const threat = await Threat.findById(req.params.id);

    if (!threat) {
      return res.status(404).json({
        success: false,
        message: 'Threat not found'
      });
    }

    await threat.remove();

    res.status(200).json({
      success: true,
      message: 'Threat deleted successfully'
    });
  } catch (error) {
    console.error('Delete threat error:', error);
    res.status(500).json({
      success: false,
      message: 'Error deleting threat'
    });
  }
};

// @desc    Block IP address (threat action)
// @route   POST /api/threats/:id/block
// @access  Private
exports.blockThreat = async (req, res) => {
  try {
    const threat = await Threat.findById(req.params.id);

    if (!threat) {
      return res.status(404).json({
        success: false,
        message: 'Threat not found'
      });
    }

    if (threat.status === 'Blocked') {
      return res.status(400).json({
        success: false,
        message: 'Threat is already blocked'
      });
    }

    // Add block action
    await threat.addAction('block', req.user, req.body.notes || `IP ${threat.sourceIP} blocked due to malicious activity`);

    const updatedThreat = await Threat.findById(threat._id)
      .populate('analyst', 'username firstName lastName fullName')
      .populate('blockedBy', 'username firstName lastName fullName');

    res.status(200).json({
      success: true,
      message: `IP ${threat.sourceIP} has been blocked successfully`,
      threat: updatedThreat
    });
  } catch (error) {
    console.error('Block threat error:', error);
    res.status(500).json({
      success: false,
      message: 'Error blocking threat'
    });
  }
};

// @desc    Escalate threat
// @route   POST /api/threats/:id/escalate
// @access  Private
exports.escalateThreat = async (req, res) => {
  try {
    const threat = await Threat.findById(req.params.id);

    if (!threat) {
      return res.status(404).json({
        success: false,
        message: 'Threat not found'
      });
    }

    if (threat.status === 'Escalated') {
      return res.status(400).json({
        success: false,
        message: 'Threat is already escalated'
      });
    }

    // Upgrade severity if needed
    const severityLevels = { 'Low': 'Medium', 'Medium': 'High', 'High': 'Critical', 'Critical': 'Critical' };
    const newSeverity = severityLevels[threat.severity];
    
    if (newSeverity !== threat.severity) {
      threat.severity = newSeverity;
    }

    // Set escalated user if provided
    if (req.body.escalateTo) {
      const escalateToUser = await User.findById(req.body.escalateTo);
      if (escalateToUser) {
        threat.escalatedTo = escalateToUser._id;
      }
    }

    // Add escalate action
    await threat.addAction('escalate', req.user, req.body.notes || `Threat escalated to ${newSeverity} severity and forwarded to Security Manager`);

    const updatedThreat = await Threat.findById(threat._id)
      .populate('analyst', 'username firstName lastName fullName')
      .populate('escalatedBy escalatedTo', 'username firstName lastName fullName');

    res.status(200).json({
      success: true,
      message: `Threat ${threat.threatId} has been escalated to ${newSeverity} severity`,
      threat: updatedThreat
    });
  } catch (error) {
    console.error('Escalate threat error:', error);
    res.status(500).json({
      success: false,
      message: 'Error escalating threat'
    });
  }
};

// @desc    Resolve threat
// @route   POST /api/threats/:id/resolve
// @access  Private
exports.resolveThreat = async (req, res) => {
  try {
    const threat = await Threat.findById(req.params.id);

    if (!threat) {
      return res.status(404).json({
        success: false,
        message: 'Threat not found'
      });
    }

    if (threat.status === 'Resolved') {
      return res.status(400).json({
        success: false,
        message: 'Threat is already resolved'
      });
    }

    // Add resolve action
    await threat.addAction('resolve', req.user, req.body.notes || 'Threat analyzed and confirmed as resolved. No further action required.');

    const updatedThreat = await Threat.findById(threat._id)
      .populate('analyst', 'username firstName lastName fullName')
      .populate('resolvedBy', 'username firstName lastName fullName');

    res.status(200).json({
      success: true,
      message: `Threat ${threat.threatId} has been resolved successfully`,
      threat: updatedThreat
    });
  } catch (error) {
    console.error('Resolve threat error:', error);
    res.status(500).json({
      success: false,
      message: 'Error resolving threat'
    });
  }
};

// @desc    Add IOC to threat
// @route   POST /api/threats/:id/iocs
// @access  Private
exports.addIOC = async (req, res) => {
  try {
    const threat = await Threat.findById(req.params.id);

    if (!threat) {
      return res.status(404).json({
        success: false,
        message: 'Threat not found'
      });
    }

    const { type, value } = req.body;

    if (!type || !value) {
      return res.status(400).json({
        success: false,
        message: 'IOC type and value are required'
      });
    }

    await threat.addIOC(type, value);

    res.status(200).json({
      success: true,
      message: 'IOC added successfully',
      iocs: threat.iocs
    });
  } catch (error) {
    console.error('Add IOC error:', error);
    res.status(500).json({
      success: false,
      message: 'Error adding IOC'
    });
  }
};

// @desc    Toggle threat star
// @route   POST /api/threats/:id/star
// @access  Private
exports.toggleStar = async (req, res) => {
  try {
    const threat = await Threat.findById(req.params.id);

    if (!threat) {
      return res.status(404).json({
        success: false,
        message: 'Threat not found'
      });
    }

    threat.starred = !threat.starred;
    await threat.save();

    res.status(200).json({
      success: true,
      starred: threat.starred,
      message: threat.starred ? 'Threat starred' : 'Threat unstarred'
    });
  } catch (error) {
    console.error('Toggle star error:', error);
    res.status(500).json({
      success: false,
      message: 'Error toggling star'
    });
  }
};

// @desc    Toggle threat flag
// @route   POST /api/threats/:id/flag
// @access  Private
exports.toggleFlag = async (req, res) => {
  try {
    const threat = await Threat.findById(req.params.id);

    if (!threat) {
      return res.status(404).json({
        success: false,
        message: 'Threat not found'
      });
    }

    threat.flagged = !threat.flagged;
    await threat.save();

    res.status(200).json({
      success: true,
      flagged: threat.flagged,
      message: threat.flagged ? 'Threat flagged' : 'Threat unflagged'
    });
  } catch (error) {
    console.error('Toggle flag error:', error);
    res.status(500).json({
      success: false,
      message: 'Error toggling flag'
    });
  }
};

// @desc    Get threat statistics
// @route   GET /api/threats/stats
// @access  Private
exports.getThreatStats = async (req, res) => {
  try {
    // Build filter based on query params
    let filter = {};
    
    if (req.query.analyst) {
      filter.analyst = req.query.analyst;
    }
    
    if (req.query.dateFrom || req.query.dateTo) {
      filter.firstSeen = {};
      if (req.query.dateFrom) filter.firstSeen.$gte = new Date(req.query.dateFrom);
      if (req.query.dateTo) filter.firstSeen.$lte = new Date(req.query.dateTo);
    }

    const stats = await Threat.getStatistics(filter);
    
    res.status(200).json({
      success: true,
      stats
    });
  } catch (error) {
    console.error('Get threat stats error:', error);
    res.status(500).json({
      success: false,
      message: 'Error retrieving threat statistics'
    });
  }
};

// @desc    Get trending threats
// @route   GET /api/threats/trending
// @access  Private
exports.getTrendingThreats = async (req, res) => {
  try {
    const days = parseInt(req.query.days) || 7;
    const trending = await Threat.getTrending(days);
    
    res.status(200).json({
      success: true,
      trending
    });
  } catch (error) {
    console.error('Get trending threats error:', error);
    res.status(500).json({
      success: false,
      message: 'Error retrieving trending threats'
    });
  }
};

// @desc    Get top source IPs
// @route   GET /api/threats/top-sources
// @access  Private
exports.getTopSources = async (req, res) => {
  try {
    const limit = parseInt(req.query.limit) || 10;
    let filter = {};
    
    if (req.query.dateFrom || req.query.dateTo) {
      filter.firstSeen = {};
      if (req.query.dateFrom) filter.firstSeen.$gte = new Date(req.query.dateFrom);
      if (req.query.dateTo) filter.firstSeen.$lte = new Date(req.query.dateTo);
    }

    const topSources = await Threat.getTopSourceIPs(limit, filter);
    
    res.status(200).json({
      success: true,
      topSources
    });
  } catch (error) {
    console.error('Get top sources error:', error);
    res.status(500).json({
      success: false,
      message: 'Error retrieving top source IPs'
    });
  }
};

// @desc    Bulk update threats
// @route   PUT /api/threats/bulk
// @access  Private
exports.bulkUpdateThreats = async (req, res) => {
  try {
    const { threatIds, updates } = req.body;

    if (!threatIds || !Array.isArray(threatIds) || threatIds.length === 0) {
      return res.status(400).json({
        success: false,
        message: 'Threat IDs array is required'
      });
    }

    if (!updates || Object.keys(updates).length === 0) {
      return res.status(400).json({
        success: false,
        message: 'Updates object is required'
      });
    }

    // Remove fields that shouldn't be bulk updated
    delete updates.threatId;
    delete updates.analyst;
    delete updates.actions;

    const result = await Threat.updateMany(
      { _id: { $in: threatIds } },
      { $set: updates }
    );

    res.status(200).json({
      success: true,
      message: `${result.modifiedCount} threats updated successfully`,
      modifiedCount: result.modifiedCount
    });
  } catch (error) {
    console.error('Bulk update threats error:', error);
    res.status(500).json({
      success: false,
      message: 'Error bulk updating threats'
    });
  }
};

// @desc    Assign threat to analyst
// @route   PUT /api/threats/:id/assign
// @access  Private (Admin/SOC Manager only)
exports.assignThreat = async (req, res) => {
  try {
    const { analystId } = req.body;

    if (!analystId) {
      return res.status(400).json({
        success: false,
        message: 'Analyst ID is required'
      });
    }

    // Verify analyst exists
    const analyst = await User.findById(analystId);
    if (!analyst) {
      return res.status(404).json({
        success: false,
        message: 'Analyst not found'
      });
    }

    const threat = await Threat.findById(req.params.id);
    if (!threat) {
      return res.status(404).json({
        success: false,
        message: 'Threat not found'
      });
    }

    // Update assignment
    threat.analyst = analystId;
    threat.analystName = analyst.fullName || analyst.username;
    
    // Add action
    await threat.addAction(
      'investigate', 
      req.user, 
      `Threat reassigned to ${analyst.fullName || analyst.username}`
    );

    const updatedThreat = await Threat.findById(threat._id)
      .populate('analyst', 'username firstName lastName fullName');

    res.status(200).json({
      success: true,
      message: 'Threat assigned successfully',
      threat: updatedThreat
    });
  } catch (error) {
    console.error('Assign threat error:', error);
    res.status(500).json({
      success: false,
      message: 'Error assigning threat'
    });
  }
};

// @desc    Get threat timeline
// @route   GET /api/threats/timeline
// @access  Private
exports.getThreatTimeline = async (req, res) => {
  try {
    const { days = 30, groupBy = 'day' } = req.query;
    
    const endDate = new Date();
    const startDate = new Date();
    startDate.setDate(endDate.getDate() - parseInt(days));

    let dateFormat;
    switch (groupBy) {
      case 'hour':
        dateFormat = '%Y-%m-%d %H:00:00';
        break;
      case 'day':
        dateFormat = '%Y-%m-%d';
        break;
      case 'week':
        dateFormat = '%Y-%U';
        break;
      case 'month':
        dateFormat = '%Y-%m';
        break;
      default:
        dateFormat = '%Y-%m-%d';
    }

    const timeline = await Threat.aggregate([
      {
        $match: {
          firstSeen: {
            $gte: startDate,
            $lte: endDate
          }
        }
      },
      {
        $group: {
          _id: {
            date: {
              $dateToString: {
                format: dateFormat,
                date: '$firstSeen'
              }
            },
            severity: '$severity'
          },
          count: { $sum: 1 }
        }
      },
      {
        $group: {
          _id: '$_id.date',
          critical: {
            $sum: {
              $cond: [{ $eq: ['$_id.severity', 'Critical'] }, '$count', 0]
            }
          },
          high: {
            $sum: {
              $cond: [{ $eq: ['$_id.severity', 'High'] }, '$count', 0]
            }
          },
          medium: {
            $sum: {
              $cond: [{ $eq: ['$_id.severity', 'Medium'] }, '$count', 0]
            }
          },
          low: {
            $sum: {
              $cond: [{ $eq: ['$_id.severity', 'Low'] }, '$count', 0]
            }
          },
          total: { $sum: '$count' }
        }
      },
      {
        $sort: { '_id': 1 }
      },
      {
        $project: {
          date: '$_id',
          critical: 1,
          high: 1,
          medium: 1,
          low: 1,
          total: 1,
          _id: 0
        }
      }
    ]);

    res.status(200).json({
      success: true,
      timeline
    });
  } catch (error) {
    console.error('Get threat timeline error:', error);
    res.status(500).json({
      success: false,
      message: 'Error retrieving threat timeline'
    });
  }
};

// @desc    Export threats to CSV
// @route   GET /api/threats/export
// @access  Private
exports.exportThreats = async (req, res) => {
  try {
    // Build query (similar to getThreats)
    let query = {};
    
    const { 
      severity, 
      status, 
      category, 
      dateFrom,
      dateTo
    } = req.query;

    if (severity) query.severity = Array.isArray(severity) ? { $in: severity } : severity;
    if (status) query.status = Array.isArray(status) ? { $in: status } : status;
    if (category) query.category = Array.isArray(category) ? { $in: category } : category;
    
    if (dateFrom || dateTo) {
      query.firstSeen = {};
      if (dateFrom) query.firstSeen.$gte = new Date(dateFrom);
      if (dateTo) query.firstSeen.$lte = new Date(dateTo);
    }

    const threats = await Threat.find(query)
      .populate('analyst', 'username firstName lastName')
      .sort({ firstSeen: -1 })
      .lean();

    // Convert to CSV format
    const csvHeaders = [
      'Threat ID',
      'Title',
      'Severity',
      'Status',
      'Category',
      'Risk Score',
      'Source IP',
      'Target IP',
      'Country',
      'Protocol',
      'Port',
      'First Seen',
      'Last Activity',
      'Analyst',
      'IOCs Count',
      'Actions Count'
    ];

    const csvRows = threats.map(threat => [
      threat.threatId,
      `"${threat.title}"`,
      threat.severity,
      threat.status,
      threat.category,
      threat.riskScore,
      threat.sourceIP,
      threat.targetIP,
      threat.country,
      threat.protocol,
      threat.port || '',
      new Date(threat.firstSeen).toISOString(),
      new Date(threat.lastActivity).toISOString(),
      threat.analyst ? `"${threat.analyst.firstName} ${threat.analyst.lastName}"` : '',
      threat.iocsCount,
      threat.actions.length
    ]);

    const csvContent = [csvHeaders.join(','), ...csvRows.map(row => row.join(','))].join('\n');

    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', `attachment; filename="threats-export-${new Date().toISOString().split('T')[0]}.csv"`);
    res.status(200).send(csvContent);
  } catch (error) {
    console.error('Export threats error:', error);
    res.status(500).json({
      success: false,
      message: 'Error exporting threats'
    });
  }
};