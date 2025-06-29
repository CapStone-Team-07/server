const express = require('express');
const { protect, requirePermission } = require('../middleware/authMiddleware');

const router = express.Router();

// Placeholder routes
router.get('/', protect, requirePermission('reports:read'), (req, res) => {
  res.json({ success: true, message: 'Report routes - Coming soon' });
});

module.exports = router;