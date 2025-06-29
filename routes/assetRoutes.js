const express = require('express');
const { protect, requirePermission } = require('../middleware/authMiddleware');

const router = express.Router();

// Placeholder routes
router.get('/', protect, requirePermission('assets:read'), (req, res) => {
  res.json({ success: true, message: 'Asset routes - Coming soon' });
});

module.exports = router;