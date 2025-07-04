const express = require('express');
const router = express.Router();
const { containAgent, restoreAgent, containAgentStatus } = require('../controllers/containmentController');

router.post('/isolate', containAgent);
router.post('/restore', restoreAgent);
router.post('/status', containAgentStatus);

module.exports = router;