const express = require('express');
const router = express.Router();
const { containAgent } = require('../controllers/containmentController');

router.post('/:action', containAgent);

module.exports = router;