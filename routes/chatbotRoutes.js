const express = require('express');
const ChatbotController = require('../controllers/ChatbotController');
const { protect } = require('../middleware/authMiddleware'); // assuming 'protect' is the actual middleware function

const router = express.Router();
const chatbotController = new ChatbotController();

// Main chat endpoint
router.post('/chat', 
  protect, 
  chatbotController.chat.bind(chatbotController)
);

// Alert analysis endpoint
router.post('/analyze-alerts', 
  protect,
  chatbotController.analyzeAlerts.bind(chatbotController)
);

// Clear chat history
router.delete('/history/:sessionId', 
  protect,
  chatbotController.clearHistory.bind(chatbotController)
);

module.exports = router;