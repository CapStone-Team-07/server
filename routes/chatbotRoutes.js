const express = require('express');
const ChatbotController = require('../controllers/chatbotController'); // Adjust the path as necessary
// const { protect } = require('../middleware/authMiddleware'); // assuming 'protect' is the actual middleware function

const router = express.Router();
const chatbotController = new ChatbotController();

// Main chat endpoint
router.post('/chat',  
  chatbotController.chat.bind(chatbotController)
);

// Alert analysis endpoint
router.post('/analyze-alerts', 
  chatbotController.analyzeAlerts.bind(chatbotController)
);

// Clear chat history
router.delete('/history/:sessionId', 
  chatbotController.clearHistory.bind(chatbotController)
);

module.exports = router;