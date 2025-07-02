const express = require('express');
const { body } = require('express-validator');
const { sendTelegramMessage } = require('../controllers/telegramController');
const { protect, auditLog } = require('../middleware/authMiddleware');

const router = express.Router();

const telegramMessageValidation = [
  body('chat_id').notEmpty().withMessage('Chat ID is required'), 
  body('text').notEmpty().withMessage('Message is required')
];

router.get('/test', (req, res) => {
  res.json({ success: true, message: 'Telegram route is working!' });
});

router.post(
  '/sendTelegram',
  protect,
  telegramMessageValidation,
  auditLog('TELEGRAM_SEND'),
  sendTelegramMessage
);

module.exports = router;
