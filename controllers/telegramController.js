const { validationResult } = require("express-validator");
const axios = require("axios");

// Your bot token from BotFather
const TELEGRAM_BOT_TOKEN = "7450160783:AAHmgSRlPQR_CxEUz8grqlZXSNLpVrxCHTA";

exports.sendTelegramMessage = async (req, res) => {
  try {
    console.log("📬 Received request to send Telegram message");
    console.log("Testing -- salam");
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        success: false,
        message: "Validation failed",
        errors: errors.array(),
      });
    }

    const { chat_id, text } = req.body;

    if (!chat_id || !text) {
      return res.status(400).json({
        success: false,
        message: "Missing required fields: 'chat_id' and 'text'.",
      });
    }

    const telegramApiUrl = `https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage`;

    // Send message via Telegram Bot API using axios
    const response = await axios.post(telegramApiUrl, {
      chat_id,
      text,
      parse_mode: "HTML" // optional, allows you to send formatted text
    });

    if (!response.data.ok) {
      throw new Error("Telegram API responded with an error");
    }

    console.log(`✅ Telegram message sent to chat_id ${chat_id}`);

    res.status(200).json({
      success: true,
      message: "Telegram message sent successfully",
      result: response.data.result,
    });
  } catch (error) {
    console.error("❌ Send Telegram message error:", error.message);
    res.status(500).json({
      success: false,
      message: "Failed to send Telegram message",
      error: error.message,
    });
  }
};