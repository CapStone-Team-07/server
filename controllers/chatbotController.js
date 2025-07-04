const CybersecurityChatbot = require('../services/chatbotService');

class ChatbotController {
  constructor() {
    this.chatbot = new CybersecurityChatbot();
    this.setupEventListeners();
  }

  setupEventListeners() {
    this.chatbot.on('chatResponse', this.logChatActivity.bind(this));
    this.chatbot.on('chatError', this.handleChatError.bind(this));
  }

  async chat(req, res) {
    try {
      const { message, sessionId } = req.body;
      
      if (!message || !sessionId) {
        return res.status(400).json({
          success: false,
          error: 'Message and sessionId are required'
        });
      }

      // Build context from your existing services
      const context = await this.buildSystemContext(req.user);
      
      const response = await this.chatbot.chat(sessionId, message, context);
      
      res.json({
        success: true,
        data: response
      });

    } catch (error) {
      console.error('Chat handler error:', error);
      res.status(500).json({
        success: false,
        error: 'Internal server error',
        message: error.message
      });
    }
  }

  async analyzeAlerts(req, res) {
    try {
      const { alertIds, query } = req.body;
      
      // This would integrate with your existing alert system
      // You can use your existing threatController or assetController
      const alerts = await this.getAlertsByIds(alertIds);
      
      const analysisPrompt = `${query || 'Analyze these security alerts for threats and patterns'}\n\nAlerts:\n${
        alerts.map(alert => 
          `[${alert.timestamp}] Level ${alert.rule?.level}: ${alert.rule?.description} - ${alert.location}`
        ).join('\n')
      }`;

      const completion = await this.chatbot.openai.chat.completions.create({
        model: 'gpt-4',
        messages: [
          { role: 'system', content: this.chatbot.systemPrompt },
          { role: 'user', content: analysisPrompt }
        ],
        max_tokens: 1500,
        temperature: 0.2
      });

      res.json({
        success: true,
        data: {
          analysis: completion.choices[0].message.content,
          alertsAnalyzed: alerts.length,
          timestamp: new Date()
        }
      });

    } catch (error) {
      console.error('Alert analysis error:', error);
      res.status(500).json({
        success: false,
        error: 'Failed to analyze alerts'
      });
    }
  }

  async buildSystemContext(user) {
    try {
      // You can integrate with your existing services here
      // For example, using your threatController or assetController
      
      const context = {
        systemStats: {
          total_agents: 0, // Get from your existing service
          active_alerts: 0, // Get from your existing service
        },
        recentAlerts: [], // Get from your existing alert service
        userRole: user?.role || 'user'
      };

      return context;
    } catch (error) {
      console.error('Context building error:', error);
      return {};
    }
  }

  async getAlertsByIds(alertIds) {
    // Implement this to work with your existing alert system
    // This should integrate with your threat or alert models
    return [];
  }

  clearHistory(req, res) {
    try {
      const { sessionId } = req.params;
      this.chatbot.clearHistory(sessionId);
      
      res.json({
        success: true,
        message: 'Chat history cleared'
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        error: 'Failed to clear history'
      });
    }
  }

  logChatActivity(data) {
    console.log('Chat activity:', {
      sessionId: data.sessionId,
      timestamp: data.timestamp,
      tokensUsed: data.tokens_used
    });
  }

  handleChatError(data) {
    console.error('Chat error for session:', data.sessionId, data.error);
  }
}

module.exports = ChatbotController;