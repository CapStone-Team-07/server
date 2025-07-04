const OpenAI = require('openai');
const EventEmitter = require('events');

class CybersecurityChatbot extends EventEmitter {
  constructor(config = {}) {
    super();
    this.openai = new OpenAI({
      apiKey: process.env.OPENAI_API_KEY
    });
    
    this.conversationHistory = new Map();
    this.maxHistoryLength = config.maxHistoryLength || 20;
    this.systemPrompt = this.buildSystemPrompt();
  }

  buildSystemPrompt() {
    return `You are a cybersecurity AI assistant for a Wazuh-based security monitoring platform.
    
Your capabilities include:
- Analyzing security logs and incidents from Wazuh agents
- Providing threat intelligence insights
- Explaining security alerts and their severity levels
- Recommending incident response actions
- Helping with security best practices and compliance
- Interpreting Wazuh rules and configurations
- Assisting with vulnerability assessments
- Threat hunting guidance

When users ask about security incidents, provide clear analysis and actionable recommendations.
For log analysis, help interpret patterns and anomalies.
Always prioritize security and provide accurate, professional guidance.

Current context: Integrated with a Node.js backend monitoring Wazuh security events.`;
  }

  async chat(sessionId, message, context = {}) {
    try {
      if (!this.conversationHistory.has(sessionId)) {
        this.conversationHistory.set(sessionId, []);
      }
      
      const history = this.conversationHistory.get(sessionId);
      history.push({ role: 'user', content: message });
      
      const contextualMessage = this.buildContextualMessage(message, context);
      
      const messages = [
        { role: 'system', content: this.systemPrompt },
        ...history.slice(-this.maxHistoryLength)
      ];

      if (contextualMessage !== message) {
        messages.push({ role: 'user', content: contextualMessage });
      }

      const completion = await this.openai.chat.completions.create({
        model: 'gpt-4',
        messages: messages,
        max_tokens: 1000,
        temperature: 0.3,
        presence_penalty: 0.1
      });

      const aiResponse = completion.choices[0].message.content;
      history.push({ role: 'assistant', content: aiResponse });
      
      this.emit('chatResponse', {
        sessionId,
        userMessage: message,
        aiResponse,
        context,
        timestamp: new Date()
      });

      return {
        response: aiResponse,
        sessionId,
        timestamp: new Date(),
        tokens_used: completion.usage?.total_tokens || 0
      };

    } catch (error) {
      console.error('Chatbot error:', error);
      this.emit('chatError', { sessionId, error: error.message });
      throw new Error('Failed to generate response');
    }
  }

  buildContextualMessage(message, context) {
    if (!context || Object.keys(context).length === 0) {
      return message;
    }

    let contextualInfo = '\n\nCurrent system context:\n';
    
    if (context.recentAlerts) {
      contextualInfo += `Recent alerts: ${context.recentAlerts.slice(0, 5).map(alert => 
        `[Level ${alert.rule?.level}] ${alert.rule?.description}`
      ).join(', ')}\n`;
    }
    
    if (context.systemStats) {
      contextualInfo += `System: ${context.systemStats.total_agents} agents, ${context.systemStats.active_alerts} active alerts\n`;
    }

    return message + contextualInfo;
  }

  clearHistory(sessionId) {
    this.conversationHistory.delete(sessionId);
  }

  getHistory(sessionId) {
    return this.conversationHistory.get(sessionId) || [];
  }
}

module.exports = CybersecurityChatbot;