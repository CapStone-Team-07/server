import { NextResponse } from 'next/server';
import { headers } from 'next/headers';
import jwt from 'jsonwebtoken'; // Assuming you use JWT for auth
import CybersecurityChatbot from '../../../../services/chatbotService'; // Adjust path to your service

// This is a simplified replacement for your 'protect' middleware.
// In a real app, you might move this to a dedicated utility function.
const verifyAuth = (requestHeaders) => {
  const authHeader = requestHeaders.get('authorization');
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    throw new Error('Not authorized, no token');
  }
  try {
    const token = authHeader.split(' ')[1];
    // Replace 'YOUR_JWT_SECRET' with your actual secret key
    const decoded = jwt.verify(token, process.env.JWT_SECRET); 
    // You can return the user info if needed
    return decoded; 
  } catch (error) {
    throw new Error('Not authorized, token failed');
  }
};

// Instantiate your chatbot service
const chatbot = new CybersecurityChatbot();

// Export a named function for the HTTP method (POST)
export async function POST(request) {
  try {
    // 1. Protect the route by verifying the token
    const requestHeaders = headers();
    const user = verifyAuth(requestHeaders); // This will throw an error if auth fails

    // 2. Get the request body
    const { message, sessionId } = await request.json();
    
    if (!message || !sessionId) {
      return NextResponse.json({
        success: false,
        error: 'Message and sessionId are required'
      }, { status: 400 });
    }
    
    // 3. Build context (assuming buildSystemContext is a standalone function or part of the service)
    // For this example, we'll create a simplified context. You should adapt this.
    const context = {
      userRole: user?.role || 'user',
      // ... add other context data as needed
    };
    
    // 4. Call your chatbot service logic
    const response = await chatbot.chat(sessionId, message, context);
    
    // 5. Return a successful response using NextResponse
    return NextResponse.json({
      success: true,
      data: response
    }, { status: 200 });

  } catch (error) {
    console.error('Chat API handler error:', error.message);
    
    // Handle specific auth errors
    if (error.message.includes('Not authorized')) {
       return NextResponse.json({ success: false, error: 'Authorization failed' }, { status: 401 });
    }
    
    // Handle other server errors
    return NextResponse.json({
      success: false,
      error: 'Internal server error',
      message: error.message
    }, { status: 500 });
  }
}