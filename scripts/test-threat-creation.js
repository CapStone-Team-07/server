// test-threat-creation.js - Script to test threat creation
const mongoose = require('mongoose');
const dotenv = require('dotenv');

// Load environment variables
dotenv.config();

// Import the fixed Threat model
const Threat = require('../models/Threat');

// Connect to database
const connectDB = async () => {
  try {
    await mongoose.connect(process.env.MONGODB_URI, {
    //   useNewUrlParser: true,
    //   useUnifiedTopology: true,
    });
    console.log('MongoDB Connected for testing...');
  } catch (error) {
    console.error('Error connecting to MongoDB:', error);
    process.exit(1);
  }
};

// Test threat creation
const testThreatCreation = async () => {
  try {
    console.log('Testing threat creation...');
    
    const testThreat = new Threat({
      title: "Test Malware Detection",
      description: "Test suspicious malware activity detected",
      severity: "High",
      category: "Malware",
      sourceIP: "192.168.1.100",
      targetIP: "192.168.1.200",
      protocol: "TCP",
      port: 80,
      country: "Unknown",
      attackVector: "Email Attachment",
      source: "Endpoint Detection",
      riskScore: 85,
      confidence: 90,
      analyst: new mongoose.Types.ObjectId("686167082e881148d56db45c"), // Use the user ID from JWT
      analystName: "Test User"
    });
    
    console.log('Before save - threatId:', testThreat.threatId);
    
    const savedThreat = await testThreat.save();
    
    console.log('✅ Threat created successfully!');
    console.log('Generated threatId:', savedThreat.threatId);
    console.log('Threat details:', {
      id: savedThreat._id,
      threatId: savedThreat.threatId,
      title: savedThreat.title,
      severity: savedThreat.severity,
      status: savedThreat.status,
      analyst: savedThreat.analyst,
      analystName: savedThreat.analystName
    });
    
    // Clean up - remove the test threat
    await Threat.findByIdAndDelete(savedThreat._id);
    console.log('Test threat cleaned up');
    
  } catch (error) {
    console.error('❌ Error creating threat:', error);
    if (error.errors) {
      Object.keys(error.errors).forEach(key => {
        console.error(`Validation error for ${key}:`, error.errors[key].message);
      });
    }
  } finally {
    mongoose.connection.close();
    console.log('Database connection closed');
    process.exit(0);
  }
};

// Run the test
const main = async () => {
  await connectDB();
  await testThreatCreation();
};

main().catch(console.error);