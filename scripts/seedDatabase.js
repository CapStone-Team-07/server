// scripts/seedDatabase.js - Database Seeder
const mongoose = require('mongoose');
const dotenv = require('dotenv');
const User = require('../models/User');
const Threat = require('../models/Threat');
const Asset = require('../models/Asset');

// Load environment variables
dotenv.config();

// Connect to database
const connectDB = async () => {
  try {
    await mongoose.connect(process.env.MONGODB_URI, {
      useNewUrlParser: true,
      useUnifiedTopology: true,
    });
    console.log('MongoDB Connected for seeding...');
  } catch (error) {
    console.error('Error connecting to MongoDB:', error);
    process.exit(1);
  }
};

// Sample users data
const users = [
  {
    username: 'admin',
    email: 'admin@cybersec.com',
    password: 'admin123',
    firstName: 'System',
    lastName: 'Administrator',
    role: 'admin',
    isActive: true,
    isEmailVerified: true
  },
  {
    username: 'Hasah',
    email: 'hasan_hamidli@cybersec.com',
    password: 'password123',
    firstName: 'Hasan',
    lastName: 'Hamidli',
    role: 'soc_manager',
    isActive: true,
    isEmailVerified: true
  },
  {
    username: 'Gulyaz',
    email: 'gulyaz_ismayilzada@cybersec.com',
    password: 'password123',
    firstName: 'Gulyaz',
    lastName: 'Ismayilzada',
    role: 'senior_analyst',
    isActive: true,
    isEmailVerified: true
  },
  {
    username: 'Elvin',
    email: 'elvin_seidli@cybersec.com',
    password: 'password123',
    firstName: 'Elvin',
    lastName: 'Seidli',
    role: 'soc_analyst',
    isActive: true,
    isEmailVerified: true
  },
  {
    username: 'Arif',
    email: 'arif_mammadov@cybersec.com',
    password: 'password123',
    firstName: 'Arif',
    lastName: 'Mammadov',
    role: 'soc_analyst',
    isActive: true,
    isEmailVerified: true
  }
];

// Generate sample threats
const generateSampleThreats = (analysts) => {
  const severities = ['Critical', 'High', 'Medium', 'Low'];
  const categories = ['Malware', 'Phishing', 'Brute Force', 'Data Exfiltration', 'Insider Threat'];
  const statuses = ['Active', 'Investigating', 'Contained', 'Resolved'];
  const sources = ['Firewall', 'IDS/IPS', 'Endpoint Detection', 'Email Security', 'SIEM'];
  const countries = ['United States', 'China', 'Russia', 'Germany', 'United Kingdom'];

  const threats = [];
  for (let i = 0; i < 50; i++) {
    const analyst = analysts[Math.floor(Math.random() * analysts.length)];
    const severity = severities[Math.floor(Math.random() * severities.length)];
    const category = categories[Math.floor(Math.random() * categories.length)];
    const status = statuses[Math.floor(Math.random() * statuses.length)];
    const country = countries[Math.floor(Math.random() * countries.length)];
    
    const baseTime = Date.now() - (Math.random() * 7 * 24 * 60 * 60 * 1000);
    
    threats.push({
      threatId: `THREAT-${String(i + 1).padStart(4, '0')}`,
      title: `${category} Attack - ${country}`,
      description: `Suspicious ${category.toLowerCase()} activity detected from ${country}`,
      severity,
      category,
      status,
      source: sources[Math.floor(Math.random() * sources.length)],
      riskScore: Math.floor(Math.random() * 100) + 1,
      sourceIP: `${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`,
      targetIP: `192.168.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`,
      protocol: ['TCP', 'UDP', 'HTTP', 'HTTPS'][Math.floor(Math.random() * 4)],
      port: Math.floor(Math.random() * 65535) + 1,
      country,
      attackVector: `${category} Attack Vector`,
      mitreTactics: ['Initial Access', 'Execution', 'Persistence'][Math.floor(Math.random() * 3)],
      confidence: Math.floor(Math.random() * 40) + 60,
      affectedAssets: Math.floor(Math.random() * 20) + 1,
      firstSeen: new Date(baseTime),
      lastActivity: new Date(baseTime + Math.random() * 24 * 60 * 60 * 1000),
      analyst: analyst._id,
      analystName: `${analyst.firstName} ${analyst.lastName}`,
      iocs: {
        ipAddresses: [`${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`],
        domains: [`malicious${i}.com`],
        urls: [`http://malicious${i}.com/payload`]
      }
    });
  }
  return threats;
};

// Generate sample assets
const generateSampleAssets = () => {
  const types = ['Web Server', 'Database Server', 'Workstation', 'Router', 'Firewall'];
  const statuses = ['Online', 'Offline', 'Warning', 'Maintenance'];
  const locations = ['Data Center A', 'Data Center B', 'Office Floor 1', 'Office Floor 2'];
  const owners = ['IT Department', 'Finance', 'HR', 'Engineering', 'Sales'];

  const assets = [];
  for (let i = 0; i < 30; i++) {
    const type = types[Math.floor(Math.random() * types.length)];
    
    assets.push({
      assetId: `ASST-${String(i + 1).padStart(3, '0')}`, // validation error | commented regex match
      name: `${type.replace(' ', '-')}-${String(i + 1).padStart(3, '0')}`,
      type,
      ipAddress: `192.168.${Math.floor(Math.random() * 10) + 1}.${Math.floor(Math.random() * 254) + 1}`,
      macAddress: Array.from({ length: 6 }, () => Math.floor(Math.random() * 256).toString(16).padStart(2, '0')).join(':'),
      operatingSystem: ['Windows Server 2022', 'Ubuntu 22.04', 'CentOS 8', 'Windows 11'][Math.floor(Math.random() * 4)],
      location: locations[Math.floor(Math.random() * locations.length)],
      owner: owners[Math.floor(Math.random() * owners.length)],
      status: statuses[Math.floor(Math.random() * statuses.length)],
      criticality: ['Critical', 'High', 'Medium', 'Low'][Math.floor(Math.random() * 4)],
      securityScore: Math.floor(Math.random() * 30) + 70,
      complianceScore: Math.floor(Math.random() * 30) + 70,
      vulnerabilities: {
        critical: Math.floor(Math.random() * 3),
        high: Math.floor(Math.random() * 5),
        medium: Math.floor(Math.random() * 10),
        low: Math.floor(Math.random() * 15)
      },
      patchLevel: Math.floor(Math.random() * 30) + 70,
      lastSeen: new Date(Date.now() - Math.random() * 24 * 60 * 60 * 1000),
      tags: ['production', 'monitored']
    });
  }
  return assets;
};

// Seed function
const seedDatabase = async () => {
  try {
    console.log('🌱 Starting database seeding...');
    
    // Clear existing data
    console.log('🗑️  Clearing existing data...');
    await User.deleteMany({});
    await Threat.deleteMany({});
    await Asset.deleteMany({});
    
    // Create users
    console.log('👥 Creating users...');
    const createdUsers = await User.create(users);
    console.log(`✅ Created ${createdUsers.length} users`);
    
    // // Create threats
    console.log('🛡️  Creating threats...');
    const threats = generateSampleThreats(createdUsers);
    const createdThreats = await Threat.create(threats);
    console.log(`✅ Created ${createdThreats.length} threats`);
    
    // Create assets
    console.log('💻 Creating assets...');
    const assets = generateSampleAssets();
    const createdAssets = await Asset.create(assets);
    console.log(`✅ Created ${createdAssets.length} assets`);
    
    console.log('🎉 Database seeding completed successfully!');
    console.log('\n📋 Summary:');
    console.log(`Users: ${createdUsers.length}`);
    console.log(`Threats: ${createdThreats.length}`);
    console.log(`Assets: ${createdAssets.length}`);
    
    console.log('\n🔐 Default Login Credentials:');
    console.log('Email: admin@cybersec.com');
    console.log('Username: admin');
    console.log('Password: admin123');
    console.log('\n👥 Other Test Users:');
    createdUsers.forEach(user => {
      if (user.username !== 'admin') {
        console.log(`${user.fullName} (${user.role}): ${user.username} / password123`);
      }
    });
    
  } catch (error) {
    console.error('❌ Error seeding database:', error);
  } finally {
    mongoose.connection.close();
    console.log('\n🔌 Database connection closed');
    process.exit(0);
  }
};

// Clear database function
const clearDatabase = async () => {
  try {
    console.log('🗑️  Clearing database...');
    
    await User.deleteMany({});
    await Threat.deleteMany({});
    await Asset.deleteMany({});
    
    console.log('✅ Database cleared successfully!');
  } catch (error) {
    console.error('❌ Error clearing database:', error);
  } finally {
    mongoose.connection.close();
    process.exit(0);
  }
};

// Create admin user only
const createAdminUser = async () => {
  try {
    console.log('👑 Creating admin user...');
    
    // Check if admin already exists
    const existingAdmin = await User.findOne({ 
      $or: [
        { email: 'admin@cybersec.com' },
        { username: 'admin' }
      ]
    });
    
    if (existingAdmin) {
      console.log('⚠️  Admin user already exists!');
      console.log(`Email: ${existingAdmin.email}`);
      console.log(`Username: ${existingAdmin.username}`);
      return;
    }
    
    const adminUser = await User.create(users[0]); // First user is admin
    console.log('✅ Admin user created successfully!');
    console.log(`Email: ${adminUser.email}`);
    console.log(`Username: ${adminUser.username}`);
    console.log('Password: admin123');
    
  } catch (error) {
    console.error('❌ Error creating admin user:', error);
  } finally {
    mongoose.connection.close();
    process.exit(0);
  }
};

// Main execution
const main = async () => {
  await connectDB();
  
  const command = process.argv[2];
  
  switch (command) {
    case 'clear':
      await clearDatabase();
      break;
    case 'admin':
      await createAdminUser();
      break;
    case 'seed':
    default:
      await seedDatabase();
      break;
  }
};

// Handle uncaught exceptions
process.on('uncaughtException', (err) => {
  console.error('Uncaught Exception:', err.message);
  process.exit(1);
});

process.on('unhandledRejection', (err) => {
  console.error('Unhandled Rejection:', err.message);
  process.exit(1);
});

// Run the script
if (require.main === module) {
  main();
}

module.exports = {
  seedDatabase,
  clearDatabase,
  createAdminUser,
  connectDB
};