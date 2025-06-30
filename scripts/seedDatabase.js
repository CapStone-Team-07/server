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
      // useNewUrlParser: true,
      // useUnifiedTopology: true,
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
    username: 'Hasan',
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
  },
  {
    username: 'Fidan',
    email: 'fidan_huseynova@cybersec.com',
    password: 'password123',
    firstName: 'Fidan',
    lastName: 'Huseynova',
    role: 'soc_analyst',
    isActive: true,
    isEmailVerified: true
  },
  {
    username: 'Altun',
    email: 'altun_tarverdiyev@cybersec.com',
    password: 'password123',
    firstName: 'Altun',
    lastName: 'Tarverdiyev',
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

// Generate sample assets with custom network topology
const generateSampleAssets = (users) => {
  const assets = [];
  const assetRegistry = {}; // Track created assets for connections
  let assetCounter = 1;

  // Helper function to create base asset
  const createBaseAsset = (overrides = {}) => {
    const deploymentDate = new Date(Date.now() - Math.random() * 365 * 2 * 24 * 60 * 60 * 1000);
    const lastSeenOffset = Math.random() * 7 * 24 * 60 * 60 * 1000;
    const lastSeen = new Date(Date.now() - lastSeenOffset);
    
    return {
      assetId: `AST-${String(assetCounter++).padStart(4, '0')}`,
      hostname: `${overrides.name?.toLowerCase() || 'asset'}.acc.local`,
      macAddress: Array.from({ length: 6 }, () => Math.floor(Math.random() * 256).toString(16).padStart(2, '0')).join(':'),
      location: 'IT-Room',
      department: 'IT',
      owner: 'IT Department',
      ownerContact: 'it@cybersec.com',
      status: 'online',
      lastSeen,
      uptime: Math.floor(Math.random() * 180) + 1,
      criticality: 'medium',
      securityScore: Math.floor(Math.random() * 40) + 60,
      complianceScore: Math.floor(Math.random() * 30) + 70,
      riskLevel: 'medium',
      tags: ['production', 'monitored', 'acc.local'],
      businessFunction: 'IT Operations',
      dataClassification: 'internal',
      discoveryMethod: 'network_scan',
      discoveredBy: users[users.length - 1]._id,
      lastUpdatedBy: users[users.length - 1]._id,
      vulnerabilities: {
        total: Math.floor(Math.random() * 10),
        critical: Math.floor(Math.random() * 2),
        high: Math.floor(Math.random() * 3),
        medium: Math.floor(Math.random() * 4),
        low: Math.floor(Math.random() * 5)
      },
      lastVulnScan: new Date(Date.now() - Math.random() * 30 * 24 * 60 * 60 * 1000),
      nextVulnScan: new Date(Date.now() + Math.random() * 7 * 24 * 60 * 60 * 1000),
      patchLevel: Math.floor(Math.random() * 30) + 70,
      lastPatchDate: new Date(Date.now() - Math.random() * 30 * 24 * 60 * 60 * 1000),
      pendingPatches: Math.floor(Math.random() * 10),
      lifecycle: {
        acquisitionDate: new Date(deploymentDate.getTime() - 30 * 24 * 60 * 60 * 1000),
        deploymentDate,
        lastMaintenanceDate: new Date(Date.now() - Math.random() * 90 * 24 * 60 * 60 * 1000),
        nextMaintenanceDate: new Date(Date.now() + Math.random() * 90 * 24 * 60 * 60 * 1000),
        endOfLifeDate: new Date(Date.now() + Math.random() * 365 * 5 * 24 * 60 * 60 * 1000),
      },
      financial: {
        acquisitionCost: Math.floor(Math.random() * 10000) + 1000,
        currentValue: Math.floor(Math.random() * 8000) + 500,
        maintenanceCost: Math.floor(Math.random() * 1000) + 100,
        currency: 'USD'
      },
      securityControls: {
        antivirus: {
          installed: false,
          product: 'CyberSec Antivirus Pro',
          version: '12.5.1',
          lastUpdate: new Date(Date.now() - Math.random() * 7 * 24 * 60 * 60 * 1000),
          status: 'active'
        },
        backups: {
          enabled: false,
          frequency: 'Daily',
          lastBackup: new Date(Date.now() - Math.random() * 24 * 60 * 60 * 1000),
          retention: '30 days'
        },
        monitoring: {
          enabled: true,
          agent: 'CyberSec Agent',
          version: '2.1.5'
        }
      },
      compliance: {
        frameworks: [
          {
            name: 'ISO 27001',
            status: Math.random() > 0.2 ? 'compliant' : 'partial',
            lastAssessment: new Date(Date.now() - Math.random() * 90 * 24 * 60 * 60 * 1000),
            score: Math.floor(Math.random() * 30) + 70
          }
        ],
        policies: [
          {
            name: 'Password Policy',
            status: Math.random() > 0.1 ? 'compliant' : 'non_compliant',
            lastCheck: new Date(Date.now() - Math.random() * 7 * 24 * 60 * 60 * 1000)
          }
        ]
      },
      monitoring: {
        enabled: true,
        intervals: {
          heartbeat: 30,
          performance: 300,
          vulnerability: 86400
        },
        thresholds: {
          cpu: 80,
          memory: 85,
          storage: 90,
          network: 75
        }
      },
      alerts: {
        enabled: true,
        notifications: [
          {
            type: 'email',
            endpoint: 'it@cybersec.com',
            enabled: true
          }
        ]
      },
      ...overrides
    };
  };

  // 1. Main Firewall (gateway to internet) - positioned at top center
  const firewallAsset = createBaseAsset({
    name: 'Main-Firewall',
    type: 'firewall',
    ipAddress: '192.168.1.1',
    position: { x: 400, y: 120 },
    criticality: 'critical',
    riskLevel: 'high',
    connections: [], // Will be populated after switch creation
    operatingSystem: 'Cisco ASA OS',
    osVersion: '9.12(4)',
    metadata: {
      cpu: 25,
      memory: 45,
      networkLoad: 30,
      throughput: '150 Mbps',
      rules: 245,
      manufacturer: 'Cisco',
      model: 'ASA 5515-X',
      firmware: '9.12(4)',
      serialNumber: `SN${Math.random().toString(36).substring(2, 12).toUpperCase()}`,
      version: 'v9.12',
      bandwidth: '1 Gbps'
    },
    services: [
      { name: 'SNMP', port: 161, protocol: 'UDP', status: 'running' },
      { name: 'Management', port: 8443, protocol: 'TCP', status: 'running' },
      { name: 'SSH', port: 22, protocol: 'TCP', status: 'running' }
    ],
    dependencies: [], // Will be populated later
    notes: 'Main firewall providing network security and internet gateway access'
  });
  assets.push(firewallAsset);
  assetRegistry['Main-Firewall'] = firewallAsset;

  // 2. Core Switch (connects all PCs) - positioned below firewall
  const switchAsset = createBaseAsset({
    name: 'Core-Switch',
    type: 'switch',
    ipAddress: '192.168.1.2',
    position: { x: 400, y: 250 },
    criticality: 'high',
    riskLevel: 'medium',
    connections: [], // Will be populated after all assets are created
    operatingSystem: 'Cisco IOS',
    osVersion: '15.2(7)E',
    metadata: {
      cpu: 15,
      memory: 32,
      networkLoad: 45,
      connectedDevices: 7,
      bandwidth: '1 Gbps',
      manufacturer: 'Cisco',
      model: 'Catalyst 2960-X',
      ports: 48,
      activeports: 7,
      serialNumber: `SN${Math.random().toString(36).substring(2, 12).toUpperCase()}`,
      firmware: '15.2(7)E',
      version: 'v15.2'
    },
    services: [
      { name: 'SNMP', port: 161, protocol: 'UDP', status: 'running' },
      { name: 'SSH', port: 22, protocol: 'TCP', status: 'running' },
      { name: 'Telnet', port: 23, protocol: 'TCP', status: 'disabled' }
    ],
    dependencies: [], // Will be populated later
    notes: 'Core network switch connecting all workstations'
  });
  assets.push(switchAsset);
  assetRegistry['Core-Switch'] = switchAsset;

  // 3. Specific workstations with exact names and IPs from your configuration
  const pcConfigs = [
    { name: 'AKMPC007', x: 150, y: 380, ip: '192.168.80.244' },
    { name: 'AKMPC105', x: 280, y: 450, ip: '192.168.80.36' },
    { name: 'AKMPC085', x: 400, y: 480, ip: '192.168.80.121' },
    { name: 'AKMPC047', x: 520, y: 450, ip: '192.168.80.40' },
    { name: 'CL101', x: 650, y: 380, ip: '192.168.80.220' },
    { name: 'AKMPC049', x: 580, y: 300, ip: '192.168.80.248' },
    { name: 'AKMPC048', x: 220, y: 300, ip: '192.168.80.222' }
  ];

  pcConfigs.forEach((pc, index) => {
    const osChoices = ['Windows 11', 'Windows 10', 'Windows Server 2019'];
    const selectedOS = osChoices[index % 3];
    
    const workstationAsset = createBaseAsset({
      name: pc.name,
      type: 'workstation',
      ipAddress: pc.ip,
      position: { x: pc.x, y: pc.y },
      criticality: 'low',
      riskLevel: 'low',
      location: 'Office-Floor1',
      connections: [], // Will be populated after all assets are created
      operatingSystem: selectedOS,
      osVersion: selectedOS === 'Windows 11' ? '22H2' : selectedOS === 'Windows 10' ? '22H2' : '2019',
      metadata: {
        cpu: Math.floor(Math.random() * 80) + 10,
        memory: Math.floor(Math.random() * 70) + 20,
        storage: Math.floor(Math.random() * 60) + 30,
        networkLoad: Math.floor(Math.random() * 30) + 5,
        user: 'User',
        manufacturer: index % 2 === 0 ? 'Dell' : 'HP',
        model: index % 2 === 0 ? `OptiPlex-${7000 + index}` : `EliteDesk-${800 + index}`,
        serialNumber: `SN${Math.random().toString(36).substring(2, 12).toUpperCase()}`,
        domain: 'ACC.LOCAL',
        lastLogin: new Date(Date.now() - Math.random() * 86400000).toLocaleString(),
        throughput: `${Math.floor(Math.random() * 90) + 10} Mbps`,
        bandwidth: '100 Mbps'
      },
      services: [
        { name: 'RDP', port: 3389, protocol: 'TCP', status: 'running' },
        { name: 'SMB', port: 445, protocol: 'TCP', status: 'running' }
      ],
      software: [
        {
          name: 'Microsoft Office',
          version: '2021',
          vendor: 'Microsoft',
          licenseType: 'Commercial',
          installDate: new Date(Date.now() - Math.random() * 365 * 24 * 60 * 60 * 1000),
          lastUpdate: new Date(Date.now() - Math.random() * 30 * 24 * 60 * 60 * 1000)
        },
        {
          name: 'Windows Defender',
          version: '4.18.2209.7',
          vendor: 'Microsoft',
          licenseType: 'Built-in',
          installDate: new Date(Date.now() - Math.random() * 365 * 24 * 60 * 60 * 1000),
          lastUpdate: new Date(Date.now() - Math.random() * 7 * 24 * 60 * 60 * 1000)
        }
      ],
      securityControls: {
        antivirus: {
          installed: true,
          product: 'Windows Defender',
          version: '4.18.2209.7',
          lastUpdate: new Date(Date.now() - Math.random() * 7 * 24 * 60 * 60 * 1000),
          status: 'active'
        },
        backups: {
          enabled: true,
          frequency: 'Weekly',
          lastBackup: new Date(Date.now() - Math.random() * 7 * 24 * 60 * 60 * 1000),
          retention: '30 days'
        },
        monitoring: {
          enabled: true,
          agent: 'CyberSec Agent',
          version: '2.1.5'
        }
      },
      dependencies: [], // Will be populated later
      notes: `Workstation ${pc.name} deployed in Office-Floor1. Domain: ACC.LOCAL`
    });
    
    assets.push(workstationAsset);
    assetRegistry[pc.name] = workstationAsset;
  });

  // Add some additional infrastructure assets to make the network more realistic
  const additionalAssets = [
    // File Server
    {
      name: 'FILE-SERVER-001',
      type: 'server',
      ipAddress: '192.168.1.100',
      position: { x: 200, y: 120 },
      criticality: 'high',
      location: 'IT-Room',
      operatingSystem: 'Windows Server 2019',
      metadata: {
        cpu: 45,
        memory: 65,
        storage: 85,
        user: 'File Server',
        manufacturer: 'Dell',
        model: 'PowerEdge-R740'
      },
      connections: []
    },
    // Domain Controller
    {
      name: 'DC-001',
      type: 'server',
      ipAddress: '192.168.1.101',
      position: { x: 600, y: 120 },
      criticality: 'critical',
      location: 'IT-Room',
      operatingSystem: 'Windows Server 2019',
      metadata: {
        cpu: 35,
        memory: 55,
        storage: 40,
        user: 'Domain Controller',
        manufacturer: 'HP',
        model: 'ProLiant-DL380'
      },
      connections: []
    },
    // Printer
    {
      name: 'PRINTER-001',
      type: 'printer',
      ipAddress: '192.168.80.100',
      position: { x: 400, y: 380 },
      criticality: 'low',
      location: 'Office-Floor1',
      operatingSystem: 'Embedded Linux',
      metadata: {
        manufacturer: 'HP',
        model: 'LaserJet-Pro-4001n',
        connectedDevices: 7
      },
      connections: []
    }
  ];

  additionalAssets.forEach(asset => {
    const additionalAsset = createBaseAsset(asset);
    assets.push(additionalAsset);
    assetRegistry[asset.name] = additionalAsset;
  });

  // Now establish all connections using asset IDs (not names)
  // Firewall connects to switch
  firewallAsset.connections = [switchAsset.assetId];
  firewallAsset.dependencies = [];

  // Switch connects to all workstations and servers
  switchAsset.connections = [
    firewallAsset.assetId,
    ...pcConfigs.map(pc => assetRegistry[pc.name].assetId),
    assetRegistry['FILE-SERVER-001'].assetId,
    assetRegistry['DC-001'].assetId,
    assetRegistry['PRINTER-001'].assetId
  ];
  switchAsset.dependencies = [
    {
      assetId: firewallAsset.assetId,
      relationship: 'connected_to',
      description: 'Network connection through firewall'
    }
  ];

  // All workstations connect to switch and depend on firewall
  pcConfigs.forEach(pc => {
    const workstation = assetRegistry[pc.name];
    workstation.connections = [switchAsset.assetId];
    workstation.dependencies = [
      {
        assetId: switchAsset.assetId,
        relationship: 'connected_to',
        description: 'Network access'
      },
      {
        assetId: firewallAsset.assetId,
        relationship: 'depends_on',
        description: 'Security protection'
      }
    ];
  });

  // Servers connect to switch and depend on firewall
  ['FILE-SERVER-001', 'DC-001', 'PRINTER-001'].forEach(serverName => {
    const server = assetRegistry[serverName];
    server.connections = [switchAsset.assetId];
    server.dependencies = [
      {
        assetId: switchAsset.assetId,
        relationship: 'connected_to',
        description: 'Network access'
      },
      {
        assetId: firewallAsset.assetId,
        relationship: 'depends_on',
        description: 'Security protection'
      }
    ];
  });

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
    
    // Create threats
    console.log('🛡️  Creating threats...');
    const threats = generateSampleThreats(createdUsers);
    const createdThreats = await Threat.create(threats);
    console.log(`✅ Created ${createdThreats.length} threats`);
    
    // Create assets
    console.log('💻 Creating assets...');
    const assets = generateSampleAssets(createdUsers);
    const createdAssets = await Asset.create(assets);
    console.log(`✅ Created ${createdAssets.length} assets`);
    
    console.log('🎉 Database seeding completed successfully!');
    console.log('\n📋 Summary:');
    console.log(`Users: ${createdUsers.length}`);
    console.log(`Threats: ${createdThreats.length}`);
    console.log(`Assets: ${createdAssets.length}`);
    
    // Show asset breakdown by type
    const assetsByType = {};
    createdAssets.forEach(asset => {
      assetsByType[asset.type] = (assetsByType[asset.type] || 0) + 1;
    });
    
    console.log('\n💻 Assets by Type:');
    Object.entries(assetsByType).forEach(([type, count]) => {
      console.log(`  ${type}: ${count}`);
    });
    
    console.log('\n🖥️  Workstation Assets:');
    createdAssets.filter(asset => asset.type === 'workstation').forEach(asset => {
      console.log(`  ${asset.name}: ${asset.ipAddress} (${asset.operatingSystem})`);
    });
    
    console.log('\n🔐 Default Login Credentials:');
    console.log('Email: admin@cybersec.com');
    console.log('Username: admin');
    console.log('Password: admin123');
    
    console.log('\n👥 Other Test Users:');
    createdUsers.forEach(user => {
      if (user.username !== 'admin') {
        console.log(`${user.firstName} ${user.lastName} (${user.role}): ${user.username} / password123`);
      }
    });
    
  } catch (error) {
    console.error('❌ Error seeding database:', error.message);
    if (error.code === 11000) {
      console.error('💡 Duplicate key error detected. This usually means:');
      console.error('   - The database was not properly cleared');
      console.error('   - There are existing assets with conflicting IDs');
      console.error('   - Try running: npm run seed clear && npm run seed');
    }
    if (error.errors) {
      console.error('📋 Validation errors:');
      Object.keys(error.errors).forEach(field => {
        console.error(`   - ${field}: ${error.errors[field].message}`);
      });
    }
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

// Create sample network topology
const createNetworkTopology = async () => {
  try {
    console.log('🌐 Creating network topology...');
    
    // Clear existing assets
    await Asset.deleteMany({});
    
    // Create custom network topology using the new function
    const users = await User.find({});
    if (users.length === 0) {
      console.log('⚠️  No users found. Creating admin user first...');
      const adminUser = await User.create(users[0]);
      users.push(adminUser);
    }
    
    const assets = generateSampleAssets(users);
    const createdAssets = await Asset.create(assets);
    
    console.log(`✅ Created ${createdAssets.length} network topology assets`);
    console.log('\n🌐 Network Topology Summary:');
    console.log('  1 x Main Firewall (192.168.1.1)');
    console.log('  1 x Core Switch (192.168.1.2)');
    console.log('  7 x Workstations (AKMPC007, AKMPC105, AKMPC085, AKMPC047, CL101, AKMPC049, AKMPC048)');
    console.log('  2 x Servers (File Server, Domain Controller)');
    console.log('  1 x Printer');
    
  } catch (error) {
    console.error('❌ Error creating network topology:', error);
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
    case 'topology':
      await createNetworkTopology();
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
  createNetworkTopology,
  connectDB
};