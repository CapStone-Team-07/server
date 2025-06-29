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

// Generate sample assets with new schema
const generateSampleAssets = (users) => {
  const types = ['firewall', 'switch', 'router', 'workstation', 'server', 'mobile_device', 'printer', 'access_point', 'iot_device'];
  const statuses = ['online', 'offline', 'warning', 'maintenance'];
  const locations = ['Data Center A', 'Data Center B', 'Office Floor 1', 'Office Floor 2', 'Remote Office', 'Cloud - AWS', 'Cloud - Azure'];
  const departments = ['IT', 'Finance', 'HR', 'Engineering', 'Sales', 'Marketing', 'Operations'];
  const owners = ['IT Department', 'Network Team', 'Security Team', 'DevOps Team'];
  const operatingSystems = ['Windows Server 2022', 'Ubuntu 22.04', 'CentOS 8', 'Windows 11', 'macOS Ventura', 'Cisco IOS', 'pfSense'];
  const manufacturers = ['Cisco', 'HP', 'Dell', 'Juniper', 'Fortinet', 'Palo Alto', 'VMware', 'Microsoft'];
  const criticalities = ['critical', 'high', 'medium', 'low'];
  const dataClassifications = ['public', 'internal', 'confidential', 'restricted'];

  const assets = [];
  const createdAssets = []; // To track created assets for connections

  for (let i = 0; i < 40; i++) {
    const type = types[Math.floor(Math.random() * types.length)];
    const status = statuses[Math.floor(Math.random() * statuses.length)];
    const criticality = criticalities[Math.floor(Math.random() * criticalities.length)];
    const location = locations[Math.floor(Math.random() * locations.length)];
    const department = departments[Math.floor(Math.random() * departments.length)];
    const manufacturer = manufacturers[Math.floor(Math.random() * manufacturers.length)];
    const os = operatingSystems[Math.floor(Math.random() * operatingSystems.length)];
    
    // Generate realistic IP addresses based on location
    let ipPrefix = '192.168.1';
    if (location.includes('Data Center A')) ipPrefix = '10.1.0';
    else if (location.includes('Data Center B')) ipPrefix = '10.2.0';
    else if (location.includes('Cloud')) ipPrefix = '172.16.0';
    
    const deploymentDate = new Date(Date.now() - Math.random() * 365 * 2 * 24 * 60 * 60 * 1000); // Up to 2 years ago
    const lastSeenOffset = Math.random() * 7 * 24 * 60 * 60 * 1000; // Up to 7 days ago
    const lastSeen = new Date(Date.now() - lastSeenOffset);
    
    const asset = {
      // Pre-generate asset ID to avoid conflicts in bulk insert
      assetId: `AST-${String(i + 1).padStart(4, '0')}`,
      name: `${type.toUpperCase()}-${String(i + 1).padStart(3, '0')}`,
      type,
      ipAddress: `${ipPrefix}.${Math.floor(Math.random() * 254) + 1}`,
      macAddress: Array.from({ length: 6 }, () => Math.floor(Math.random() * 256).toString(16).padStart(2, '0')).join(':'),
      hostname: `${type}${String(i + 1).padStart(3, '0')}.cybersec.local`,
      
      // Position for network topology (spread assets in a grid)
      position: {
        x: (i % 8) * 150 + Math.random() * 50,
        y: Math.floor(i / 8) * 120 + Math.random() * 40
      },
      
      operatingSystem: os,
      osVersion: `${os.split(' ')[0]} ${Math.floor(Math.random() * 10) + 1}.${Math.floor(Math.random() * 10)}`,
      
      location,
      department,
      owner: owners[Math.floor(Math.random() * owners.length)],
      ownerContact: `${department.toLowerCase()}@cybersec.com`,
      
      status,
      lastSeen,
      uptime: status === 'online' ? Math.floor(Math.random() * 365) : 0,
      
      criticality,
      securityScore: Math.floor(Math.random() * 40) + 60,
      complianceScore: Math.floor(Math.random() * 30) + 70,
      riskLevel: criticality === 'critical' ? 'high' : criticality === 'high' ? 'medium' : 'low',
      
      // Performance metrics
      metadata: {
        cpu: status === 'online' ? Math.floor(Math.random() * 80) + 10 : 0,
        memory: status === 'online' ? Math.floor(Math.random() * 70) + 20 : 0,
        storage: Math.floor(Math.random() * 60) + 30,
        networkLoad: status === 'online' ? Math.floor(Math.random() * 50) + 10 : 0,
        throughput: type.includes('server') ? `${Math.floor(Math.random() * 900) + 100} Mbps` : `${Math.floor(Math.random() * 90) + 10} Mbps`,
        bandwidth: type === 'server' ? '1 Gbps' : type === 'switch' ? '10 Gbps' : '100 Mbps',
        connectedDevices: type === 'switch' ? Math.floor(Math.random() * 24) + 4 : type === 'access_point' ? Math.floor(Math.random() * 50) + 5 : 0,
        activeports: type === 'switch' ? Math.floor(Math.random() * 48) + 8 : 0,
        manufacturer,
        model: `${manufacturer}-${type.toUpperCase()}-${Math.floor(Math.random() * 9000) + 1000}`,
        serialNumber: `SN${Math.random().toString(36).substring(2, 12).toUpperCase()}`,
        firmware: `${Math.floor(Math.random() * 5) + 1}.${Math.floor(Math.random() * 10)}.${Math.floor(Math.random() * 100)}`,
        version: `v${Math.floor(Math.random() * 3) + 1}.${Math.floor(Math.random() * 10)}`,
        rules: type === 'firewall' ? Math.floor(Math.random() * 500) + 50 : 0,
        ports: type === 'switch' ? Math.floor(Math.random() * 24) + 24 : 0,
        user: type === 'workstation' ? `user${Math.floor(Math.random() * 100) + 1}` : null,
        domain: type === 'workstation' ? 'CYBERSEC' : null,
        lastLogin: type === 'workstation' ? new Date(Date.now() - Math.random() * 24 * 60 * 60 * 1000).toISOString() : null,
        warrantyExpiry: new Date(Date.now() + Math.random() * 365 * 3 * 24 * 60 * 60 * 1000), // Up to 3 years
        lastMaintenanceDate: new Date(Date.now() - Math.random() * 90 * 24 * 60 * 60 * 1000), // Last 90 days
        nextMaintenanceDate: new Date(Date.now() + Math.random() * 90 * 24 * 60 * 60 * 1000) // Next 90 days
      },
      
      vulnerabilities: {
        total: (() => {
          const critical = Math.floor(Math.random() * 3);
          const high = Math.floor(Math.random() * 5);
          const medium = Math.floor(Math.random() * 8);
          const low = Math.floor(Math.random() * 10);
          return critical + high + medium + low;
        })(),
        critical: Math.floor(Math.random() * 3),
        high: Math.floor(Math.random() * 5),
        medium: Math.floor(Math.random() * 8),
        low: Math.floor(Math.random() * 10)
      },
      lastVulnScan: new Date(Date.now() - Math.random() * 30 * 24 * 60 * 60 * 1000),
      nextVulnScan: new Date(Date.now() + Math.random() * 7 * 24 * 60 * 60 * 1000),
      
      patchLevel: Math.floor(Math.random() * 30) + 70,
      lastPatchDate: new Date(Date.now() - Math.random() * 30 * 24 * 60 * 60 * 1000),
      pendingPatches: Math.floor(Math.random() * 10),
      
      // Sample software
      software: type === 'workstation' || type === 'server' ? [
        {
          name: 'Microsoft Office',
          version: '2021',
          vendor: 'Microsoft',
          licenseType: 'Commercial',
          installDate: new Date(Date.now() - Math.random() * 365 * 24 * 60 * 60 * 1000),
          lastUpdate: new Date(Date.now() - Math.random() * 30 * 24 * 60 * 60 * 1000)
        },
        {
          name: 'Antivirus Solution',
          version: '12.5.1',
          vendor: 'Security Vendor',
          licenseType: 'Commercial',
          installDate: deploymentDate,
          lastUpdate: new Date(Date.now() - Math.random() * 7 * 24 * 60 * 60 * 1000)
        }
      ] : [],
      
      // Sample services based on asset type
      services: (() => {
        const commonServices = [];
        if (type === 'server') {
          commonServices.push(
            { name: 'HTTP', port: 80, protocol: 'TCP', status: 'running' },
            { name: 'HTTPS', port: 443, protocol: 'TCP', status: 'running' },
            { name: 'SSH', port: 22, protocol: 'TCP', status: 'running' }
          );
        } else if (type === 'workstation') {
          commonServices.push(
            { name: 'RDP', port: 3389, protocol: 'TCP', status: 'running' }
          );
        } else if (type === 'firewall') {
          commonServices.push(
            { name: 'SNMP', port: 161, protocol: 'UDP', status: 'running' },
            { name: 'Management', port: 8443, protocol: 'TCP', status: 'running' }
          );
        }
        return commonServices;
      })(),
      
      // Security controls - only include fields that work with the schema
      securityControls: {
        antivirus: {
          installed: type === 'workstation' || type === 'server',
          product: 'CyberSec Antivirus Pro',
          version: '12.5.1',
          lastUpdate: new Date(Date.now() - Math.random() * 7 * 24 * 60 * 60 * 1000),
          status: Math.random() > 0.1 ? 'active' : 'outdated'
        },
        backups: {
          enabled: type === 'server' || Math.random() > 0.5,
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
      
      // Compliance
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
      
      // Lifecycle
      lifecycle: {
        acquisitionDate: new Date(deploymentDate.getTime() - 30 * 24 * 60 * 60 * 1000), // 30 days before deployment
        deploymentDate,
        lastMaintenanceDate: new Date(Date.now() - Math.random() * 90 * 24 * 60 * 60 * 1000),
        nextMaintenanceDate: new Date(Date.now() + Math.random() * 90 * 24 * 60 * 60 * 1000),
        endOfLifeDate: new Date(Date.now() + Math.random() * 365 * 5 * 24 * 60 * 60 * 1000), // 5 years from now
      },
      
      // Financial
      financial: {
        acquisitionCost: Math.floor(Math.random() * 10000) + 1000,
        currentValue: Math.floor(Math.random() * 8000) + 500,
        maintenanceCost: Math.floor(Math.random() * 1000) + 100,
        currency: 'USD'
      },
      
      tags: ['production', 'monitored', department.toLowerCase()],
      businessFunction: `${department} Operations`,
      dataClassification: dataClassifications[Math.floor(Math.random() * dataClassifications.length)],
      
      discoveryMethod: 'network_scan',
      discoveredBy: users[(users.length)-1]._id,
      
      // Monitoring configuration
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
      
      // Alerts
      alerts: {
        enabled: true,
        notifications: [
          {
            type: 'email',
            endpoint: `${department.toLowerCase()}@cybersec.com`,
            enabled: true
          }
        ]
      },
      
      lastUpdatedBy: users[(users.length)-1]._id,
      notes: `${type.charAt(0).toUpperCase() + type.slice(1)} asset deployed in ${location}. Managed by ${department} department.`
    };
    
    assets.push(asset);
    createdAssets.push({
      name: asset.name,
      type: asset.type,
      id: i // temporary ID for connections
    });
  }
  
  // Add some realistic network connections after creating all assets
  assets.forEach((asset, index) => {
    const connections = [];
    const dependencies = [];
    
    // Servers connect to switches
    if (asset.type === 'server') {
      const switches = createdAssets.filter(a => a.type === 'switch');
      if (switches.length > 0) {
        const randomSwitch = switches[Math.floor(Math.random() * switches.length)];
        connections.push(randomSwitch.name);
        dependencies.push({
          assetId: randomSwitch.name,
          relationship: 'connected_to',
          description: 'Network connection'
        });
      }
    }
    
    // Workstations connect to switches
    if (asset.type === 'workstation') {
      const switches = createdAssets.filter(a => a.type === 'switch');
      if (switches.length > 0) {
        const randomSwitch = switches[Math.floor(Math.random() * switches.length)];
        connections.push(randomSwitch.name);
        dependencies.push({
          assetId: randomSwitch.name,
          relationship: 'connected_to',
          description: 'Network access'
        });
      }
    }
    
    // Switches connect to routers
    if (asset.type === 'switch') {
      const routers = createdAssets.filter(a => a.type === 'router');
      if (routers.length > 0) {
        const randomRouter = routers[Math.floor(Math.random() * routers.length)];
        connections.push(randomRouter.name);
        dependencies.push({
          assetId: randomRouter.name,
          relationship: 'connected_to',
          description: 'Network routing'
        });
      }
    }
    
    // Everything behind firewall
    if (asset.type !== 'firewall') {
      const firewalls = createdAssets.filter(a => a.type === 'firewall');
      if (firewalls.length > 0) {
        const randomFirewall = firewalls[Math.floor(Math.random() * firewalls.length)];
        dependencies.push({
          assetId: randomFirewall.name,
          relationship: 'depends_on',
          description: 'Security protection'
        });
      }
    }
    
    asset.connections = connections;
    asset.dependencies = dependencies;
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
    
    // Create a realistic network topology
    const networkAssets = [
      // Core Infrastructure
      {
        name: 'FIREWALL-001',
        type: 'firewall',
        ipAddress: '192.168.1.1',
        location: 'Data Center A',
        criticality: 'critical',
        position: { x: 400, y: 50 },
        metadata: {
          manufacturer: 'Fortinet',
          model: 'FortiGate-600E',
          rules: 250,
          cpu: 35,
          memory: 45
        }
      },
      {
        name: 'ROUTER-001',
        type: 'router',
        ipAddress: '192.168.1.2',
        location: 'Data Center A',
        criticality: 'critical',
        position: { x: 400, y: 150 },
        connections: ['FIREWALL-001'],
        metadata: {
          manufacturer: 'Cisco',
          model: 'ISR-4431',
          cpu: 25,
          memory: 30
        }
      },
      // Switches
      {
        name: 'SWITCH-001',
        type: 'switch',
        ipAddress: '192.168.1.10',
        location: 'Data Center A',
        criticality: 'high',
        position: { x: 200, y: 250 },
        connections: ['ROUTER-001'],
        metadata: {
          manufacturer: 'Cisco',
          model: 'Catalyst-9300',
          ports: 48,
          connectedDevices: 15,
          cpu: 20,
          memory: 25
        }
      },
      {
        name: 'SWITCH-002',
        type: 'switch',
        ipAddress: '192.168.1.11',
        location: 'Data Center A',
        criticality: 'high',
        position: { x: 600, y: 250 },
        connections: ['ROUTER-001'],
        metadata: {
          manufacturer: 'HP',
          model: 'Aruba-CX-6300',
          ports: 24,
          connectedDevices: 8,
          cpu: 15,
          memory: 20
        }
      },
      // Servers
      {
        name: 'SERVER-001',
        type: 'server',
        ipAddress: '192.168.1.100',
        location: 'Data Center A',
        criticality: 'critical',
        position: { x: 100, y: 350 },
        connections: ['SWITCH-001'],
        operatingSystem: 'Windows Server 2022',
        metadata: {
          manufacturer: 'Dell',
          model: 'PowerEdge-R750',
          cpu: 65,
          memory: 78,
          storage: 45,
          user: 'Database Server'
        }
      },
      {
        name: 'SERVER-002',
        type: 'server',
        ipAddress: '192.168.1.101',
        location: 'Data Center A',
        criticality: 'high',
        position: { x: 300, y: 350 },
        connections: ['SWITCH-001'],
        operatingSystem: 'Ubuntu 22.04',
        metadata: {
          manufacturer: 'HP',
          model: 'ProLiant-DL380',
          cpu: 45,
          memory: 55,
          storage: 60,
          user: 'Web Server'
        }
      },
      // Workstations
      {
        name: 'WORKSTATION-001',
        type: 'workstation',
        ipAddress: '192.168.1.200',
        location: 'Office Floor 1',
        criticality: 'medium',
        position: { x: 500, y: 350 },
        connections: ['SWITCH-002'],
        operatingSystem: 'Windows 11',
        metadata: {
          manufacturer: 'Dell',
          model: 'OptiPlex-7090',
          cpu: 35,
          memory: 40,
          storage: 25,
          user: 'john.doe'
        }
      },
      {
        name: 'WORKSTATION-002',
        type: 'workstation',
        ipAddress: '192.168.1.201',
        location: 'Office Floor 1',
        criticality: 'medium',
        position: { x: 700, y: 350 },
        connections: ['SWITCH-002'],
        operatingSystem: 'Windows 11',
        metadata: {
          manufacturer: 'HP',
          model: 'EliteDesk-800',
          cpu: 28,
          memory: 35,
          storage: 30,
          user: 'jane.smith'
        }
      },
      // Network devices
      {
        name: 'ACCESS-POINT-001',
        type: 'access_point',
        ipAddress: '192.168.1.50',
        location: 'Office Floor 1',
        criticality: 'medium',
        position: { x: 800, y: 250 },
        connections: ['SWITCH-002'],
        metadata: {
          manufacturer: 'Cisco',
          model: 'Aironet-9120',
          connectedDevices: 12,
          cpu: 15,
          memory: 20
        }
      }
    ];

    // Create the topology assets
    const createdAssets = [];
    for (let i = 0; i < networkAssets.length; i++) {
      const assetData = networkAssets[i];
      const asset = new Asset({
        ...assetData,
        assetId: `AST-${String(i + 1).padStart(4, '0')}`, // Pre-generate unique asset ID
        status: 'online',
        owner: 'IT Department',
        department: 'IT',
        hostname: `${assetData.name.toLowerCase()}.cybersec.local`,
        macAddress: Array.from({ length: 6 }, () => Math.floor(Math.random() * 256).toString(16).padStart(2, '0')).join(':'),
        securityScore: Math.floor(Math.random() * 30) + 70,
        complianceScore: Math.floor(Math.random() * 20) + 80,
        lastSeen: new Date(),
        tags: ['production', 'monitored', 'topology'],
        dataClassification: 'internal',
        securityControls: {
          antivirus: {
            installed: assetData.type === 'workstation' || assetData.type === 'server',
            product: 'CyberSec Antivirus Pro',
            version: '12.5.1',
            lastUpdate: new Date(Date.now() - Math.random() * 7 * 24 * 60 * 60 * 1000),
            status: 'active'
          },
          backups: {
            enabled: assetData.type === 'server',
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
        vulnerabilities: {
          total: Math.floor(Math.random() * 10),
          critical: Math.floor(Math.random() * 2),
          high: Math.floor(Math.random() * 3),
          medium: Math.floor(Math.random() * 4),
          low: Math.floor(Math.random() * 5)
        },
        patchLevel: Math.floor(Math.random() * 20) + 80,
        lifecycle: {
          acquisitionDate: new Date(Date.now() - 365 * 24 * 60 * 60 * 1000),
          deploymentDate: new Date(Date.now() - 300 * 24 * 60 * 60 * 1000),
          lastMaintenanceDate: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000),
          nextMaintenanceDate: new Date(Date.now() + 60 * 24 * 60 * 60 * 1000)
        },
        financial: {
          acquisitionCost: Math.floor(Math.random() * 5000) + 1000,
          currentValue: Math.floor(Math.random() * 3000) + 500,
          maintenanceCost: Math.floor(Math.random() * 500) + 100,
          currency: 'USD'
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
        }
      });
      
      const savedAsset = await asset.save();
      createdAssets.push(savedAsset);
    }

    console.log(`✅ Created ${createdAssets.length} network topology assets`);
    
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