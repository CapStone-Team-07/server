// models/User.js - User Model with Security Features
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const userSchema = new mongoose.Schema({
  // Basic Information
  username: {
    type: String,
    required: [true, 'Username is required'],
    unique: true,
    trim: true,
    minlength: [3, 'Username must be at least 3 characters'],
    maxlength: [30, 'Username cannot exceed 30 characters'],
    match: [/^[a-zA-Z0-9_]+$/, 'Username can only contain letters, numbers, and underscores']
  },
  email: {
    type: String,
    required: [true, 'Email is required'],
    unique: true,
    lowercase: true,
    trim: true,
    // match: [/^\w+([.-]?\w+)*@\w+([.-]?\w+)*(\.\w{2,3})+$/, 'Please enter a valid email']
  },
  password: {
    type: String,
    required: [true, 'Password is required'],
    minlength: [6, 'Password must be at least 6 characters'],
    select: false // Don't include password in queries by default
  },
  
  // Profile Information
  firstName: {
    type: String,
    required: [true, 'First name is required'],
    trim: true,
    maxlength: [50, 'First name cannot exceed 50 characters']
  },
  lastName: {
    type: String,
    required: [true, 'Last name is required'],
    trim: true,
    maxlength: [50, 'Last name cannot exceed 50 characters']
  },
  
  // Role and Permissions
  role: {
    type: String,
    enum: {
      values: ['admin', 'soc_manager', 'senior_analyst', 'soc_analyst', 'readonly'],
      message: 'Invalid role specified'
    },
    default: 'soc_analyst'
  },
  permissions: [{
    type: String,
    enum: [
      'threats:read', 'threats:write', 'threats:delete',
      'vulnerabilities:read', 'vulnerabilities:write', 'vulnerabilities:delete',
      'assets:read', 'assets:write', 'assets:delete',
      'reports:read', 'reports:write', 'reports:delete',
      'users:read', 'users:write', 'users:delete',
      'settings:read', 'settings:write',
      'system:admin'
    ]
  }],
  
  // Security Settings
  isActive: {
    type: Boolean,
    default: true
  },
  isEmailVerified: {
    type: Boolean,
    default: false
  },
  twoFactorEnabled: {
    type: Boolean,
    default: false
  },
  twoFactorSecret: {
    type: String,
    select: false
  },
  
  // Login Tracking
  lastLogin: {
    type: Date,
    default: null
  },
  lastLoginIP: {
    type: String,
    default: null
  },
  loginAttempts: {
    type: Number,
    default: 0
  },
  lockUntil: {
    type: Date,
    default: null
  },
  
  // Password Reset
  resetPasswordToken: {
    type: String,
    select: false
  },
  resetPasswordExpire: {
    type: Date,
    select: false
  },
  
  // Email Verification
  emailVerificationToken: {
    type: String,
    select: false
  },
  emailVerificationExpire: {
    type: Date,
    select: false
  },
  
  // Preferences
  preferences: {
    theme: {
      type: String,
      enum: ['dark', 'light', 'auto'],
      default: 'dark'
    },
    notifications: {
      email: { type: Boolean, default: true },
      browser: { type: Boolean, default: true },
      mobile: { type: Boolean, default: false }
    },
    dashboard: {
      refreshInterval: { type: Number, default: 30 },
      defaultView: { type: String, default: 'overview' }
    }
  },
  
  // Audit Trail
  createdBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    default: null
  },
  updatedBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    default: null
  }
}, {
  timestamps: true,
  toJSON: { virtuals: true },
  toObject: { virtuals: true }
});

// Indexes for performance
userSchema.index({ email: 1 });
userSchema.index({ username: 1 });
userSchema.index({ role: 1 });
userSchema.index({ isActive: 1 });
userSchema.index({ lastLogin: -1 });

// Virtual for full name
userSchema.virtual('fullName').get(function() {
  return `${this.firstName} ${this.lastName}`;
});

// Virtual for account locked status
userSchema.virtual('isLocked').get(function() {
  return !!(this.lockUntil && this.lockUntil > Date.now());
});

// Pre-save middleware to hash password
userSchema.pre('save', async function(next) {
  // Only hash the password if it has been modified (or is new)
  if (!this.isModified('password')) return next();
  
  try {
    // Hash password with cost of 12
    const saltRounds = parseInt(process.env.BCRYPT_SALT_ROUNDS) || 12;
    this.password = await bcrypt.hash(this.password, saltRounds);
    next();
  } catch (error) {
    next(error);
  }
});

// Pre-save middleware to set default permissions based on role
userSchema.pre('save', function(next) {
  if (this.isModified('role') || this.isNew) {
    switch (this.role) {
      case 'admin':
        this.permissions = [
          'threats:read', 'threats:write', 'threats:delete',
          'vulnerabilities:read', 'vulnerabilities:write', 'vulnerabilities:delete',
          'assets:read', 'assets:write', 'assets:delete',
          'reports:read', 'reports:write', 'reports:delete',
          'users:read', 'users:write', 'users:delete',
          'settings:read', 'settings:write',
          'system:admin'
        ];
        break;
      case 'soc_manager':
        this.permissions = [
          'threats:read', 'threats:write', 'threats:delete',
          'vulnerabilities:read', 'vulnerabilities:write',
          'assets:read', 'assets:write',
          'reports:read', 'reports:write',
          'users:read', 'users:write',
          'settings:read'
        ];
        break;
      case 'senior_analyst':
        this.permissions = [
          'threats:read', 'threats:write',
          'vulnerabilities:read', 'vulnerabilities:write',
          'assets:read', 'assets:write',
          'reports:read', 'reports:write'
        ];
        break;
      case 'soc_analyst':
        this.permissions = [
          'threats:read', 'threats:write',
          'vulnerabilities:read',
          'assets:read',
          'reports:read'
        ];
        break;
      case 'readonly':
        this.permissions = [
          'threats:read',
          'vulnerabilities:read',
          'assets:read',
          'reports:read'
        ];
        break;
    }
  }
  next();
});

// Instance method to check password
userSchema.methods.matchPassword = async function(enteredPassword) {
  return await bcrypt.compare(enteredPassword, this.password);
};

// Instance method to generate JWT token
userSchema.methods.getSignedJwtToken = function() {
  return jwt.sign(
    { 
      id: this._id,
      username: this.username,
      role: this.role 
    },
    process.env.JWT_SECRET,
    {
      expiresIn: process.env.JWT_EXPIRE || '7d'
    }
  );
};

// Instance method to check permissions
userSchema.methods.hasPermission = function(permission) {
  return this.permissions.includes(permission) || this.role === 'admin';
};

// Instance method to handle failed login attempts
userSchema.methods.incLoginAttempts = function() {
  // If we have a previous lock that has expired, restart at 1
  if (this.lockUntil && this.lockUntil < Date.now()) {
    return this.updateOne({
      $unset: { lockUntil: 1 },
      $set: { loginAttempts: 1 }
    });
  }
  
  const updates = { $inc: { loginAttempts: 1 } };
  
  // If we've reached max attempts and it's not locked already, lock the account
  if (this.loginAttempts + 1 >= 5 && !this.isLocked) {
    updates.$set = { lockUntil: Date.now() + 2 * 60 * 60 * 1000 }; // Lock for 2 hours
  }
  
  return this.updateOne(updates);
};

// Instance method to reset login attempts
userSchema.methods.resetLoginAttempts = function() {
  return this.updateOne({
    $unset: { loginAttempts: 1, lockUntil: 1 }
  });
};

// Static method to find user by credentials
userSchema.statics.findByCredentials = async function(username, password) {
  const user = await this.findOne({
    $or: [
      { username: username },
      { email: username }
    ],
    isActive: true
  }).select('+password');
  
  if (!user) {
    throw new Error('Invalid credentials');
  }
  
  // Check if account is locked
  if (user.isLocked) {
    // Increment attempts if account is locked
    await user.incLoginAttempts();
    throw new Error('Account is temporarily locked due to too many failed login attempts');
  }
  
  const isMatch = await user.matchPassword(password);
  
  if (!isMatch) {
    await user.incLoginAttempts();
    throw new Error('Invalid credentials');
  }
  
  // Reset login attempts on successful login
  if (user.loginAttempts && user.loginAttempts > 0) {
    await user.resetLoginAttempts();
  }
  
  // Update last login info
  user.lastLogin = new Date();
  await user.save();
  
  return user;
};

// Static method to create default admin user
userSchema.statics.createDefaultAdmin = async function() {
  try {
    const adminExists = await this.findOne({ role: 'admin' });
    
    if (!adminExists) {
      const defaultAdmin = new this({
        username: 'admin',
        email: 'admin@cybersec.com',
        password: 'admin123', // Change this in production!
        firstName: 'System',
        lastName: 'Administrator',
        role: 'admin',
        isActive: true,
        isEmailVerified: true
      });
      
      await defaultAdmin.save();
      console.log('✅ Default admin user created successfully');
      console.log('📧 Email: admin@cybersec.com');
      console.log('🔑 Password: admin123');
      console.log('⚠️  Please change the default password immediately!');
      
      return defaultAdmin;
    }
    
    return adminExists;
  } catch (error) {
    console.error('❌ Error creating default admin user:', error);
    throw error;
  }
};

// Remove sensitive data when converting to JSON
userSchema.methods.toJSON = function() {
  const user = this.toObject();
  delete user.password;
  delete user.resetPasswordToken;
  delete user.resetPasswordExpire;
  delete user.emailVerificationToken;
  delete user.emailVerificationExpire;
  delete user.twoFactorSecret;
  return user;
};

module.exports = mongoose.model('User', userSchema);