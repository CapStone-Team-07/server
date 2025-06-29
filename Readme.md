# Cybersecurity Platform Backend

A comprehensive Node.js backend API for cybersecurity threat management, built with Express.js, MongoDB, and JWT authentication.

## 🚀 Features

- **Authentication & Authorization**
  - JWT-based authentication
  - Role-based access control (RBAC)
  - Password hashing with bcrypt
  - Account lockout protection
  - Permission-based route protection

- **Threat Management**
  - CRUD operations for threats
  - Block IP addresses
  - Escalate threats
  - Resolve threats
  - IOC (Indicators of Compromise) management
  - Threat statistics and analytics

- **User Management**
  - User CRUD operations
  - Role management
  - Account status management
  - Activity tracking

- **Security Features**
  - Rate limiting
  - Input validation
  - XSS protection
  - MongoDB injection prevention
  - Audit logging
  - Helmet.js security headers

## 📋 Prerequisites

- Node.js (v16 or higher)
- MongoDB Atlas account or local MongoDB installation
- npm or yarn package manager

## 🛠️ Installation

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd cybersecurity-platform-backend
   ```

2. **Install dependencies**
   ```bash
   npm install
   ```

3. **Set up environment variables**
   
   Create a `.env` file in the root directory:
   ```bash
   cp .env.example .env
   ```
   
   Update the `.env` file with your configuration:
   ```env
   NODE_ENV=development
   PORT=5000
   MONGODB_URI=mongodb+srv://arif:PiojwXuWYdPnPnaq@cluster0.eurei2j.mongodb.net/cybersecurity_platform?retryWrites=true&w=majority
   JWT_SECRET=your_super_secret_jwt_key_change_this_in_production_2024
   JWT_EXPIRE=7d
   JWT_COOKIE_EXPIRE=7
   ```

4. **Start the server**
   ```bash
   # Development mode with auto-restart
   npm run dev
   
   # Production mode
   npm start
   ```

## 📊 Database Setup

### Option 1: Seed with Sample Data
```bash
npm run seed
```
This will create:
- 5 sample users (including admin)
- 50 sample threats
- 30 sample assets

### Option 2: Create Admin User Only
```bash
npm run seed admin
```

### Option 3: Clear Database
```bash
npm run seed clear
```

### Manual User Creation
Use curl to create a user:
```bash
curl -X POST http://localhost:5000/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "username": "admin",
    "email": "admin@gmail.com",
    "password": "Salam123",
    "firstName": "Admin",
    "lastName": "User",
    "role": "admin"
  }'
```

## 🔐 Default Credentials

After seeding, you can login with:
- **Email**: admin@cybersec.com
- **Username**: admin
- **Password**: admin123

## 📚 API Documentation

### Base URL
```
http://localhost:5000/api
```

### Authentication Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/auth/register` | Register new user |
| POST | `/auth/login` | User login |
| GET | `/auth/me` | Get current user |
| PUT | `/auth/updatedetails` | Update user details |
| PUT | `/auth/updatepassword` | Update password |
| GET | `/auth/logout` | Logout user |
| POST | `/auth/forgotpassword` | Request password reset |
| PUT | `/auth/resetpassword/:token` | Reset password |

### Threat Management Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/threats` | Get all threats |
| POST | `/threats` | Create new threat |
| GET | `/threats/:id` | Get single threat |
| PUT | `/threats/:id` | Update threat |
| DELETE | `/threats/:id` | Delete threat |
| POST | `/threats/:id/block` | Block threat IP |
| POST | `/threats/:id/escalate` | Escalate threat |
| POST | `/threats/:id/resolve` | Resolve threat |
| GET | `/threats/stats` | Get threat statistics |
| GET | `/threats/timeline` | Get threat timeline |
| GET | `/threats/export` | Export threats to CSV |

### User Management Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/users` | Get all users |
| POST | `/users` | Create new user |
| GET | `/users/:id` | Get single user |
| PUT | `/users/:id` | Update user |
| DELETE | `/users/:id` | Delete user |
| PUT | `/users/:id/role` | Update user role |
| PUT | `/users/:id/status` | Toggle user status |

## 🔧 User Roles & Permissions

### Admin
- Full system access
- User management
- System configuration
- All threat operations

### SOC Manager
- User management (limited)
- All threat operations
- Report generation
- System monitoring

### Senior Analyst
- Threat analysis and management
- Report generation
- Asset management

### SOC Analyst
- Threat detection and analysis
- Basic threat operations
- Asset viewing

### Readonly
- View-only access to threats
- View-only access to assets
- Basic reporting

## 🛡️ Security Features

- **JWT Authentication**: Secure token-based authentication
- **Rate Limiting**: API rate limiting to prevent abuse
- **Input Validation**: Comprehensive input validation using express-validator
- **Password Security**: bcrypt hashing with salt rounds
- **Account Lockout**: Automatic account lockout after failed attempts
- **Audit Logging**: Comprehensive audit trail for all actions
- **Permission System**: Granular permission-based access control

## 📈 Testing the API

### 1. Health Check
```bash
curl http://localhost:5000/api/health
```

### 2. Register User
```bash
curl -X POST http://localhost:5000/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "username": "testuser",
    "email": "test@example.com",
    "password": "Test123!",
    "firstName": "Test",
    "lastName": "User",
    "role": "soc_analyst"
  }'
```

### 3. Login
```bash
curl -X POST http://localhost:5000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "testuser",
    "password": "Test123!"
  }'
```

### 4. Get Threats (with token)
```bash
curl -X GET http://localhost:5000/api/threats \
  -H "Authorization: Bearer YOUR_JWT_TOKEN"
```

### 5. Create Threat
```bash
curl -X POST http://localhost:5000/api/threats \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -d '{
    "title": "Malware Detection",
    "description": "Suspicious malware activity detected",
    "severity": "High",
    "category": "Malware",
    "sourceIP": "192.168.1.100",
    "targetIP": "192.168.1.200",
    "protocol": "TCP",
    "port": 80,
    "country": "Unknown",
    "attackVector": "Email Attachment",
    "source": "Endpoint Detection",
    "riskScore": 85,
    "confidence": 90
  }'
```

## 🐛 Troubleshooting

### Common Issues

1. **MongoDB Connection Error**
   - Verify your MongoDB URI in `.env`
   - Check network connectivity
   - Ensure MongoDB Atlas IP whitelist includes your IP

2. **JWT Token Errors**
   - Check if JWT_SECRET is set in `.env`
   - Verify token is properly included in Authorization header

3. **Permission Denied**
   - Check user role and permissions
   - Verify user is active and not locked

4. **Cookie Issues**
   - Ensure JWT_COOKIE_EXPIRE is set correctly
   - Check browser settings for cookies

## 📝 Development

### Project Structure
```
cybersecurity-platform-backend/
├── controllers/         # Route handlers
├── middleware/         # Custom middleware
├── models/            # Mongoose schemas
├── routes/            # Express routes
├── scripts/           # Utility scripts
├── server.js          # Main server file
├── package.json       # Dependencies
└── .env              # Environment variables
```

### Adding New Features

1. Create model in `models/`
2. Create controller in `controllers/`
3. Create routes in `routes/`
4. Update `server.js` to include new routes
5. Add appropriate middleware and validation

## 🚀 Deployment

### Environment Variables for Production
```env
NODE_ENV=production
PORT=5000
MONGODB_URI=your_production_mongodb_uri
JWT_SECRET=your_super_secure_production_secret
CORS_ORIGIN=https://your-frontend-domain.com
```

### Docker Deployment
```dockerfile
FROM node:16-alpine
WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production
COPY . .
EXPOSE 5000
CMD ["npm", "start"]
```

## 📞 Support

If you encounter any issues or need help:

1. Check the troubleshooting section above
2. Review the API documentation
3. Check server logs for detailed error messages
4. Ensure all environment variables are correctly set

## 🔄 Version History

- **v1.0.0**: Initial release with authentication and threat management
- Features: JWT auth, RBAC, threat CRUD, user management, audit logging