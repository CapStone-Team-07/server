### Create a user
```bash
curl -X POST http://192.168.0.193:5000/api/auth/register -H "Content-Type: application/json"   -d '{
    "username": "admin",
    "email": "admin@gmail.com",
    "password": "Salam123",
    "firstName": "Admin",
    "lastName": "User",
    "role": "admin"
  }'
```
### Users
# 🔐 Default Login Credentials:
# Email: admin@cybersec.com
# Username: admin
# Password: admin123

## 👥 Other Test Users:
# Hasan Hamidli (soc_manager): Hasah / password123
# Gulyaz Ismayilzada (senior_analyst): Gulyaz / password123
# Elvin Seidli (soc_analyst): Elvin / password123
# Arif Mammadov (soc_analyst): Arif / password123
# Fidan Huseynova (soc_analyst): Fidan / password123
# Altun Tarverdiyev (soc_analyst): Altun / password123

### Login 
```bash
curl -X POST http://192.168.0.193:5000/api/auth/login   -H "Content-Type: application/json"   -d '{
    "username": "Arif",
    "password": "password123"
  }' | jq
```

### Adding JWT token (from response)
# JWT = ey... 

### Fetching users
# Only admin can fetch users
# Get admin' jwt token 

```bash
curl http://192.168.0.193:5000/api/users -H "Authorization: Bearer $JWT" | jq
```

## Creating a threat
```bash
curl -X POST http://192.168.0.193:5000/api/threats -H "Content-Type: application/json" -H "Authorization: Bearer $JWT"   -d '{
    "threatId": "THREAT-9999",
    "title": "Phishing Attack - Germany",
    "description": "Suspicious phishing activity detected from Germany",
    "severity": "High",
    "category": "Phishing",
    "status": "Active",
    "source": "Email Security",
    "riskScore": 87,
    "sourceIP": "123.45.67.89",
    "targetIP": "192.168.1.101",
    "protocol": "HTTP",
    "port": 8080,
    "country": "Germany",
    "attackVector": "Phishing Attack Vector",
    "mitreTactics": "Initial Access",
    "confidence": 92,
    "affectedAssets": 5,
    "firstSeen": "2024-06-28T08:00:00Z",
    "lastActivity": "2024-06-29T09:15:00Z",
    "analyst": "60f5c03e90a1f22d9c2b7b10",
    "analystName": "Elvin Seidli",
    "iocs": {
      "ipAddresses": ["234.56.78.90"],
      "domains": ["malicious1.com"],
      "urls": ["http://malicious1.com/payload"]
    }
  }'
```

### Fetching threats
```bash
curl http://192.168.0.193:5000/api/threats -H "Authorization: Bearer $JWT" | jq
```

### Creating an Asset


### Telegram Chatids
Stored: @Elvinnsuleymanov = 1530374052
Stored: @Gulyazizade = 1947654367
Stored: @Juliusvault = 1062394539
Stored: @arifmamadov = 1947715194

