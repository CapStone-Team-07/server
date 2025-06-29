### Create a user
```bash
curl -X POST http://192.168.0.193:5000/api/auth/register   -H "Content-Type: application/json"   -d '{
    "username": "admin",
    "email": "admin@gmail.com",
    "password": "Salam123",
    "firstName": "Admin",
    "lastName": "User",
    "role": "admin"
  }'
```

