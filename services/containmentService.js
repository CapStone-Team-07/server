//containment implementation
//const express = require('express');
const app = express();
require('dotenv').config();
const containmentRoutes = require('./routes/containmentRoutes');

app.use(express.json());

// other routes...
app.use('/api/containment', containmentRoutes);

// Start server
const PORT = process.env.PORTT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));