const express = require("express");
const cors = require("cors");
const mysql = require("mysql");
const jwt = require("jsonwebtoken");
const path = require("path");
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
require('dotenv').config();

const app = express();

const corsOptions = {
  origin: "http://localhost:8081", // Set your allowed origin here
};

//app.use(cors(corsOptions)); // Use CORS middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

const connection = mysql.createConnection({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME
});

connection.connect((err) => {
  if (err) {
    console.error('Error connecting to the database:', err);
    return;
  }
  console.log('Connected to the database.');
});

// Helper functions for encryption and decryption
function encrypt(text) {
  const cipher = crypto.createCipher('aes-256-cbc', process.env.SECRET_KEY);
  let encrypted = cipher.update(text, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  return encrypted;
}

function decrypt(text) {
  const decipher = crypto.createDecipher('aes-256-cbc', process.env.SECRET_KEY);
  let decrypted = decipher.update(text, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  return decrypted;
}

app.post("/api/v1/register", async (req, res) => {
  const { full_name, wa_number, education, email, password } = req.body;

  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  const waNumberRegex = /^\d+$/;

  if (!full_name || !wa_number || !education || !email || !password) {
    res.send("Error, null credential");
    return;
  }

  if (full_name.length > 30 || wa_number.length > 30 || education.length > 30 || email.length > 30 || password.length > 30) {
    res.send("Error, fields cannot exceed 30 characters");
    return;
  }

  if (!emailRegex.test(email)) {
    res.send("Error, invalid email format");
    return;
  }

  if (!waNumberRegex.test(wa_number)) {
    res.send("Error, WhatsApp number must be numeric");
    return;
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const hashedNumber = await bcrypt.hash(wa_number, 10);
    const encryptedEmail = encrypt(email);

    const query = `INSERT INTO users (username, email, password, fullname, education, wa_number, createdAt, updatedAt) 
                   VALUES (?, ?, ?, ?, ?, ?, NOW(), NOW())`;

    const values = [full_name, encryptedEmail, hashedPassword, full_name, education, hashedNumber];

    connection.query(query, values, (err) => {
      if (err) {
        console.error('Error inserting data into the database:', err);
        res.send("Error registering user");
        return;
      }
      res.send("Registration successful");
    });
  } catch (err) {
    console.error('Error hashing email or password:', err);
    res.send("Error registering user");
  }
});

const JWT_SECRET = "your-very-secure-secret"; // Replace with a secure key

// Login route
app.post("/api/v1/login", (req, res) => {
  const { email, password } = req.body;

  console.log("Received password:", password);

  // Encrypt the email to match the stored encrypted email
  const encryptedEmail = encrypt(email); // Assuming encrypt is a predefined function

  const query = 'SELECT password FROM users WHERE email = ?';
  connection.query(query, [encryptedEmail], async (err, results) => {
    if (err) {
      console.error('Error querying database:', err);
      res.status(500).send("Error logging in");
      return;
    }

    if (results.length === 0) {
      res.status(401).send("Invalid credentials");
      return;
    }

    try {
      console.log("Stored hashed password:", results[0].password);

      const match = await bcrypt.compare(password, results[0].password);
      if (match) {
        // Generate JWT on successful login
        const token = jwt.sign({ email }, JWT_SECRET, { expiresIn: '1h' });

        // Send the token to the client
        res.status(200).json({
          message: "Login successful",
          token: token
        });
      } else {
        res.status(401).send("Invalid credentials");
      }
    } catch (err) {
      console.error('Error comparing passwords:', err);
      res.status(500).send("Error logging in");
    }
  });
});

// Middleware to verify JWT
function authenticateJWT(req, res, next) {
  const authHeader = req.headers.authorization;

  if (authHeader) {
    const token = authHeader.split(' ')[1]; // Bearer <token>

    jwt.verify(token, JWT_SECRET, (err, user) => {
      if (err) {
        return res.status(403).send("Invalid token");
      }

      req.user = user; // Attach the decoded token data (e.g., email) to the request
      next();
    });
  } else {
    res.status(401).send("Token missing or not provided");
  }
}


app.put("/api/v1/reset-password", (req, res) => {
  const { email, otp, new_password } = req.body;

  res.status(501).send("Password reset not implemented yet");
});

const PORT = process.env.PORT || 8080;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
