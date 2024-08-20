const express = require("express");
const cors = require("cors");
const mysql = require("mysql");
const path = require("path");
const bcrypt = require('bcryptjs');
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
  host: 'sql12.freesqldatabase.com',
  user: 'sql12725260',
  password: '7RLxBbNh9P',
  database: 'sql12725260'
});

connection.connect((err) => {
  if (err) {
    console.error('Error connecting to the database:', err);
    return;
  }
  console.log('Connected to the database.');
});

app.post("/api/v1/register", async (req, res) => {
  const { full_name, wa_number, education, email, password } = req.body;

const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

const waNumberRegex = /^\d+$/;

if (
  !full_name || 
  !wa_number || 
  !education || 
  !email || 
  !password
) {
  res.send("Error, null credential");
  return;
}

// Check if each field is within the 30 character limit
if (
  full_name.length > 30 || 
  wa_number.length > 30 || 
  education.length > 30 || 
  email.length > 30 || 
  password.length > 30
) {
  res.send("Error, fields cannot exceed 30 characters");
  return;
}

// Validate the email format
if (!emailRegex.test(email)) {
  res.send("Error, invalid email format");
  return;
}

// Validate the WhatsApp number format (must be numeric)
if (!waNumberRegex.test(wa_number)) {
  res.send("Error, WhatsApp number must be numeric");
  return;
}

res.send("All credentials are valid");
  try {
    // Hash the email and password
    const hashedEmail = await bcrypt.hash(email, 10);
    const hashedPassword = await bcrypt.hash(password, 10);
    const hashedNumber = await bcrypt.hash(wa_number, 10);

    const query = `INSERT INTO users (username, email, password, fullname, education, wa_number, createdAt, updatedAt) 
                   VALUES (?, ?, ?, ?, ?, ?, NOW(), NOW())`;

    const values = [full_name, hashedEmail, hashedPassword, full_name, education, hashedNumber];

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

app.post("/api/v1/login", (req, res) => {
  const { email, password } = req.body;

  // Validate that email and password are provided
  if (!email || !password) {
    res.status(400).send("Email and password are required");
    return;
  }

  // Validate the email format
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(email)) {
    res.status(400).send("Invalid email format");
    return;
  }

  const query = 'SELECT password FROM users WHERE email = ?';
  connection.query(query, [email], async (err, results) => {
    if (err) {
      console.error('Error querying database:', err);
      res.status(500).send("Error logging in");
      return;
    }

    // Check if email exists in the database
    if (results.length === 0) {
      res.status(401).send("Invalid credentials");
      return;
    }

    // Verify password
    try {
      const match = await bcrypt.compare(password, results[0].password);
      if (match) {
        res.status(200).send("Login successful");
      } else {
        res.status(401).send("Invalid credentials");
      }
    } catch (err) {
      console.error('Error comparing passwords:', err);
      res.status(500).send("Error logging in");
    }
  });
});

app.put("/api/v1/reset-password", (req, res) => {
  const { email, otp, new_password } = req.body;

  // Implementation for OTP validation and password reset goes here
  // This usually involves additional logic to validate OTP and update the password

  res.status(501).send("Password reset not implemented yet");
});

const PORT = process.env.PORT || 8080;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
 
