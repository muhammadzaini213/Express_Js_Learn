const express = require("express");
const cors = require("cors");
const mysql = require("mysql");
const jwt = require("jsonwebtoken");
const path = require("path");
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const nodemailer = require('nodemailer');
require('dotenv').config();

const app = express();

const corsOptions = {
  origin: "http://localhost:8081", // Set your allowed origin here
};

const transporter = nodemailer.createTransport({
  host: process.env.MAIL_HOST,
  port: process.env.MAIL_PORT,
  secure: false, // Use `true` for port 465, `false` for all other ports
  auth: {
    user: process.env.MAIL_USER,
    pass: process.env.MAIL_PASSWORD,
  },
});


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

  // Validate required fields
  if (!full_name || !wa_number || !education || !email || !password) {
    res.send("Error, null credential");
    return;
  }

  // Validate field lengths
  if (full_name.length > 30 || wa_number.length > 30 || education.length > 30 || email.length > 30 || password.length > 30) {
    res.send("Error, fields cannot exceed 30 characters");
    return;
  }

  // Validate email format
  if (!emailRegex.test(email)) {
    res.send("Error, invalid email format");
    return;
  }

  // Validate WhatsApp number (must be numeric)
  if (!waNumberRegex.test(wa_number)) {
    res.send("Error, WhatsApp number must be numeric");
    return;
  }

  try {
    // Encrypt the email and WhatsApp number
    const encryptedEmail = encrypt(email);
    const encryptedWaNumber = encrypt(wa_number);

    // Check if a user with the same email or WhatsApp number exists
    const checkUserQuery = `SELECT * FROM users WHERE email = ? OR wa_number = ?`;
    connection.query(checkUserQuery, [encryptedEmail, encryptedWaNumber], async (err, results) => {
      if (err) {
        console.error('Error querying the database:', err);
        res.send("Error checking user existence");
        return;
      }

      // If a user with the same email or WhatsApp number exists, return an error
      if (results.length > 0) {
        res.send("Error, user with this email or WhatsApp number already exists");
        return;
      }

      // Hash the password for secure storage
      const hashedPassword = await bcrypt.hash(password, 10);

      // Proceed with inserting the new user into the database
      const insertQuery = `INSERT INTO users (username, email, password, fullname, education, wa_number, createdAt, updatedAt) 
                           VALUES (?, ?, ?, ?, ?, ?, NOW(), NOW())`;

      const values = [full_name, encryptedEmail, hashedPassword, full_name, education, encryptedWaNumber];

      connection.query(insertQuery, values, (err) => {
        if (err) {
          console.error('Error inserting data into the database:', err);
          res.send("Error registering user");
          return;
        }
        res.send("Registration successful");
      });
    });
  } catch (err) {
    console.error('Error during registration process:', err);
    res.send("Error registering user");
  }
});

const JWT_SECRET = process.env.JWT_SECRET; // Replace with a secure key

const JWT_REFRESH_SECRET = process.env.JWT_REFRESH;


function generateTokens(user) {
  const accessToken = jwt.sign({ email: user.email }, JWT_SECRET, { expiresIn: '15m' }); // Short-lived
  const refreshToken = jwt.sign({ email: user.email }, JWT_REFRESH_SECRET, { expiresIn: '7d' }); // Longer-lived
  return { accessToken, refreshToken };
}

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
  const accessToken = jwt.sign({ email }, JWT_SECRET, { expiresIn: '15m' });
  const refreshToken = jwt.sign({ email }, JWT_REFRESH_SECRET, { expiresIn: '7d' });

  // Store refresh token and only send the response after successful update
  const storeRefreshTokenQuery = `UPDATE users SET refresh_token = ? WHERE email = ?`;
  connection.query(storeRefreshTokenQuery, [refreshToken, encryptedEmail], (err) => {
    if (err) {
      console.error('Error storing refresh token:', err);
      return res.status(500).send("Error logging in");  // Handle the error and exit
    }

    // Send the response only after the refresh token is stored
    res.status(200).json({
      message: "Login successful",
      accessToken: accessToken,
      refreshToken: refreshToken
    });
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

app.post("/api/v1/request-password-reset", (req, res) => {
  const { email } = req.body;

  // Encrypt the email to match the stored encrypted email
  const encryptedEmail = encrypt(email);

  // Step 1: Check if the user exists
  const checkUserQuery = `SELECT * FROM users WHERE email = ?`;
  connection.query(checkUserQuery, [encryptedEmail], (err, results) => {
    if (err) {
      console.error('Error querying the database:', err);
      return res.status(500).send("Error checking user existence");
    }

    // If no user is found, send an error response
    if (results.length === 0) {
      return res.status(404).send("Email not found");
    }

    // Step 2: Generate a 6-digit OTP
    const otp = crypto.randomInt(100000, 999999).toString();

    // Step 3: Store OTP in the database
    const insertOtpQuery = `INSERT INTO password_resets (email, otp) VALUES (?, ?)`;
    connection.query(insertOtpQuery, [encryptedEmail, otp], (err) => {
      if (err) {
        console.error('Error saving OTP:', err);
        return res.status(500).send("Error saving OTP");
      }

      // Step 4: Send OTP via nodemailer
      const mailOptions = {
        from: '"Your App" <your_email@example.com>', // Sender address
        to: email, // Recipient email
        subject: 'Password Reset OTP', // Subject line
        text: `Your OTP for resetting your password is: ${otp}`, // Plain text body
      };

      transporter.sendMail(mailOptions, (err, info) => {
        if (err) {
          console.error('Error sending OTP email:', err);
          return res.status(500).send("Error sending OTP email");
        }

        // Success response if email is sent
        res.status(200).send("OTP sent successfully");
      });
    });
  });
});

// Middleware to verify JWT
function authenticateJWT(req, res, next) {
  const authHeader = req.headers.authorization;

  if (authHeader) {
    const token = authHeader.split(' ')[1]; // Bearer <token>

    jwt.verify(token, JWT_SECRET, (err, user) => {
      if (err) {
        return res.status(403).send("Invalid or expired access token");
      }

      req.user = user; // Attach the decoded token data (e.g., email) to the request
      next();
    });
  } else {
    res.status(401).send("Token missing or not provided");
  }
}

app.post("/api/v1/refresh-token", (req, res) => {
  const { refreshToken } = req.body;

  if (!refreshToken) {
    return res.status(401).send("Refresh token required");
  }

  // Verify the refresh token
  jwt.verify(refreshToken, JWT_REFRESH_SECRET, (err, user) => {
    if (err) {
      return res.status(403).send("Invalid or expired refresh token");
    }

    // Optionally check if the refresh token matches the one in the database
    const query = `SELECT refresh_token FROM users WHERE email = ?`;
    connection.query(query, [encrypt(user.email)], (err, results) => {
      if (err || results.length === 0 || results[0].refresh_token !== refreshToken) {
        return res.status(403).send("Invalid refresh token");
      }

      // Generate a new access token
      const newAccessToken = jwt.sign({ email: user.email }, JWT_SECRET, { expiresIn: '15m' });

      res.status(200).json({
        accessToken: newAccessToken,
      });
    });
  });
});

const PORT = process.env.PORT || 8080;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});