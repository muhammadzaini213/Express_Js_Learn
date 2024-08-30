const express = require("express");
const cors = require("cors");
const mysql = require("mysql");
const jwt = require("jsonwebtoken");
const path = require("path");
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const nodemailer = require('nodemailer');
const { generateTokens, authenticateJWT } = require('./utils/jwtUtils');
const { encrypt, decrypt } = require('./utils/cryptoUtils');
const connection = require('./config/db.config');

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
    const encryptedEmail = encrypt(email);
    const encryptedWaNumber = encrypt(wa_number);

    const checkUserQuery = `SELECT * FROM users WHERE email = ? OR wa_number = ?`;
    connection.query(checkUserQuery, [encryptedEmail, encryptedWaNumber], async (err, results) => {
      if (err) {
        console.error('Error querying the database:', err);
        res.send("Error checking user existence");
        return;
      }

      if (results.length > 0) {
        res.send("Error, user with this email or WhatsApp number already exists");
        return;
      }

      const hashedPassword = await bcrypt.hash(password, 10);

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


app.post("/api/v1/login", (req, res) => {
  const { email, password } = req.body;
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

  const storeRefreshTokenQuery = `UPDATE users SET refresh_token = ? WHERE email = ?`;
  connection.query(storeRefreshTokenQuery, [refreshToken, encryptedEmail], (err) => {
    if (err) {
      console.error('Error storing refresh token:', err);
      return res.status(500).send("Error logging in");  // Handle the error and exit
    }

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
