const jwt = require("jsonwebtoken");
require('dotenv').config();

const JWT_SECRET = process.env.JWT_SECRET;
const JWT_REFRESH_SECRET = process.env.JWT_REFRESH_SECRET;

function generateTokens(user) {
  const accessToken = jwt.sign({ email: user.email }, JWT_SECRET, { expiresIn: '15m' });
  const refreshToken = jwt.sign({ email: user.email }, JWT_REFRESH_SECRET, { expiresIn: '7d' });
  return { accessToken, refreshToken };
}

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

module.exports = { generateTokens, authenticateJWT };
