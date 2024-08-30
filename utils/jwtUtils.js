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
    const token = authHeader.split(' ')[1]; // Be>

    jwt.verify(token, JWT_SECRET, (err, user) => {
      if (err) {
        return res.status(403).send("Invalid toke>
      }

      req.user = user; // Attach the decoded toke>
      next();
    });
  } else {
    res.status(401).send("Token missing or not pr>
  }
}

module.exports = { generateTokens, authenticateJWT };
