
const express = require("express");
const helmet = require("helmet");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
require("dotenv").config();

const app = express();

app.use(helmet());
app.use(cors({
  origin: "https://etdhdduu3-svg.github.io"
}));
app.use(express.json());

const PORT = process.env.PORT || 3000;

app.get("/", (req, res) => {
  res.json({
    status: "ONLINE",
    name: "RITH API SERVER",
    version: "1.0.0"
  });
});

app.post("/api/admin/login", async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({
      success: false,
      message: "Username and password are required"
    });
  }

  const adminUsername = process.env.ADMIN_USERNAME;
  const adminPasswordHash = process.env.ADMIN_PASSWORD_HASH;
  const jwtSecret = process.env.JWT_SECRET;

  if (!adminUsername || !adminPasswordHash || !jwtSecret) {
    return res.status(503).json({
      success: false,
      message: "Admin login is not configured"
    });
  }

  const validUsername = username === adminUsername;
  const validPassword = await bcrypt.compare(
    password,
    adminPasswordHash
  );

  if (!validUsername || !validPassword) {
    return res.status(401).json({
      success: false,
      message: "Invalid login details"
    });
  }

  const token = jwt.sign(
    { role: "admin" },
    jwtSecret,
    { expiresIn: "1h" }
  );

  res.json({
    success: true,
    token,
    message: "Login successful"
  });
});

app.listen(PORT, () => {
  console.log(`RITH API running on port ${PORT}`);
});
