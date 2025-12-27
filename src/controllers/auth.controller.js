const pool = require("../config/db");
const crypto = require("crypto");
const jwt = require("jsonwebtoken");

const { hashPassword, comparePassword } = require("../utils/hash");
const {
  generateAccessToken,
  generateRefreshToken,
  rotateRefreshToken,
} = require("../services/token.service");

/* =========================
   REGISTER
========================= */
exports.register = async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password)
      return res.status(400).json({ message: "Email and password required" });

    const exists = await pool.query(
      "SELECT id FROM users WHERE email=$1",
      [email]
    );

    if (exists.rows.length)
      return res.status(409).json({ message: "Email already registered" });

    const hashedPassword = await hashPassword(password);
    const verificationToken = crypto.randomBytes(32).toString("hex");

    await pool.query(
      `
      INSERT INTO users (
        email,
        password,
        is_verified,
        email_verification_token,
        email_verification_expires
      )
      VALUES ($1, $2, false, $3, NOW() + INTERVAL '24 hours')
      `,
      [email, hashedPassword, verificationToken]
    );

    // dev-only email simulation
    console.log(
      `Verify email → http://localhost:5000/api/auth/verify-email?token=${verificationToken}`
    );

    res.status(201).json({
      message: "Registration successful. Please verify your email.",
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
};

/* =========================
   VERIFY EMAIL
========================= */
exports.verifyEmail = async (req, res) => {
  try {
    const { token } = req.query;

    if (!token)
      return res.status(400).json({ message: "Invalid verification token" });

    const result = await pool.query(
      `
      UPDATE users
      SET is_verified = true,
          email_verification_token = NULL,
          email_verification_expires = NULL
      WHERE email_verification_token = $1
        AND email_verification_expires > NOW()
      RETURNING id
      `,
      [token]
    );

    if (!result.rows.length)
      return res.status(400).json({ message: "Token expired or invalid" });

    res.json({ message: "Email verified successfully" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
};

/* =========================
   LOGIN
========================= */
exports.login = async (req, res) => {
  try {
    const { email, password } = req.body;

    const result = await pool.query(
      "SELECT * FROM users WHERE email=$1",
      [email]
    );

    if (!result.rows.length)
      return res.status(401).json({ message: "Invalid credentials" });

    const user = result.rows[0];

    if (!user.is_verified)
      return res.status(403).json({ message: "Please verify your email first" });

    const valid = await comparePassword(password, user.password);
    if (!valid)
      return res.status(401).json({ message: "Invalid credentials" });

    const accessToken = generateAccessToken({
      id: user.id,
      role: user.role,
    });

    const refreshToken = generateRefreshToken({
      id: user.id,
    });

    await pool.query(
      `
      INSERT INTO refresh_tokens (user_id, token, expires_at)
      VALUES ($1, $2, NOW() + INTERVAL '7 days')
      `,
      [user.id, refreshToken]
    );

    res.json({ accessToken, refreshToken });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
};

/* =========================
   REFRESH TOKEN (ROTATION)
========================= */
exports.refreshToken = async (req, res) => {
  try {
    const { token } = req.body;

    if (!token)
      return res.status(400).json({ message: "Refresh token required" });

    const newRefreshToken = await rotateRefreshToken(token, pool);

    const decoded = jwt.verify(
      newRefreshToken,
      process.env.JWT_REFRESH_SECRET
    );

    const accessToken = generateAccessToken({ id: decoded.id });

    res.json({
      accessToken,
      refreshToken: newRefreshToken,
    });
  } catch (err) {
    console.error(err);
    res.status(401).json({ message: "Invalid refresh token" });
  }
};
