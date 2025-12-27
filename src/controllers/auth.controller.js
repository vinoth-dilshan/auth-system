const pool = require("../config/db");
const { hashPassword, comparePassword } = require("../utils/hash");
const {
  generateAccessToken,
  generateRefreshToken,
} = require("../services/token.service");

exports.register = async (req, res) => {
  const { email, password } = req.body;

  const hashed = await hashPassword(password);

  const user = await pool.query(
    "INSERT INTO users(email, password) VALUES($1, $2) RETURNING *",
    [email, hashed]
  );

  res.status(201).json({ message: "User created" });
};

exports.login = async (req, res) => {
  const { email, password } = req.body;

  const result = await pool.query("SELECT * FROM users WHERE email=$1", [email]);
  if (!result.rows.length) return res.status(401).json({ message: "Invalid credentials" });

  const user = result.rows[0];
  const valid = await comparePassword(password, user.password);
  if (!valid) return res.status(401).json({ message: "Invalid credentials" });

  const accessToken = generateAccessToken(user);
  const refreshToken = generateRefreshToken(user);

  await pool.query(
    "INSERT INTO refresh_tokens(user_id, token, expires_at) VALUES($1,$2, NOW() + INTERVAL '7 days')",
    [user.id, refreshToken]
  );

  res.json({ accessToken, refreshToken });
};
