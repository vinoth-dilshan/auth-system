const jwt = require("jsonwebtoken");

const generateAccessToken = (user) => {
  return jwt.sign(
    { id: user.id, role: user.role },
    process.env.JWT_ACCESS_SECRET,
    { expiresIn: process.env.ACCESS_TOKEN_EXPIRY }
  );
};

const generateRefreshToken = (user) => {
  return jwt.sign(
    { id: user.id },
    process.env.JWT_REFRESH_SECRET,
    { expiresIn: process.env.REFRESH_TOKEN_EXPIRY }
  );
};

// Verify refresh token and rotate
const rotateRefreshToken = async (oldToken, pool) => {
  const decoded = jwt.verify(oldToken, process.env.JWT_REFRESH_SECRET);

  // Check if token exists and not revoked
  const res = await pool.query(
    "SELECT * FROM refresh_tokens WHERE token=$1 AND revoked=false",
    [oldToken]
  );
  if (!res.rows.length) throw new Error("Invalid refresh token");

  const userId = res.rows[0].user_id;

  // Revoke old token and add replaced_by
  const newToken = generateRefreshToken({ id: userId });
  await pool.query(
    "UPDATE refresh_tokens SET revoked=true, replaced_by=$1 WHERE token=$2",
    [newToken, oldToken]
  );

  // Store new token in DB
  await pool.query(
    "INSERT INTO refresh_tokens(user_id, token, expires_at) VALUES($1, $2, NOW() + INTERVAL '7 days')",
    [userId, newToken]
  );

  return newToken;
};

module.exports = { generateAccessToken, generateRefreshToken, rotateRefreshToken };
