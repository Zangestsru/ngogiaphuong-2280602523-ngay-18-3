const jwt = require('jsonwebtoken');
const fs = require('fs');
const path = require('path');

const PRIVATE_KEY = fs.readFileSync(path.join(__dirname, '..', 'private.pem'), 'utf8');
const PUBLIC_KEY = fs.readFileSync(path.join(__dirname, '..', 'public.pem'), 'utf8');

const JWT_OPTIONS = {
  algorithm: 'RS256',
  expiresIn: '1h'
};

/**
 * Tạo JWT token sử dụng RS256 với RSA 2048-bit private key
 * @param {Object} payload - Dữ liệu cần mã hóa trong token
 * @returns {string} JWT token
 */
function generateToken(payload) {
  return jwt.sign(payload, PRIVATE_KEY, JWT_OPTIONS);
}

/**
 * Xác thực JWT token sử dụng RS256 với RSA 2048-bit public key
 * @param {string} token - JWT token cần xác thực
 * @returns {Object} Decoded payload
 */
function verifyToken(token) {
  return jwt.verify(token, PUBLIC_KEY, { algorithms: ['RS256'] });
}

/**
 * Middleware xác thực JWT cho các route cần đăng nhập
 * Trích xuất token từ header Authorization: Bearer <token>
 */
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).send({ message: 'Token khong duoc cung cap' });
  }

  try {
    const decoded = verifyToken(token);
    req.user = decoded;
    next();
  } catch (error) {
    return res.status(403).send({ message: 'Token khong hop le hoac da het han' });
  }
}

module.exports = {
  generateToken,
  verifyToken,
  authenticateToken
};
