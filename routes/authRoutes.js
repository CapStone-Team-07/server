// routes/authRoutes.js - Authentication Routes
const express = require('express');
const { body } = require('express-validator');
const {
  register,
  login,
  getMe,
  forgotPassword,
  resetPassword,
  updateDetails,
  updatePassword,
  updatePreferences,
  logout,
  verifyToken
} = require('../controllers/authController');

const { protect, auditLog } = require('../middleware/authMiddleware');

const router = express.Router();

// Validation rules
const registerValidation = [
  body('username')
    .isLength({ min: 3, max: 30 })
    .withMessage('Username must be between 3 and 30 characters')
    .matches(/^[a-zA-Z0-9_]+$/)
    .withMessage('Username can only contain letters, numbers, and underscores'),
  body('email')
    .isEmail()
    .normalizeEmail()
    .withMessage('Please provide a valid email'),
  body('password')
    .isLength({ min: 6 })
    .withMessage('Password must be at least 6 characters long')
    .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/)
    .withMessage('Password must contain at least one uppercase letter, one lowercase letter, and one number'),
  body('firstName')
    .isLength({ min: 1, max: 50 })
    .withMessage('First name is required and must be less than 50 characters')
    .trim(),
  body('lastName')
    .isLength({ min: 1, max: 50 })
    .withMessage('Last name is required and must be less than 50 characters')
    .trim(),
  body('role')
    .optional()
    .isIn(['admin', 'soc_manager', 'senior_analyst', 'soc_analyst', 'readonly'])
    .withMessage('Invalid role specified')
];

const loginValidation = [
  body('username')
    .notEmpty()
    .withMessage('Username or email is required'),
  body('password')
    .notEmpty()
    .withMessage('Password is required')
];

// Public routes
router.post('/register', registerValidation, auditLog('USER_REGISTER'), register);
router.post('/login', loginValidation, auditLog('USER_LOGIN'), login);
router.post('/forgotpassword', auditLog('PASSWORD_FORGOT'), forgotPassword);
router.put('/resetpassword/:resettoken', auditLog('PASSWORD_RESET'), resetPassword);
router.post('/verify', verifyToken);

// Protected routes
router.get('/me', protect, getMe);
router.put('/updatedetails', protect, auditLog('USER_UPDATE_DETAILS'), updateDetails);
router.put('/updatepassword', protect, auditLog('PASSWORD_UPDATE'), updatePassword);
router.put('/preferences', protect, auditLog('USER_UPDATE_PREFERENCES'), updatePreferences);
router.get('/logout', protect, auditLog('USER_LOGOUT'), logout);

module.exports = router;