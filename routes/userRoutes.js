// routes/userRoutes.js - User Management Routes
const express = require('express');
const { body } = require('express-validator');
const {
  getUsers,
  getUser,
  createUser,
  updateUser,
  deleteUser,
  updateUserRole,
  toggleUserStatus,
  getUserActivity,
  resetUserPassword
} = require('../controllers/userController');

const { 
  protect, 
  authorize, 
  requirePermission,
  auditLog,
  ownerOrAdmin 
} = require('../middleware/authMiddleware');

const router = express.Router();

// Validation rules
const createUserValidation = [
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
    .withMessage('Password must be at least 6 characters long'),
  body('firstName')
    .isLength({ min: 1, max: 50 })
    .withMessage('First name is required and must be less than 50 characters')
    .trim(),
  body('lastName')
    .isLength({ min: 1, max: 50 })
    .withMessage('Last name is required and must be less than 50 characters')
    .trim(),
  body('role')
    .isIn(['admin', 'soc_manager', 'senior_analyst', 'soc_analyst', 'readonly'])
    .withMessage('Invalid role specified')
];

const updateUserValidation = [
  body('email')
    .optional()
    .isEmail()
    .normalizeEmail()
    .withMessage('Please provide a valid email'),
  body('firstName')
    .optional()
    .isLength({ min: 1, max: 50 })
    .withMessage('First name must be less than 50 characters')
    .trim(),
  body('lastName')
    .optional()
    .isLength({ min: 1, max: 50 })
    .withMessage('Last name must be less than 50 characters')
    .trim()
];

// User management routes (Admin/SOC Manager only)
router.route('/')
  .get(getUsers)
  .post(protect, authorize('admin', 'soc_manager'), createUserValidation, auditLog('USER_CREATE'), createUser);

// Individual user routes
router.route('/:id')
  .get(protect, ownerOrAdmin, getUser)
  .put(protect, ownerOrAdmin, updateUserValidation, auditLog('USER_UPDATE'), updateUser)
  .delete(protect, authorize('admin'), auditLog('USER_DELETE'), deleteUser);

// Admin-only user management
router.put('/:id/role', protect, authorize('admin'), auditLog('USER_ROLE_UPDATE'), updateUserRole);
router.put('/:id/status', protect, authorize('admin', 'soc_manager'), auditLog('USER_STATUS_TOGGLE'), toggleUserStatus);
router.post('/:id/reset-password', protect, authorize('admin', 'soc_manager'), auditLog('USER_PASSWORD_RESET'), resetUserPassword);

// User activity tracking
router.get('/:id/activity', protect, ownerOrAdmin, getUserActivity);

module.exports = router;