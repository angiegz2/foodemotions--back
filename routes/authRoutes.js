const express = require('express');
const { registerUser, loginUser } = require('../controllers/authController');
const { body } = require('express-validator');
const { isAuthenticated } = require('../middlewares/authMiddleware'); // Middleware de autenticación
const router = express.Router();

// Validaciones de datos de entrada
router.post('/signup', 
  [
    body('email').isEmail().withMessage('Debe ser un correo válido'),
    body('password').isLength({ min: 6 }).withMessage('La contraseña debe tener al menos 6 caracteres')
  ],
  registerUser
);

router.post('/login', 
  [
    body('email').isEmail().withMessage('Debe ser un correo válido'),
    body('password').exists().withMessage('La contraseña es requerida')
  ],
  loginUser
);

// Ejemplo de una ruta protegida
router.get('/protected', isAuthenticated, (req, res) => {
  res.json({ message: 'Acceso concedido a una ruta protegida' });
});

module.exports = router;
