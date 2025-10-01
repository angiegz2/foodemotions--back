const express = require('express');
const passport = require('passport');
const { body } = require('express-validator');
const { registerUser, loginUser } = require('../controllers/authController');
const { ensureAuthenticated } = require('../middleware/authMiddleware'); 

const router = express.Router();


// Registro manual
router.post('/signup', 
  [
    body('email').isEmail().withMessage('Debe ser un correo válido'),
    body('password').isLength({ min: 6 }).withMessage('La contraseña debe tener al menos 6 caracteres')
  ],
  registerUser
);

// Login manual
router.post('/login', 
  [
    body('email').isEmail().withMessage('Debe ser un correo válido'),
    body('password').exists().withMessage('La contraseña es requerida')
  ],
  loginUser
);

// Login con Google
router.get('/google', passport.authenticate('google', { scope: ['profile', 'email'] }));

// Callback de Google
router.get('/google/callback', 
  passport.authenticate('google', { failureRedirect: '/login' }),
  (req, res) => {
    res.redirect('http://localhost:4321/Profile'); 
  }
);

// Logout
router.post('/logout', (req, res, next) => {
  req.logout((err) => {
    if (err) return next(err);
    res.json({ message: 'Sesión cerrada correctamente' });
  });
});

// Ejemplo de ruta protegida
router.get('/protected', ensureAuthenticated, (req, res) => {
  res.json({ message: 'Acceso concedido a una ruta protegida' });
});

module.exports = router;
