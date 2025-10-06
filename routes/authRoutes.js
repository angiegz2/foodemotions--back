const express = require('express');
const passport = require('passport');
const { body } = require('express-validator');
const { registerUser, loginUser } = require('../controllers/authController');
const { verifyToken, ensureAuthenticated } = require('../middleware/authMiddleware');
const User = require('../models/User');

const router = express.Router();

/* ============================================================
   🟢 REGISTRO MANUAL
   ============================================================ */
router.post(
  '/sign-up',
  [
    body('email').isEmail().withMessage('Debe ser un correo válido'),
    body('password').isLength({ min: 6 }).withMessage('La contraseña debe tener al menos 6 caracteres'),
  ],
  registerUser
);

/* ============================================================
   🟢 LOGIN MANUAL
   ============================================================ */
router.post(
  '/login',
  [
    body('email').isEmail().withMessage('Debe ser un correo válido'),
    body('password').exists().withMessage('La contraseña es requerida'),
  ],
  loginUser
);

/* ============================================================
   🟢 LOGIN CON GOOGLE (OAUTH 2.0)
   ============================================================ */
router.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));

router.get(
  '/auth/google/callback',
  passport.authenticate('google', { failureRedirect: '/login' }),
  (req, res) => {
    res.redirect('http://localhost:4321/Profile');
  }
);

/* ============================================================
   🟢 PERFIL DE USUARIO (JWT y GOOGLE)
   ============================================================ */
// Perfil (login manual)
router.get('/profile', verifyToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.id)
      .select('-password')
      .populate('followers', 'username')
      .populate('likes', 'username');
    if (!user) return res.status(404).json({ message: 'Usuario no encontrado' });
    res.json(user);
  } catch (error) {
    console.error('Error al obtener perfil:', error);
    res.status(500).json({ message: 'Error al obtener perfil' });
  }
});

// Perfil (Google)
router.get('/google/profile', ensureAuthenticated, (req, res) => {
  res.json(req.user);
});

/* ============================================================
   🟢 ACTUALIZAR ESTADO Y BIOGRAFÍA
   ============================================================ */
router.put('/profile/status', verifyToken, async (req, res) => {
  try {
    const { status } = req.body;
    const user = await User.findByIdAndUpdate(req.user.id, { status }, { new: true });
    res.json({ message: 'Estado actualizado', status: user.status });
  } catch (err) {
    console.error('Error al actualizar estado:', err);
    res.status(500).json({ message: 'Error al actualizar estado' });
  }
});

router.put('/profile/bio', verifyToken, async (req, res) => {
  try {
    const { bio } = req.body;
    const user = await User.findByIdAndUpdate(req.user.id, { bio }, { new: true });
    res.json({ message: 'Biografía actualizada', bio: user.bio });
  } catch (err) {
    console.error('Error al actualizar biografía:', err);
    res.status(500).json({ message: 'Error al actualizar biografía' });
  }
});

/* ============================================================
   🟢 SEGUIDORES Y LIKES
   ============================================================ */
// Obtener seguidores
router.get('/profile/followers', verifyToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).populate('followers', 'username');
    res.json(user.followers);
  } catch (err) {
    console.error('Error al obtener seguidores:', err);
    res.status(500).json({ message: 'Error al obtener seguidores' });
  }
});

// Obtener likes
router.get('/profile/likes', verifyToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).populate('likes', 'username');
    res.json(user.likes);
  } catch (err) {
    console.error('Error al obtener likes:', err);
    res.status(500).json({ message: 'Error al obtener likes' });
  }
});

/* ============================================================
   🟢 LOGOUT
   ============================================================ */
router.post('/logout', (req, res, next) => {
  req.logout(err => {
    if (err) return next(err);
    res.json({ message: 'Sesión cerrada correctamente' });
  });
});

module.exports = router;



