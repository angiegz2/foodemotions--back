const jwt = require('jsonwebtoken');

/**
 * Middleware para verificar un token JWT (útil si implementas auth con JWT).
 */
exports.verifyToken = (req, res, next) => {
  const token = req.header('Authorization')?.replace('Bearer ', '');
  if (!token) {
    return res.status(401).json({ message: 'Acceso denegado. No se proporcionó un token.' });
  }

  try {
    const verified = jwt.verify(token, process.env.JWT_SECRET);
    req.user = verified; // adjunta los datos del usuario al request
    next();
  } catch (err) {
    return res.status(400).json({ message: 'Token no válido.' });
  }
};

/**
 * Middleware para proteger rutas con sesiones (Passport).
 */
exports.ensureAuthenticated = (req, res, next) => {
  if (req.isAuthenticated && req.isAuthenticated()) {
    return next();
  }
  return res.status(401).json({ message: 'No autorizado, por favor inicia sesión' });
};
