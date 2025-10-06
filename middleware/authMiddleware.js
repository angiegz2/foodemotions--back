const jwt = require('jsonwebtoken');

/**
 * Middleware para verificar el token JWT en peticiones protegidas
 * (para usuarios registrados manualmente).
 */
exports.verifyToken = (req, res, next) => {
  // Buscar el token en los encabezados
  const authHeader = req.headers.authorization;
  const token = authHeader?.split(' ')[1];

  if (!token) {
    return res.status(401).json({ message: 'Acceso denegado. Token no proporcionado.' });
  }

  try {
    // Verificar y decodificar token
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded; // guardar datos del usuario en la request
    next();
  } catch (err) {
    console.error('❌ Error al verificar token:', err);
    return res.status(403).json({ message: 'Token inválido o expirado.' });
  }
};

/**
 * Middleware para proteger rutas basadas en sesiones de Passport
 * (para usuarios autenticados con Google OAuth).
 */
exports.ensureAuthenticated = (req, res, next) => {
  if (req.isAuthenticated && req.isAuthenticated()) {
    return next();
  }
  return res.status(401).json({ message: 'No autorizado, por favor inicia sesión.' });
};
