const jwt = require('jsonwebtoken');

// Middleware para verificar el token JWT
exports.verifyToken = (req, res, next) => {
  // Obtener el token desde los encabezados de la solicitud
  const token = req.header('Authorization')?.replace('Bearer ', '');

  if (!token) {
    // Si no se proporciona un token, devolver un error de autorización
    return res.status(401).json({ message: 'Acceso denegado. No se proporcionó un token.' });
  }

  try {
    // Verificar el token y extraer los datos del usuario
    const verified = jwt.verify(token, process.env.JWT_SECRET);

    // Adjuntar los datos del usuario al objeto de solicitud para usarlo en las rutas
    req.user = verified;

    // Continuar con la siguiente función de middleware o la ruta
    next();
  } catch (err) {
    // Si el token no es válido o ha expirado, devolver un error
    return res.status(400).json({ message: 'Token no válido.' });
  }
};
// Middleware para proteger rutas
function ensureAuthenticated(req, res, next) {
  console.log('Verificando autenticación del usuario:', req.isAuthenticated());
  if (req.isAuthenticated()) {
    return next();  // El usuario está autenticado, continuar
  }
  // Redirigir a la página de login o devolver error si no está autenticado
  res.status(401).json({ message: 'No autorizado, por favor inicia sesión' });
}

// Ruta protegida para obtener los datos del perfil
app.get('/profile-data', ensureAuthenticated, (req, res) => {
  // Devolver los datos del perfil del usuario autenticado
  const user = req.user;  // req.user contiene la información del usuario autenticado
  res.json({
    userName: user.username,
    email: user.email,
    profilePic: user.profilePic,
    status: user.status,
    bio: user.bio
  });
});
