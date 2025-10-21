// middleware/authMiddleware.js
import jwt from "jsonwebtoken";

/**
 * ✅ Middleware para verificar el token JWT en rutas protegidas
 * (para Users registrados manualmente).
 */
export function verifyToken(req, res, next) {
  const authHeader = req.headers.authorization;
  const token = authHeader?.split(" ")[1];

  if (!token) {
    return res.status(401).json({ message: "Acceso denegado. Token no proporcionado." });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded; // guarda los datos del User en la request
    next();
  } catch (err) {
    console.error("❌ Error al verificar token:", err);
    return res.status(403).json({ message: "Token inválido o expirado." });
  }
}

/**
 * ✅ Middleware para proteger rutas con sesiones de Passport
 * (para Users autenticados con Google OAuth).
 */
export function ensureAuthenticated(req, res, next) {
  if (req.isAuthenticated && req.isAuthenticated()) {
    return next();
  }
  return res.status(401).json({ message: "No autorizado, por favor inicia sesión." });
}
