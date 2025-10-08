// ============================================================
// 🔹 Dependencias principales
// ============================================================
const express = require('express');
const session = require('express-session');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const dotenv = require('dotenv');
const cors = require('cors');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const { body, validationResult } = require('express-validator');
const morgan = require('morgan');
const helmet = require('helmet');
const multer = require('multer');
const cloudinary = require('cloudinary').v2;
const { CloudinaryStorage } = require('multer-storage-cloudinary');
const fetch = (...args) => import('node-fetch').then(({ default: fetch }) => fetch(...args));


// ============================================================
// 🔹 Cargar variables de entorno
// ============================================================
dotenv.config();

const app = express();

// ============================================================
// 🔹 Middlewares globales
// ============================================================
app.use(morgan('dev'));
app.use(helmet({ crossOriginResourcePolicy: false }));

app.use(cors({
  origin: process.env.CLIENT_URL || 'http://localhost:4321',
  credentials: true,
}));

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ============================================================
// 🔹 Conexión a MongoDB
// ============================================================
const mongoUri = process.env.MONGODB_URI || 'mongodb://localhost:27017/mi_base_de_datos';
mongoose.connect(mongoUri)
  .then(() => console.log('✅ Conexión exitosa a MongoDB'))
  .catch(err => console.error('❌ Error conectando a MongoDB:', err));

// ============================================================
// 🔹 Configuración de Cloudinary y Multer
// ============================================================

// Cargar configuración de Cloudinary desde .env
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

// Verificar configuración
if (!process.env.CLOUDINARY_API_KEY || !process.env.CLOUDINARY_API_SECRET) {
  console.error('❌ Error: Faltan las variables de entorno de Cloudinary en el archivo .env');
} else {
  console.log('✅ Cloudinary configurado correctamente');
}

// Configurar almacenamiento en Cloudinary
const storage = new CloudinaryStorage({
  cloudinary,
  params: {
    folder: process.env.CLOUDINARY_FOLDER || 'profile_pics',
    allowed_formats: ['jpg', 'jpeg', 'png'],
    transformation: [
      { width: 300, height: 300, crop: 'fill', gravity: 'face' }, // Recorte automático al rostro
    ],
  },
});

// Inicializar multer con ese storage
const upload = multer({ storage });

// ============================================================
// 🔹 Esquemas y modelos de Mongoose
// ============================================================
const usuarioSchema = new mongoose.Schema({
  googleId: String,
  username: String,
  email: { type: String, required: true, unique: true },
  telefono: String,
  password: { type: String },
  profilePic: String,
  bio: String,
  status: { type: String, default: 'Offline' },
  followers: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  following: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
});

const Usuario = mongoose.model('User', usuarioSchema);

const recipeSchema = new mongoose.Schema({
  name: String,
  description: String,
  ingredients: [String],
  steps: [String],
  rating: { type: Number, min: 0, max: 5 },
});

const Recipe = mongoose.model('Recipe', recipeSchema);

// ============================================================
// 🔹 Configuración de sesiones (para Google OAuth)
// ============================================================
app.use(session({
  secret: process.env.SESSION_SECRET || 'change-me-secret',
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
  },
}));

// ============================================================
// 🔹 Configurar Passport (Google OAuth)
// ============================================================
app.use(passport.initialize());
app.use(passport.session());

passport.use(new GoogleStrategy({
  clientID: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  callbackURL: process.env.GOOGLE_CALLBACK_URL || 'http://localhost:3000/auth/google/callback',
},
  async (accessToken, refreshToken, profile, done) => {
    try {
      let user = await Usuario.findOne({ googleId: profile.id });
      if (!user) {
        user = new Usuario({
          googleId: profile.id,
          username: profile.displayName,
          email: profile.emails[0].value,
          profilePic: profile._json.picture,
          bio: '',
          status: 'Online',
        });
        await user.save();
      }
      return done(null, user);
    } catch (err) {
      return done(err, null);
    }
  }
));

passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser(async (id, done) => {
  try {
    const user = await Usuario.findById(id);
    done(null, user);
  } catch (err) {
    done(err, null);
  }
});

// ============================================================
// 🔹 Middleware de autenticación
// ============================================================
function ensureAuthenticated(req, res, next) {
  if (req.isAuthenticated()) return next();
  return res.status(401).json({ message: 'No autorizado, por favor inicia sesión' });
}

// ============================================================
// 🔹 Rutas de autenticación
// ============================================================
app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));

app.get('/auth/google/callback',
  passport.authenticate('google', { failureRedirect: '/login' }),
  (req, res) => res.redirect(`${process.env.CLIENT_URL}/Profile`)
);

// 🔹 Verificar estado de sesión
app.get('/auth/status', (req, res) => {
  res.json({ loggedIn: !!req.user });
});

app.post('/logout', (req, res) => {
  req.logout(err => {
    if (err) return res.status(500).json({ message: 'Error cerrando sesión' });
    res.sendStatus(200);
  });
});

// ============================================================
// 🔹 Perfil de usuario autenticado
// ============================================================
app.get('/profile-data', ensureAuthenticated, async (req, res) => {
  try {
    const user = await Usuario.findById(req.user.id)
      .populate('followers', 'username profilePic')
      .populate('following', 'username profilePic');
    if (!user) return res.status(404).json({ message: 'Usuario no encontrado' });

    res.json({
      profilePic: user.profilePic || null,
      userName: user.username || '',
      email: user.email || '',
      phone: user.telefono || '',
      status: user.status || 'Offline',
      bio: user.bio || '',
      followers: user.followers || [],
      following: user.following || [],
    });
  } catch (err) {
    console.error('Error obteniendo perfil:', err);
    res.status(500).json({ message: 'Error obteniendo perfil' });
  }
});

// ============================================================
// 🔹 Actualizar información del perfil
// ============================================================
app.put('/profile/update', ensureAuthenticated, async (req, res) => {
  try {
    const { username, telefono } = req.body;
    const user = await Usuario.findByIdAndUpdate(
      req.user.id,
      { username, telefono },
      { new: true }
    );
    res.json({ message: 'Perfil actualizado correctamente', user });
  } catch (error) {
    console.error('Error actualizando perfil:', error);
    res.status(500).json({ message: 'Error al actualizar el perfil.' });
  }
});

// ============================================================
// 🔹 Actualizar estado
// ============================================================
app.put('/profile/status', ensureAuthenticated, async (req, res) => {
  try {
    const { status } = req.body;
    const user = await Usuario.findByIdAndUpdate(req.user.id, { status }, { new: true });
    res.json({ message: 'Estado actualizado correctamente', status: user.status });
  } catch (error) {
    console.error('Error actualizando estado:', error);
    res.status(500).json({ message: 'Error al actualizar el estado.' });
  }
});

// ============================================================
// 🔹 Actualizar biografía
// ============================================================
app.put('/profile/bio', ensureAuthenticated, async (req, res) => {
  try {
    const { bio } = req.body;
    const user = await Usuario.findByIdAndUpdate(req.user.id, { bio }, { new: true });
    res.json({ message: 'Biografía actualizada correctamente', bio: user.bio });
  } catch (error) {
    console.error('Error actualizando biografía:', error);
    res.status(500).json({ message: 'Error al actualizar biografía.' });
  }
});

// ============================================================
// 🔹 Subir o cambiar foto de perfil (Cloudinary)
// ============================================================
app.post('/profile/upload', upload.single('profilePic'), async (req, res) => {
  try {
    // Verificamos autenticación
    if (!req.user) {
      return res.status(401).json({ message: 'No autorizado. Inicia sesión.' });
    }

    // Si no hay archivo
    if (!req.file || !req.file.path) {
      return res.status(400).json({ message: 'No se recibió ninguna imagen.' });
    }

    // ✅ Usar el enlace público de Cloudinary
    const imageUrl = req.file.path || req.file.secure_url;

    // ✅ Actualizar el usuario autenticado
    const updatedUser = await Usuario.findByIdAndUpdate(
      req.user.id,
      { profilePic: imageUrl },
      { new: true }
    );

    if (!updatedUser) {
      return res.status(404).json({ message: 'Usuario no encontrado.' });
    }

    console.log('✅ Foto de perfil actualizada en la BD:', updatedUser.profilePic);

    res.json({
      message: 'Foto de perfil actualizada correctamente.',
      profilePic: updatedUser.profilePic,
    });
  } catch (error) {
    console.error('❌ Error al subir imagen:', error);
    res.status(500).json({ message: 'Error al subir la imagen.' });
  }
});

// ============================================================
// 🔹 Seguir / dejar de seguir usuarios
// ============================================================
app.post('/profile/follow/:id', ensureAuthenticated, async (req, res) => {
  try {
    const userToFollow = await Usuario.findById(req.params.id);
    const currentUser = await Usuario.findById(req.user.id);
    if (!userToFollow) return res.status(404).json({ message: 'Usuario no encontrado.' });
    if (userToFollow.id === currentUser.id) return res.status(400).json({ message: 'No puedes seguirte a ti mismo.' });

    if (!currentUser.following.includes(userToFollow.id)) {
      currentUser.following.push(userToFollow.id);
      userToFollow.followers.push(currentUser.id);
      await currentUser.save();
      await userToFollow.save();
    }
    res.json({ message: `Ahora sigues a ${userToFollow.username}` });
  } catch (error) {
    console.error('Error al seguir usuario:', error);
    res.status(500).json({ message: 'Error al seguir usuario.' });
  }
});

app.post('/profile/unfollow/:id', ensureAuthenticated, async (req, res) => {
  try {
    const userToUnfollow = await Usuario.findById(req.params.id);
    const currentUser = await Usuario.findById(req.user.id);
    if (!userToUnfollow) return res.status(404).json({ message: 'Usuario no encontrado.' });

    currentUser.following = currentUser.following.filter(u => u.toString() !== userToUnfollow.id);
    userToUnfollow.followers = userToUnfollow.followers.filter(u => u.toString() !== currentUser.id);

    await currentUser.save();
    await userToUnfollow.save();
    res.json({ message: `Has dejado de seguir a ${userToUnfollow.username}` });
  } catch (error) {
    console.error('Error al dejar de seguir usuario:', error);
    res.status(500).json({ message: 'Error al dejar de seguir usuario.' });
  }
});

// ============================================================
// 🔹 Recetas
// ============================================================
app.get('/recipes', async (req, res) => {
  try {
    const recipes = await Recipe.find();
    res.json(recipes);
  } catch (err) {
    res.status(500).json({ message: 'Error obteniendo recetas', error: err.message });
  }
});

app.post('/recipes', async (req, res) => {
  try {
    const { name, description, ingredients, steps, rating } = req.body;
    if (!name || !description || !ingredients || !steps)
      return res.status(400).json({ message: 'Todos los campos son obligatorios.' });

    const newRecipe = new Recipe({ name, description, ingredients, steps, rating });
    await newRecipe.save();
    res.status(201).json({ message: 'Receta creada', recipe: newRecipe });
  } catch (err) {
    res.status(500).json({ message: 'Error creando receta', error: err.message });
  }
});

// ============================================================
// 🔹 Registro manual
// ============================================================
app.post('/sign-up', [
  body('username').notEmpty().withMessage('El nombre de usuario es obligatorio.'),
  body('email').isEmail().withMessage('Correo electrónico inválido.'),
  body('telefono').notEmpty().withMessage('El teléfono es obligatorio.'),
  body('password').isLength({ min: 6 }).withMessage('Mínimo 6 caracteres.'),
  body('confirmPassword').custom((value, { req }) => {
    if (value !== req.body.password) throw new Error('Las contraseñas no coinciden.');
    return true;
  }),
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

  try {
    const { username, email, telefono, password } = req.body;
    const existingUser = await Usuario.findOne({ email });
    if (existingUser) return res.status(400).json({ message: 'El correo ya está registrado.' });

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new Usuario({
      username,
      email,
      telefono,
      password: hashedPassword,
      status: 'Offline',
    });

    await newUser.save();
    res.status(201).json({ message: 'Usuario registrado correctamente.' });
  } catch (err) {
    console.error('Error registrando usuario:', err);
    res.status(500).json({ message: 'Error registrando usuario.' });
  }
});

// ============================================================
// 🔹 Login manual (actualizado)
// ============================================================
app.post('/login', async (req, res) => {
  const { email, password } = req.body;

  try {
    const user = await Usuario.findOne({ email });
    if (!user) {
      return res.status(400).json({ message: 'Usuario no encontrado.' });
    }

    const isMatch = await bcrypt.compare(password, user.password || '');
    if (!isMatch) {
      return res.status(400).json({ message: 'Contraseña incorrecta.' });
    }

    // Inicia sesión con Passport
    req.login(user, (err) => {
      if (err) {
        console.error('Error iniciando sesión:', err);
        return res.status(500).json({ message: 'Error al iniciar sesión.' });
      }

      // ✅ Enviar redirección manual al frontend
      return res.status(200).json({
        message: 'Inicio de sesión exitoso.',
        redirectUrl: `${process.env.CLIENT_URL}/Profile`, // Redirige al perfil del usuario
        user: {
          username: user.username,
          email: user.email,
          profilePic: user.profilePic,
        },
      });
    });
  } catch (err) {
    console.error('Error en login:', err);
    res.status(500).json({ message: 'Error al iniciar sesión.' });
  }
});

// ============================================================
// 🔹 🔥 RUTAS Chat Roy con Hugging Face (corregidas)
// ============================================================

const HF_API_URL = "https://api-inference.huggingface.co/models/facebook/blenderbot-400M-distill";
const HF_TOKEN = process.env.HF_API_TOKEN; 

// GET informativo (para que no salga "Cannot GET")
app.get("/api/chat", (req, res) => {
  res.status(200).send("✅ Usa POST /api/chat con JSON { message: '...' }");
});

// POST real del chatbot
app.post("/api/chat", async (req, res) => {
  try {
    if (!HF_TOKEN) {
      return res.status(500).json({ error: "Falta HF_API_TOKEN en .env" });
    }

    const { message } = req.body || {};
    if (typeof message !== "string" || !message.trim()) {
      return res.status(400).json({ error: "Mensaje vacío" });
    }

    const response = await fetch(HF_API_URL, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${HF_TOKEN}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ inputs: message }),
    });

    // La Inference API a veces devuelve 503 mientras carga el modelo
    if (!response.ok) {
      const text = await response.text();
      return res.status(response.status).json({ error: "HF error", details: text });
    }

    const data = await response.json();
// Primero intenta usar data[0].generated_text
let reply = null;
if (Array.isArray(data) && data.length > 0 && typeof data[0].generated_text === "string") {
  reply = data[0].generated_text;
} else if (typeof data.generated_text === "string") {
  reply = data.generated_text;
} else if (typeof data[0]?.generated_text === "string") {
  reply = data[0].generated_text;
} else {
  // Trata de otros campos posibles
  if (data[0]?.generated_text) reply = data[0].generated_text;
  else if (data.generated_text) reply = data.generated_text;
}
// Si no encontró respuesta válida
if (!reply) {
  reply = "Lo siento, no pude entender eso. ¿Podrías reformularlo?";
}
res.json({ reply });

  } catch (err) {
    console.error("❌ Error en /api/chat:", err);
    return res.status(500).json({ error: "Error conectando con Hugging Face API" });
  }
});

// ============================================================
// 🔹 Iniciar servidor
// ============================================================
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 Servidor corriendo en http://localhost:${PORT}`);
});