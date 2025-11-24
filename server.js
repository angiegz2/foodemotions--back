import express from 'express';
import session from 'express-session';
import passport from 'passport';
import { Strategy as GoogleStrategy } from 'passport-google-oauth20';
import dotenv from 'dotenv';
import cors from 'cors';
import mongoose from 'mongoose';
import bcrypt from 'bcrypt';
import { body, validationResult } from 'express-validator';
import morgan from 'morgan';
import helmet from 'helmet';
import multer from 'multer';
import cloudinary from 'cloudinary';
import { CloudinaryStorage } from 'multer-storage-cloudinary';
import { pipeline, env } from "@xenova/transformers";
import fs from "fs";
import path from "path";
import http from 'http';
import { Server as SocketIOServer } from 'socket.io';
import twilio from 'twilio';
import nodemailer from 'nodemailer';

dotenv.config();
const app = express();

if (process.env.TRUST_PROXY === '1') {
  app.set('trust proxy', 1);
}

app.use(morgan('dev'));
app.use(helmet({ crossOriginResourcePolicy: false }));

app.use(cors({
  origin: process.env.CLIENT_URL || 'http://localhost:4321',
  credentials: true,
}));

app.use(express.json({ limit: '2mb' }));
app.use(express.urlencoded({ extended: true }));

// ============================================================
// 🧩 CONEXIÓN A MONGODB
// ============================================================
const mongoUri = process.env.MONGODB_URI || 'mongodb://localhost:27017/mi_base_de_datos';
mongoose.connect(mongoUri)
  .then(() => console.log('✅ Conexión exitosa a MongoDB'))
  .catch(err => console.error('❌ Error conectando a MongoDB:', err));

// ============================================================
// ☁️ CONFIGURACIÓN CLOUDINARY
// ============================================================
cloudinary.v2.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

if (!process.env.CLOUDINARY_API_KEY || !process.env.CLOUDINARY_API_SECRET) {
  console.error('❌ Faltan variables de entorno de Cloudinary');
} else {
  console.log('✅ Cloudinary configurado correctamente');
}

const storage = new CloudinaryStorage({
  cloudinary: cloudinary.v2,
  params: {
    folder: process.env.CLOUDINARY_FOLDER || 'profile_pics',
    allowed_formats: ['jpg', 'jpeg', 'png'],
    transformation: [{ width: 300, height: 300, crop: 'fill', gravity: 'face' }],
  },
});
const upload = multer({ storage });

// Configuración de Cloudinary para backgrounds
const backgroundStorage = new CloudinaryStorage({
  cloudinary: cloudinary.v2,
  params: {
    folder: process.env.CLOUDINARY_FOLDER_BACKGROUNDS || 'backgrounds',
    allowed_formats: ['jpg', 'jpeg', 'png', 'webp'],
    transformation: [{ width: 1920, height: 1080, crop: 'fill' }],
  },
});
const uploadBackground = multer({ storage: backgroundStorage });

const transporter = nodemailer.createTransport({
  service: 'gmail', // o 'outlook', 'yahoo', etc.
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

if (!process.env.TWILIO_SID || !process.env.TWILIO_AUTH || !process.env.TWILIO_PHONE) {
  console.warn('⚠️ Twilio no configurado. SMS deshabilitado.');
}

// ============================================================
// 📦 MODELOS MONGOOSE — FoodEmotions Social + Chat + IA
// ============================================================

const usuarioSchema = new mongoose.Schema({
  googleId: String,
  username: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  telefono: String,
  password: String,
  profilePic: { type: String, default: "" },
  bannerImage: { type: String, default: "" },
  backgroundImage: { type: String, default: "" },
  interests: [String],
  notificationsEnabled: { type: Boolean, default: true },
  preferredLanguage: { type: String, default: 'es' },
  bio: { type: String, default: "" },
  
  // ⭐ ÚNICO CAMBIO RECOMENDADO: validar status
  status: { 
    type: String, 
    enum: ['Online', 'Away', 'Busy', 'Offline'],
    default: "Offline" 
  },

  // ⭐ CAMPOS PARA RECUPERAR CONTRASEÑA
  otpCode: { type: String },         // Código OTP temporal
  otpExpires: { type: Date },        // Expiración del OTP
  
  followers: [{ type: mongoose.Schema.Types.ObjectId, ref: "User" }],
  following: [{ type: mongoose.Schema.Types.ObjectId, ref: "User" }],
  savedPosts: [{ type: mongoose.Schema.Types.ObjectId, ref: "Post" }],
  recipesLiked: [{ type: mongoose.Schema.Types.ObjectId, ref: "Recipe" }],
  isPremium: { type: Boolean, default: false },
}, { timestamps: true });

const Usuario = mongoose.models.User || mongoose.model("User", usuarioSchema);

// ==========================
// 📦 MODELO: Post
// ==========================
const postSchema = new mongoose.Schema({

  // Autor del post
  author: { 
    type: mongoose.Schema.Types.ObjectId, 
    ref: 'User', 
    required: true 
  },

  caption: { type: String, default: '' },
  images: [String],

  likes: [{ 
    type: mongoose.Schema.Types.ObjectId, 
    ref: 'User' 
  }],

  comments: [{
    user: { 
      type: mongoose.Schema.Types.ObjectId, 
      ref: 'User', 
      required: true 
    },
    text: String,
    createdAt: { type: Date, default: Date.now }
  }],

  tags: [String],
  location: String,

  visibility: { 
    type: String, 
    enum: ['public', 'followers', 'private'], 
    default: 'public' 
  },

  // ⚡ NUEVOS CAMPOS CORRECTAMENTE AGREGADOS
  groupId: { 
    type: mongoose.Schema.Types.ObjectId, 
    ref: 'Group',
    default: null 
  },

  edited: { 
    type: Boolean, 
    default: false 
  },

  editedAt: { 
    type: Date 
  }

}, 
{
  timestamps: true   // ⏱ createdAt y updatedAt
});

const Post = mongoose.models.Post || mongoose.model('Post', postSchema);

// Cloudinary + Multer
const postStorage = new CloudinaryStorage({
  cloudinary: cloudinary.v2,
  params: {
    folder: process.env.CLOUDINARY_FOLDER_POSTS || 'posts',
    allowed_formats: ['jpg','jpeg','png','webp'],
    transformation: [{ width: 1280, height: 1280, crop: 'limit' }],
  },
});
const uploadPostMedia = multer({ storage: postStorage });

// 💬 COMENTARIOS
const commentSchema = new mongoose.Schema({
  postId: { type: mongoose.Schema.Types.ObjectId, ref: "Post", required: true },
  author: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  text: { type: String, required: true },
  likes: [{ type: mongoose.Schema.Types.ObjectId, ref: "User" }],
}, { timestamps: true });

const Comment = mongoose.models.Comment || mongoose.model("Comment", commentSchema);

// ❤️ LIKE (opcional — si quieres registrar eventos)
const likeSchema = new mongoose.Schema({
  postId: { type: mongoose.Schema.Types.ObjectId, ref: "Post" },
  userId: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
}, { timestamps: true });

const Like = mongoose.models.Like || mongoose.model("Like", likeSchema);

// 🍳 RECETA
const recipeSchema = new mongoose.Schema({
  name: { type: String, required: true },
  description: String,
  ingredients: [String],
  steps: [String],
  rating: { type: Number, min: 0, max: 5 },
  author: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
  image: String,
  likes: [{ type: mongoose.Schema.Types.ObjectId, ref: "User" }],
}, { timestamps: true });

const Recipe = mongoose.models.Recipe || mongoose.model("Recipe", recipeSchema);

// 💬 CHAT (para el chatbot Roy o entre usuarios)
const chatSessionSchema = new mongoose.Schema({
  title: { type: String, default: "Nueva conversación" },
  createdBy: { type: mongoose.Schema.Types.ObjectId, ref: "User", default: null },
  messages: [
    {
      role: { type: String, enum: ["user", "assistant"], required: true },
      text: { type: String, required: true },
      ts: { type: Date, default: Date.now },
    }
  ],
}, { timestamps: true });

const ChatSession = mongoose.models.ChatSession || mongoose.model("ChatSession", chatSessionSchema);

const collectionSchema = new mongoose.Schema({
  name: { type: String, required: true },
  description: { type: String, default: '' },
  owner: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  recipes: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Recipe' }],
  isPublic: { type: Boolean, default: true },
  coverImage: { type: String, default: '' }
}, { timestamps: true });

const Collection = mongoose.models.Collection || mongoose.model('Collection', collectionSchema);

// Modelo de Archivo Personal
const fileSchema = new mongoose.Schema({
  name: { type: String, required: true },
  description: { type: String, default: '' },
  fileUrl: { type: String, required: true },
  fileType: { type: String, required: true }, // pdf, doc, image, etc
  size: { type: Number }, // en bytes
  owner: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  tags: [String],
  isPublic: { type: Boolean, default: false }
}, { timestamps: true });

const File = mongoose.models.File || mongoose.model('File', fileSchema);

// Configuración de Cloudinary para archivos
const fileStorage = new CloudinaryStorage({
  cloudinary: cloudinary.v2,
  params: {
    folder: process.env.CLOUDINARY_FOLDER_FILES || 'user_files',
    allowed_formats: ['jpg', 'jpeg', 'png', 'pdf', 'doc', 'docx', 'txt'],
    resource_type: 'auto'
  },
});
const uploadFile = multer({ storage: fileStorage });

// Modelo de Entrada de Blog
const blogPostSchema = new mongoose.Schema({
  title: { type: String, required: true },
  content: { type: String, required: true },
  excerpt: { type: String, default: '' },
  coverImage: { type: String, default: '' },
  author: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  tags: [String],
  category: { type: String, default: 'General' },
  isPublished: { type: Boolean, default: false },
  publishedAt: { type: Date },
  views: { type: Number, default: 0 },
  likes: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }]
}, { timestamps: true });

const BlogPost = mongoose.models.BlogPost || mongoose.model('BlogPost', blogPostSchema);

// Modelo de Configuración de Perfil
const profileSettingsSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, unique: true },
  privacy: {
    showEmail: { type: Boolean, default: false },
    showPhone: { type: Boolean, default: false },
    allowMessages: { type: String, enum: ['everyone', 'followers', 'none'], default: 'everyone' },
    showActivity: { type: Boolean, default: true },
    showLocation: { type: Boolean, default: false }
  },
  display: {
    showBlog: { type: Boolean, default: true },
    showFiles: { type: Boolean, default: true },
    showCollections: { type: Boolean, default: true },
    showGroups: { type: Boolean, default: true },
    showRecipes: { type: Boolean, default: true },
    profileTheme: { type: String, default: 'default' },
    customColors: {
      primary: { type: String, default: '#3b82f6' },
      secondary: { type: String, default: '#8b5cf6' }
    }
  },
  notifications: {
    emailNotifications: { type: Boolean, default: true },
    pushNotifications: { type: Boolean, default: true },
    notifyOnLike: { type: Boolean, default: true },
    notifyOnComment: { type: Boolean, default: true },
    notifyOnFollow: { type: Boolean, default: true },
    notifyOnMessage: { type: Boolean, default: true }
  },
  content: {
    language: { type: String, default: 'es' },
    contentFilter: { type: Boolean, default: true },
    autoSave: { type: Boolean, default: true }
  }
}, { timestamps: true });

const ProfileSettings = mongoose.models.ProfileSettings || mongoose.model('ProfileSettings', profileSettingsSchema);

// ============================================================
// 🆕 NUEVOS MODELOS: Notifications, Stories y Location
// ============================================================

// 📩 Notificaciones (likes, follows, comments, mensajes)
const notificationSchema = new mongoose.Schema({
  recipient: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  sender: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  type: { 
    type: String, 
    enum: ['like', 'comment', 'follow', 'message', 'system'], 
    required: true 
  },
  message: { type: String },
  read: { type: Boolean, default: false },
  entityId: { type: mongoose.Schema.Types.ObjectId }, // referencia opcional (post, comment, etc.)
}, { timestamps: true });

const Notification = mongoose.models.Notification || mongoose.model('Notification', notificationSchema);


// 📸 Historias de usuarios
const storySchema = new mongoose.Schema({
  author: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  mediaUrl: { type: String, required: true },
  caption: { type: String },
  expiresAt: { type: Date, required: true },
  viewers: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }]
}, { timestamps: true });

const Story = mongoose.models.Story || mongoose.model('Story', storySchema);


// 📍 Ubicación del usuario
const locationSchema = new mongoose.Schema({
  lat: Number,
  lng: Number,
  country: String,
  city: String,
  updatedAt: { type: Date, default: Date.now }
}, { _id: false });

// Añadimos el campo al modelo User
if (!usuarioSchema.paths.location) {
  usuarioSchema.add({ location: locationSchema });
}

// ============================================================
// 🔐 SESIONES Y AUTENTICACIÓN (Passport + Google)
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

app.use(passport.initialize());
app.use(passport.session());

passport.use(new GoogleStrategy({
  clientID: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  callbackURL: process.env.GOOGLE_CALLBACK_URL || 'http://localhost:3000/auth/google/callback',
}, async (accessToken, refreshToken, profile, done) => {
  try {
    // Buscar por googleId O por email para evitar duplicados
    let user = await Usuario.findOne({ 
      $or: [
        { googleId: profile.id },
        { email: profile.emails?.[0]?.value }
      ]
    });
    
    if (!user) {
      user = await Usuario.create({
        googleId: profile.id,
        username: profile.displayName,
        email: profile.emails?.[0]?.value,
        profilePic: profile._json?.picture,
        bio: '',
        status: 'Online',
      });
    } else if (!user.googleId) {
      // Si existe por email pero no tiene googleId, actualizarlo
      user.googleId = profile.id;
      user.profilePic = user.profilePic || profile._json?.picture;
      await user.save();
    }
    
    done(null, user);
  } catch (err) {
    done(err, null);
  }
}));

passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser(async (id, done) => {
  try {
    const user = await Usuario.findById(id);
    done(null, user);
  } catch (err) {
    done(err, null);
  }
});

function ensureAuthenticated(req, res, next) {
  if (req.isAuthenticated()) return next();
  return res.status(401).json({ message: 'No autorizado. Inicia sesión.' });
}

// ============================================================
// 💬 RUTAS DE AUTENTICACIÓN GOOGLE
// ============================================================
app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));

app.get('/auth/google/callback',
  passport.authenticate('google', { failureRedirect: '/login' }),
  (req, res) => res.redirect(`${process.env.CLIENT_URL}/Profile`)
);

app.get('/auth/status', (req, res) => {
  res.json({ loggedIn: !!req.user });
});

app.post('/logout', (req, res) => {
  req.logout(err => {
    if (err) return res.status(500).json({ message: 'Error cerrando sesión' });
    req.session.destroy(() => res.sendStatus(200));
  });
});

// ============================================================
// 👤 PERFIL DE USUARIO
// ============================================================
app.get('/profile-data', async (req, res) => {
  try {
    // Si hay usuario autenticado
    if (req.user) {
      const user = await Usuario.findById(req.user._id)
        .select('username email telefono profilePic bio status followers following');
      if (!user) return res.status(404).json({ message: 'Usuario no encontrado.' });
      return res.json(user);
    }

    // Si no hay sesión activa
    return res.status(200).json({
      username: '',
      email: '',
      telefono: '',
      profilePic: '',
      bio: '',
      status: 'Offline',
      followers: [],
      following: [],
    });
  } catch (err) {
    console.error('❌ Error en /profile-data:', err);
    res.status(500).json({ message: 'Error obteniendo datos de perfil.' });
  }
});

// ============================================================
// 🔹 ACTUALIZACIÓN DE PERFIL
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

// BIOGRAFIA
app.put('/api/users/me/bio', ensureAuthenticated, async (req, res) => {
  try {
    const { bio } = req.body;
    
    if (bio && bio.length > 500) {
      return res.status(400).json({ message: 'La biografía no puede exceder 500 caracteres.' });
    }

    const user = await Usuario.findByIdAndUpdate(
      req.user._id,
      { bio: bio || '' },
      { new: true }
    ).select('username bio profilePic');

    console.log('✅ Biografía actualizada:', user.username);
    res.json({ 
      message: 'Biografía actualizada correctamente', 
      bio: user.bio,
      user 
    });
  } catch (error) {
    console.error('❌ Error actualizando biografía:', error);
    res.status(500).json({ message: 'Error al actualizar biografía.', error: error.message });
  }
});

// 📤 Subir background desde archivo
app.post('/api/users/me/background', ensureAuthenticated, uploadBackground.single('backgroundImage'), async (req, res) => {
  try {
    if (!req.file || !req.file.path) {
      return res.status(400).json({ message: 'No se recibió ninguna imagen.' });
    }

    const backgroundUrl = req.file.path || req.file.secure_url;
    
    console.log('🎨 Actualizando background con archivo:', backgroundUrl);

    const updatedUser = await Usuario.findByIdAndUpdate(
      req.user._id,
      { backgroundImage: backgroundUrl },
      { new: true }
    );

    if (!updatedUser) {
      return res.status(404).json({ message: 'Usuario no encontrado.' });
    }

    console.log('✅ Background actualizado correctamente');
    
    res.json({ 
      message: 'Background actualizado correctamente.',
      backgroundImage: updatedUser.backgroundImage 
    });
  } catch (error) {
    console.error('❌ Error al subir background:', error);
    res.status(500).json({ 
      message: 'Error al subir background.',
      error: error.message 
    });
  }
});

app.post('/api/auth/send-otp', async (req, res) => {
  try {
    const { email, telefono } = req.body;
    let user = null;

    if (email) {
      user = await Usuario.findOne({ email });
    } else if (telefono) {
      user = await Usuario.findOne({ telefono });
    }

    if (!user) {
      return res.status(404).json({ message: "No encontramos una cuenta con esos datos." });
    }

    const otp = Math.floor(100000 + Math.random() * 900000);
    user.otpCode = otp;
    user.otpExpires = Date.now() + 10 * 60 * 1000;
    await user.save();

    console.log("🔑 OTP generado:", otp);

    let smsEnviado = false;
    let emailEnviado = false;

    // SMS con Twilio
    if (user.telefono && process.env.TWILIO_SID) {
      try {
        const client = twilio(process.env.TWILIO_SID, process.env.TWILIO_AUTH);
        await client.messages.create({
          body: `Tu código OTP de FoodEmotions es: ${otp}`,
          from: process.env.TWILIO_PHONE,
          to: user.telefono
        });
        smsEnviado = true;
      } catch (err) {
        console.error("Error enviando SMS:", err.message);
      }
    }

    // Email con Nodemailer
    if (user.email && process.env.EMAIL_USER) {
      try {
        await transporter.sendMail({
          to: user.email,
          subject: "Código de recuperación - FoodEmotions",
          html: `
            <div style="font-family: sans-serif; padding: 20px;">
              <h2 style="color:#425638;">Código de verificación</h2>
              <h1 style="font-size: 36px; color:#687450;">${otp}</h1>
              <p>Este código expirará en 10 minutos.</p>
            </div>
          `
        });
        emailEnviado = true;
      } catch (err) {
        console.error("Error enviando email:", err.message);
      }
    }

    res.json({
      message: "Se envió el código OTP.",
      smsEnviado,
      emailEnviado,
      dev_otp: otp // ELIMINAR en producción
    });

  } catch (error) {
    console.error("Error enviando OTP:", error);
    res.status(500).json({ message: "Error interno del servidor." });
  }
});

app.post('/api/auth/verify-otp', async (req, res) => {
  try {
    const { email, telefono, otp } = req.body;

    let user = null;

    if (email) {
      user = await Usuario.findOne({ email });
    } else if (telefono) {
      user = await Usuario.findOne({ telefono });
    }

    if (!user) {
      return res.status(404).json({ message: "Usuario no encontrado." });
    }

    if (!user.otpCode || user.otpCode != otp) {
      return res.status(400).json({ message: "Código incorrecto." });
    }

    if (user.otpExpires < Date.now()) {
      return res.status(400).json({ message: "El código ha expirado." });
    }

    res.json({
      message: "OTP validado. Continúa al cambio de contraseña.",
      allowed: true
    });

  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Error al verificar OTP." });
  }
});

app.post('/api/auth/reset-password', async (req, res) => {
  try {
    const { email, telefono, newPassword } = req.body;

    let user = null;

    if (email) {
      user = await Usuario.findOne({ email });
    } else if (telefono) {
      user = await Usuario.findOne({ telefono });
    }

    if (!user) {
      return res.status(404).json({ message: "Usuario no encontrado." });
    }

    // Limpiar OTP
    user.otpCode = undefined;
    user.otpExpires = undefined;

    // Hash contraseña (ESM)
    const salt = await bcrypt.genSalt(10);
    user.password = await bcrypt.hash(newPassword, salt);

    await user.save();

    res.json({ message: "Contraseña actualizada exitosamente." });

  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Error al cambiar contraseña." });
  }
});


// 🌐 Actualizar background desde URL
app.put('/api/users/me/background-url', ensureAuthenticated, async (req, res) => {
  try {
    const { imageUrl } = req.body;
    
    if (!imageUrl || !imageUrl.trim()) {
      return res.status(400).json({ message: 'URL de imagen requerida.' });
    }

    console.log('🌐 Actualizando background con URL:', imageUrl);

    // Validar que sea una URL válida
    try {
      new URL(imageUrl);
    } catch (e) {
      return res.status(400).json({ message: 'URL inválida.' });
    }

    const updatedUser = await Usuario.findByIdAndUpdate(
      req.user._id,
      { backgroundImage: imageUrl },
      { new: true }
    );

    if (!updatedUser) {
      return res.status(404).json({ message: 'Usuario no encontrado.' });
    }

    console.log('✅ Background actualizado con URL');
    
    res.json({ 
      message: 'Background actualizado correctamente.',
      backgroundImage: updatedUser.backgroundImage 
    });
  } catch (error) {
    console.error('❌ Error actualizando background con URL:', error);
    res.status(500).json({ 
      message: 'Error al actualizar background.',
      error: error.message 
    });
  }
});

// ============================================================
// 📸 SUBIR FOTO DE PERFIL
// ============================================================
app.post('/profile/upload', upload.single('profilePic'), async (req, res) => {
  try {
    if (!req.user) return res.status(401).json({ message: 'No autorizado. Inicia sesión.' });
    if (!req.file || !req.file.path) return res.status(400).json({ message: 'No se recibió ninguna imagen.' });

    const imageUrl = req.file.path || req.file.secure_url;
    const updatedUser = await Usuario.findByIdAndUpdate(req.user.id, { profilePic: imageUrl }, { new: true });
    if (!updatedUser) return res.status(404).json({ message: 'Usuario no encontrado.' });

    console.log('✅ Foto de perfil actualizada:', updatedUser.profilePic);
    res.json({ message: 'Foto de perfil actualizada correctamente.', profilePic: updatedUser.profilePic });
  } catch (error) {
    console.error('❌ Error al subir imagen:', error);
    res.status(500).json({ message: 'Error al subir la imagen.' });
  }
});

// ============================================================
// 👥 SEGUIR / DEJAR DE SEGUIR USUARIOS
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
// 🍳 RECETAS
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
// 🤖 MODELOS DE IA (Chat y Traducción)
// ============================================================
env.cacheDir = "./models_cache";
env.allowLocalModels = true;
env.useBrowserCache = false;

let chatPipeline = null;
let translatePipeline = null;

(async () => {
  try {
    console.log("Cargando modelo de conversación (TinyLlama-1.1B)...");

    chatPipeline = await pipeline(
      "text-generation",
      "Xenova/TinyLlama-1.1B-Chat-v1.0"
    );
    console.log("✅ Modelo TinyLlama cargado correctamente.");

    console.log("Cargando modelo de traducción...");
    translatePipeline = await pipeline(
      "translation",
      "Xenova/nllb-200-distilled-600M"
    );
    console.log("✅ Modelo de traducción cargado correctamente.");

  } catch (err) {
    console.error("❌ Error inicializando modelos:", err.message);
  }
})();

// ============================================================
// 🌍 Traducción automática local
// ============================================================
async function localTranslate(text, to = "eng_Latn") {
  try {
    if (!translatePipeline) return text;

    const res = await translatePipeline(text, {
      tgt_lang: to,
      src_lang: to === "eng_Latn" ? "spa_Latn" : "eng_Latn",
    });

    return res?.[0]?.translation_text || text;
  } catch (err) {
    console.warn("Falló traducción local:", err.message);
    return text;
  }
}

// ============================================================
// 😶‍🌫️ Detección emocional sencilla
// ============================================================
function detectEmotion(text) {
  const t = (text || "").toLowerCase();

  if (/(feliz|contento|alegre|animado|genial|excelente)/.test(t)) return "happy";
  if (/(triste|mal|deprimido|solo|llorar)/.test(t)) return "sad";
  if (/(enojado|molesto|furioso|rabia|odio)/.test(t)) return "angry";
  if (/(tranquilo|relajado|en paz|calmado|sereno)/.test(t)) return "calm";

  return "neutral";
}

// ============================================================
// 🎭 Prompt según el modo seleccionado
// ============================================================
function getRolePrompt(mode) {
  switch (mode) {
    case "chef":
      return "You are Roy, a friendly healthy-cooking chef. Give short, practical cooking tips and recipe suggestions. Be enthusiastic about food.";
    case "emocional":
      return "You are Roy, an empathetic and caring friend. Listen actively and respond with warmth, understanding, and supportive words.";
    case "musical":
      return "You are Roy, a music expert who recommends songs and artists based on the user's mood and preferences. Be passionate about music.";
    default:
      return "You are Roy, a helpful and friendly assistant who can talk about food, emotions, music, and daily life. Be conversational and kind.";
  }
}

// ============================================================
// 🧠 Generación local con TinyLlama (con historial y traducción)
// ============================================================
async function generateSpanishReply({ message, mode, history = [] }) {
  try {
    if (!chatPipeline || !translatePipeline) {
      return "Los modelos aún se están cargando, inténtalo en unos segundos.";
    }

    // 1. Entrada → Inglés
    const englishInput = await localTranslate(message, "eng_Latn");

    // 2. Prompt según el modo
    const rolePrompt = getRolePrompt(mode);
    let prompt = `<|system|>\n${rolePrompt}</s>\n`;

    // 3. Añadir historial corto
    const recentHistory = history.slice(-3);
    for (const msg of recentHistory) {
      if (msg.role === "user") {
        prompt += `<|user|>\n${msg.text}</s>\n`;
      } else {
        prompt += `<|assistant|>\n${msg.text}</s>\n`;
      }
    }

    // 4. Entrada actual
    prompt += `<|user|>\n${englishInput}</s>\n<|assistant|>\n`;

    // 5. Generar respuesta con TinyLlama
    const gen = await chatPipeline(prompt, {
      max_new_tokens: 80,
      temperature: 0.7,
      top_p: 0.9,
      repetition_penalty: 1.2,
      return_full_text: false,
    });

    let replyEn = gen?.[0]?.generated_text || "";

    // Limpieza del texto
    replyEn = replyEn
      .replace(/<\|system\|>|<\|user\|>|<\|assistant\|>|<\/s>/g, "")
      .replace(/^(Assistant:|Roy:)/i, "")
      .split("\n")[0]
      .trim();

    if (replyEn.length > 500) {
      replyEn = replyEn.substring(0, 500).trim();
    }

    // 6. Traducción final al español
    const replyEs = await localTranslate(replyEn, "spa_Latn");

    return replyEs.trim() || "Lo siento, no pude generar una respuesta adecuada.";
  } catch (err) {
    console.error("Error en generación:", err.message);
    return "Ocurrió un problema generando la respuesta. Por favor, intenta de nuevo.";
  }
}

// ============================================================
// 💬 ENDPOINT CHAT (solo texto)
// ============================================================
app.post("/api/chat", async (req, res) => {
  try {
    if (!chatPipeline || !translatePipeline) {
      return res.status(503).json({
        error: "Modelos cargando...",
        message: "Los modelos de IA se están inicializando. Espera unos segundos.",
      });
    }

    const { message, mode = "general" } = req.body || {};

    if (!message || !message.trim()) {
      return res.status(400).json({ error: "Mensaje vacío" });
    }

    const reply = await generateSpanishReply({
      message: message.trim(),
      mode,
    });

    const emotion = detectEmotion(message);

    console.log(`Roy (${mode}): ${reply.substring(0, 100)}...`);

    res.json({
      reply,
      emotion,
      mode,
      timestamp: new Date().toISOString(),
    });
  } catch (err) {
    console.error("Error en chat:", err);
    res.status(500).json({
      error: "Error en el servidor del chat Roy.",
      details: err.message,
    });
  }
});

// ============================================================
// 💬 ENDPOINT CHAT CON HISTORIAL
// ============================================================
app.post("/api/chats/:id/message", async (req, res) => {
  try {
    if (!chatPipeline || !translatePipeline) {
      return res.status(503).json({ error: "Modelos cargando..." });
    }

    const { message, mode = "general" } = req.body || {};

    if (!message?.trim()) {
      return res.status(400).json({ error: "Mensaje vacío" });
    }

    const chat = await ChatSession.findById(req.params.id);
    if (!chat) return res.status(404).json({ error: "Conversación no encontrada." });

    const reply = await generateSpanishReply({
      message: message.trim(),
      mode,
      history: chat.messages,
    });

    const emotion = detectEmotion(message);

    chat.messages.push({ role: "user", text: message.trim() });
    chat.messages.push({ role: "assistant", text: reply });
    await chat.save();

    res.json({
      reply,
      emotion,
      mode,
      chatId: chat._id,
      timestamp: new Date().toISOString(),
    });
  } catch (err) {
    console.error("Error en chat con historial:", err);
    res.status(500).json({
      error: "No se pudo procesar el mensaje.",
      details: err.message,
    });
  }
});

// ============================================================
// 🟢 STATUS DE MODELOS
// ============================================================
app.get("/api/status", (req, res) => {
  res.json({
    status: chatPipeline && translatePipeline ? "ready" : "loading",
    models: {
      chat: chatPipeline ? "loaded" : "loading",
      translate: translatePipeline ? "loaded" : "loading",
      tts: "disabled", // ya no existe
    },
  });
});

// ============================================================
// 🔐 REGISTRO Y LOGIN
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
      username, email, telefono, password: hashedPassword, status: 'Offline',
    });

    await newUser.save();
    res.status(201).json({ message: 'Usuario registrado correctamente.' });
  } catch (err) {
    console.error('Error registrando usuario:', err);
    res.status(500).json({ message: 'Error registrando usuario.' });
  }
});

app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const user = await Usuario.findOne({ email });
    if (!user) return res.status(400).json({ message: 'Usuario no encontrado.' });

    // Verificar si el usuario tiene contraseña (no es cuenta de Google)
    if (!user.password) {
      return res.status(400).json({ 
        message: 'Esta cuenta usa autenticación de Google. Por favor, inicia sesión con Google.',
        useGoogleAuth: true
      });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ message: 'Contraseña incorrecta.' });

    req.login(user, (err) => {
      if (err) return res.status(500).json({ message: 'Error al iniciar sesión.' });
      return res.status(200).json({
        message: 'Inicio de sesión exitoso.',
        redirectUrl: `${process.env.CLIENT_URL}/Profile`,
        user: { username: user.username, email: user.email, profilePic: user.profilePic },
      });
    });
  } catch (err) {
    console.error('Error en login:', err);
    res.status(500).json({ message: 'Error al iniciar sesión.' });
  }
});

// ============================================================
// 👤 API DE USUARIOS (CONSOLIDADO Y ORDENADO CON ESTADÍSTICAS)
// ============================================================

// 🔹 Perfil del usuario actual (sesión activa) CON ESTADÍSTICAS
app.get('/api/user/me', async (req, res) => {
  try {
    if (!req.user) {
      return res.status(200).json({ 
        message: 'Usuario no autenticado.', 
        loggedIn: false 
      });
    }
    
    const user = await Usuario.findById(req.user._id)
      .select('username email bannerImage telefono profilePic bio status followers following savedPosts recipesLiked isPremium')
      .lean();
    
    if (!user) {
      return res.status(404).json({ 
        message: 'Usuario no encontrado.',
        loggedIn: false 
      });
    }

    // ⭐ CALCULAR ESTADÍSTICAS
    const postsCount = await Post.countDocuments({ author: user._id });
    
    // Calcular likes totales en todos los posts del usuario
    const userPosts = await Post.find({ author: user._id }).select('likes').lean();
    const totalLikes = userPosts.reduce((sum, post) => sum + (post.likes?.length || 0), 0);

    // Preparar respuesta con estadísticas
    const response = {
      ...user,
      loggedIn: true,
      stats: {
        posts: postsCount,
        followers: user.followers?.length || 0,
        following: user.following?.length || 0,
        savedPosts: user.savedPosts?.length || 0,
        recipesLiked: user.recipesLiked?.length || 0,
        totalLikes: totalLikes
      }
    };

    console.log('✅ Usuario cargado con stats:', {
      username: response.username,
      stats: response.stats
    });
    
    res.json(response);
  } catch (err) {
    console.error('❌ Error en /api/user/me:', err);
    res.status(500).json({ 
      message: 'Error obteniendo usuario.',
      error: err.message 
    });
  }
});

// ============================================================
// 📈 ACTIVIDAD Y ESTADÍSTICAS
// ============================================================

app.get('/api/users/me/activity-stats', ensureAuthenticated, async (req, res) => {
  try {
    const postsCount = await Post.countDocuments({ author: req.user._id });
    const followers = await Usuario.findById(req.user._id).select('followers following');
    const likes = await Post.aggregate([
      { $match: { author: req.user._id } },
      { $project: { likes: { $size: '$likes' } } },
      { $group: { _id: null, totalLikes: { $sum: '$likes' } } }
    ]);

    res.json({
      posts: postsCount,
      followers: followers.followers.length,
      following: followers.following.length,
      totalLikes: likes[0]?.totalLikes || 0,
    });
  } catch (err) {
    console.error('❌ Error obteniendo estadísticas:', err);
    res.status(500).json({ message: 'Error obteniendo estadísticas.' });
  }
});

// 🔹 Buscar usuarios por nombre o email
app.get('/api/users/search', ensureAuthenticated, async (req, res) => {
  try {
    const query = (req.query.q || '').trim();
    
    if (!query) {
      return res.status(400).json({ 
        message: 'Falta el parámetro de búsqueda.' 
      });
    }

    console.log('🔍 Búsqueda de usuarios:', query);

    // Buscar usuarios por username o email, excepto el propio
    const users = await Usuario.find({
      $and: [
        {
          $or: [
            { username: { $regex: query, $options: 'i' } },
            { email: { $regex: query, $options: 'i' } },
          ]
        },
        { _id: { $ne: req.user._id } }
      ]
    })
      .select('username email profilePic status followers following')
      .limit(10)
      .lean();

    // Ordenar para mostrar primero los que empiezan con el texto buscado
    const sorted = users.sort((a, b) => {
      const aMatch = a.username.toLowerCase().startsWith(query.toLowerCase());
      const bMatch = b.username.toLowerCase().startsWith(query.toLowerCase());
      return (aMatch === bMatch) ? 0 : aMatch ? -1 : 1;
    });

    console.log(`✅ Encontrados ${sorted.length} usuarios`);
    res.json(sorted);
  } catch (err) {
    console.error('❌ Error en búsqueda de usuarios:', err);
    res.status(500).json({ 
      message: 'Error buscando usuarios.', 
      error: err.message 
    });
  }
});

// ============================================================
// 📍 UBICACIÓN DE USUARIOS
// ============================================================

// Actualizar ubicación del usuario
app.put('/api/users/location', ensureAuthenticated, async (req, res) => {
  try {
    const { lat, lng, country, city } = req.body;
    if (!lat || !lng) return res.status(400).json({ message: 'Coordenadas requeridas.' });

    const user = await Usuario.findByIdAndUpdate(
      req.user._id,
      { location: { lat, lng, country, city, updatedAt: new Date() } },
      { new: true }
    );

    res.json({ message: 'Ubicación actualizada', location: user.location });
  } catch (err) {
    console.error('❌ Error actualizando ubicación:', err);
    res.status(500).json({ message: 'Error actualizando ubicación.' });
  }
});

// Buscar usuarios cercanos (radio de 50 km)
app.get('/api/users/nearby', ensureAuthenticated, async (req, res) => {
  try {
    const { lat, lng } = req.query;
    if (!lat || !lng) return res.status(400).json({ message: 'Coordenadas requeridas.' });

    const R = 6371; // radio terrestre en km
    const maxDist = 50; // radio de 50 km

    const users = await Usuario.find({
      _id: { $ne: req.user._id },
      location: { $exists: true, $ne: null }
    })
      .lean();

    const nearby = users.filter(u => {
      if (!u.location?.lat || !u.location?.lng) return false;
      const dLat = (u.location.lat - lat) * Math.PI / 180;
      const dLng = (u.location.lng - lng) * Math.PI / 180;
      const a = Math.sin(dLat/2)**2 + Math.cos(lat*Math.PI/180) * Math.cos(u.location.lat*Math.PI/180) * Math.sin(dLng/2)**2;
      const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1-a));
      const dist = R * c;
      return dist <= maxDist;
    });

    res.json(nearby);
  } catch (err) {
    console.error('❌ Error buscando usuarios cercanos:', err);
    res.status(500).json({ message: 'Error buscando usuarios cercanos.' });
  }
});

// ============================================================
// 👥 User Suggestions - GET /api/users/suggestions
// ============================================================

app.get("/api/users/suggestions", ensureAuthenticated, async (req, res) => {
  try {
    const currentUserId = req.user._id;

    // Buscar usuarios menos el actual
    const users = await Usuario.find({
      _id: { $ne: currentUserId }
    })
      .select("username profilePic bio")
      .limit(5);

    return res.json(users);

  } catch (err) {
    console.error("❌ Error al obtener sugerencias:", err);
    return res.status(500).json({ message: "Error al cargar sugerencias" });
  }
});

// 🔹 Perfil de un usuario específico CON ESTADÍSTICAS
app.get('/api/users/:id/profile', ensureAuthenticated, async (req, res) => {
  try {
    const user = await Usuario.findById(req.params.id)
      .select('username email telefono profilePic bio status followers following savedPosts recipesLiked isPremium createdAt')
      .lean();

    if (!user) {
      return res.status(404).json({ 
        message: 'Usuario no encontrado.' 
      });
    }

    // ⭐ CALCULAR ESTADÍSTICAS
    const postsCount = await Post.countDocuments({ author: user._id });
    
    // Calcular likes totales
    const userPosts = await Post.find({ author: user._id }).select('likes').lean();
    const totalLikes = userPosts.reduce((sum, post) => sum + (post.likes?.length || 0), 0);

    const alreadyFollowing = user.followers.some(
      f => f.toString() === req.user._id.toString()
    );

    // Preparar respuesta con estadísticas
    const response = {
      ...user,
      alreadyFollowing,
      stats: {
        posts: postsCount,
        followers: user.followers?.length || 0,
        following: user.following?.length || 0,
        savedPosts: user.savedPosts?.length || 0,
        recipesLiked: user.recipesLiked?.length || 0,
        totalLikes: totalLikes
      }
    };

    console.log('✅ Perfil cargado con stats:', {
      username: response.username,
      stats: response.stats
    });

    res.json(response);
  } catch (err) {
    console.error('❌ Error obteniendo perfil del usuario:', err);
    res.status(500).json({ 
      message: 'Error obteniendo perfil del usuario.',
      error: err.message 
    });
  }
});

// 🔹 Seguir/dejar de seguir usuario
app.post('/api/users/:id/follow', ensureAuthenticated, async (req, res) => {
  try {
    const targetId = req.params.id;
    const currentUserId = req.user._id;

    if (targetId === currentUserId.toString()) {
      return res.status(400).json({ 
        message: 'No puedes seguirte a ti mismo.' 
      });
    }

    const targetUser = await Usuario.findById(targetId);
    const currentUser = await Usuario.findById(currentUserId);

    if (!targetUser) {
      return res.status(404).json({ 
        message: 'Usuario no encontrado.' 
      });
    }

    const isFollowing = currentUser.following.includes(targetId);

    if (isFollowing) {
      currentUser.following.pull(targetId);
      targetUser.followers.pull(currentUserId);
    } else {
      currentUser.following.push(targetId);
      targetUser.followers.push(currentUserId);
    }

    await currentUser.save();
    await targetUser.save();

    console.log(`✅ ${currentUser.username} ${isFollowing ? 'dejó de seguir' : 'ahora sigue'} a ${targetUser.username}`);

    res.json({ 
      following: !isFollowing,
      followersCount: targetUser.followers.length,
      message: isFollowing 
        ? `Has dejado de seguir a ${targetUser.username}`
        : `Ahora sigues a ${targetUser.username}`
    });
  } catch (err) {
    console.error('❌ Error en follow:', err);
    res.status(500).json({ 
      message: 'Error al seguir o dejar de seguir usuario.',
      error: err.message 
    });
  }
});

// 🔹 Endpoint adicional para obtener solo estadísticas (opcional pero útil)
app.get('/api/users/:id/stats', ensureAuthenticated, async (req, res) => {
  try {
    const userId = req.params.id === 'me' ? req.user._id : req.params.id;
    
    const user = await Usuario.findById(userId)
      .select('followers following savedPosts recipesLiked')
      .lean();

    if (!user) {
      return res.status(404).json({ message: 'Usuario no encontrado.' });
    }

    const postsCount = await Post.countDocuments({ author: userId });
    
    // Calcular likes totales
    const userPosts = await Post.find({ author: userId }).select('likes').lean();
    const totalLikes = userPosts.reduce((sum, post) => sum + (post.likes?.length || 0), 0);

    const stats = {
      posts: postsCount,
      followers: user.followers?.length || 0,
      following: user.following?.length || 0,
      savedPosts: user.savedPosts?.length || 0,
      recipesLiked: user.recipesLiked?.length || 0,
      totalLikes: totalLikes
    };

    console.log('📊 Stats para usuario:', userId, stats);

    res.json(stats);
  } catch (err) {
    console.error('❌ Error obteniendo stats:', err);
    res.status(500).json({ 
      message: 'Error obteniendo estadísticas.',
      error: err.message 
    });
  }
});

// ============================================================
// 📦 ENDPOINTS ADICIONALES PARA PROFILE.ASTRO
// ============================================================

// 🔹 Obtener lista de seguidores de un usuario
app.get('/api/users/:id/followers', ensureAuthenticated, async (req, res) => {
  try {
    const userId = req.params.id === 'me' ? req.user._id : req.params.id;
    
    console.log('👥 Obteniendo seguidores de:', userId);
    
    const user = await Usuario.findById(userId)
      .populate('followers', 'username email profilePic status')
      .lean();

    if (!user) {
      return res.status(404).json({ message: 'Usuario no encontrado.' });
    }

    console.log(`✅ ${user.followers.length} seguidores encontrados`);
    
    res.json(user.followers || []);
  } catch (err) {
    console.error('❌ Error obteniendo seguidores:', err);
    res.status(500).json({ 
      message: 'Error obteniendo seguidores.',
      error: err.message 
    });
  }
});

// 🔹 Obtener lista de usuarios que sigue
app.get('/api/users/:id/following', ensureAuthenticated, async (req, res) => {
  try {
    const userId = req.params.id === 'me' ? req.user._id : req.params.id;
    
    console.log('👥 Obteniendo seguidos de:', userId);
    
    const user = await Usuario.findById(userId)
      .populate('following', 'username email profilePic status')
      .lean();

    if (!user) {
      return res.status(404).json({ message: 'Usuario no encontrado.' });
    }

    console.log(`✅ Siguiendo a ${user.following.length} usuarios`);
    
    res.json(user.following || []);
  } catch (err) {
    console.error('❌ Error obteniendo seguidos:', err);
    res.status(500).json({ 
      message: 'Error obteniendo usuarios seguidos.',
      error: err.message 
    });
  }
});

// 🔹 Obtener posts con likes del usuario
app.get('/api/users/:id/liked-posts', ensureAuthenticated, async (req, res) => {
  try {
    const userId = req.params.id === 'me' ? req.user._id : req.params.id;
    
    console.log('❤️ Obteniendo posts con likes de:', userId);
    
    // Buscar posts donde el usuario haya dado like
    const posts = await Post.find({ likes: userId })
      .populate('author', 'username profilePic')
      .sort({ createdAt: -1 })
      .limit(50)
      .lean();

    console.log(`✅ ${posts.length} posts con likes encontrados`);
    
    res.json(posts);
  } catch (err) {
    console.error('❌ Error obteniendo posts con likes:', err);
    res.status(500).json({ 
      message: 'Error obteniendo posts con likes.',
      error: err.message 
    });
  }
});

// 🔹 Obtener posts guardados del usuario
app.get('/api/users/:id/saved-posts', ensureAuthenticated, async (req, res) => {
  try {
    const userId = req.params.id === 'me' ? req.user._id : req.params.id;
    
    console.log('💾 Obteniendo posts guardados de:', userId);
    
    const user = await Usuario.findById(userId)
      .populate({
        path: 'savedPosts',
        populate: { path: 'author', select: 'username profilePic' }
      })
      .lean();

    if (!user) {
      return res.status(404).json({ message: 'Usuario no encontrado.' });
    }

    console.log(`✅ ${user.savedPosts?.length || 0} posts guardados`);
    
    res.json(user.savedPosts || []);
  } catch (err) {
    console.error('❌ Error obteniendo posts guardados:', err);
    res.status(500).json({ 
      message: 'Error obteniendo posts guardados.',
      error: err.message 
    });
  }
});

// 🔹 Obtener configuración de perfil
app.get('/api/profile/settings', ensureAuthenticated, async (req, res) => {
  try {
    let settings = await ProfileSettings.findOne({ user: req.user._id });

    // Si no existe, crear configuración por defecto
    if (!settings) {
      settings = await ProfileSettings.create({
        user: req.user._id
      });
    }

    console.log('⚙️ Configuración de perfil obtenida');
    res.json(settings);
  } catch (error) {
    console.error('❌ Error obteniendo configuración:', error);
    res.status(500).json({ message: 'Error obteniendo configuración.' });
  }
});

// 🔹 Actualizar configuración de perfil
app.put('/api/profile/settings', ensureAuthenticated, async (req, res) => {
  try {
    const { privacy, display, notifications, content } = req.body;

    let settings = await ProfileSettings.findOne({ user: req.user._id });

    if (!settings) {
      settings = await ProfileSettings.create({
        user: req.user._id,
        privacy,
        display,
        notifications,
        content
      });
    } else {
      if (privacy) settings.privacy = { ...settings.privacy, ...privacy };
      if (display) settings.display = { ...settings.display, ...display };
      if (notifications) settings.notifications = { ...settings.notifications, ...notifications };
      if (content) settings.content = { ...settings.content, ...content };

      await settings.save();
    }

    console.log('✅ Configuración actualizada');
    res.json({
      message: 'Configuración actualizada correctamente',
      settings
    });
  } catch (error) {
    console.error('❌ Error actualizando configuración:', error);
    res.status(500).json({ message: 'Error actualizando configuración.' });
  }
});

// 🔹 Actualizar tema del perfil
app.put('/api/profile/theme', ensureAuthenticated, async (req, res) => {
  try {
    const { theme, primaryColor, secondaryColor } = req.body;

    let settings = await ProfileSettings.findOne({ user: req.user._id });

    if (!settings) {
      settings = await ProfileSettings.create({ user: req.user._id });
    }

    if (theme) settings.display.profileTheme = theme;
    if (primaryColor) settings.display.customColors.primary = primaryColor;
    if (secondaryColor) settings.display.customColors.secondary = secondaryColor;

    await settings.save();

    console.log('🎨 Tema actualizado');
    res.json({
      message: 'Tema actualizado correctamente',
      theme: settings.display
    });
  } catch (error) {
    console.error('❌ Error actualizando tema:', error);
    res.status(500).json({ message: 'Error actualizando tema.' });
  }
});

// 🔹 Obtener perfil público con configuración de privacidad
app.get('/api/users/:id/public-profile-full', async (req, res) => {
  try {
    const userId = req.params.id;
    const requesterId = req.user?._id;

    const user = await Usuario.findById(userId)
      .select('username profilePic bannerImage bio status followers following createdAt')
      .lean();

    if (!user) {
      return res.status(404).json({ message: 'Usuario no encontrado.' });
    }

    // Obtener configuración de privacidad
    const settings = await ProfileSettings.findOne({ user: userId });

    // Aplicar configuración de privacidad
    const publicProfile = {
      _id: user._id,
      username: user.username,
      profilePic: user.profilePic,
      bannerImage: user.bannerImage,
      bio: user.bio,
      status: user.status,
      memberSince: user.createdAt,
      stats: {
        followers: user.followers?.length || 0,
        following: user.following?.length || 0
      }
    };

    // Mostrar elementos según configuración
    if (settings) {
      publicProfile.showBlog = settings.display.showBlog;
      publicProfile.showFiles = settings.display.showFiles;
      publicProfile.showCollections = settings.display.showCollections;
      publicProfile.showGroups = settings.display.showGroups;
      publicProfile.showRecipes = settings.display.showRecipes;
      publicProfile.theme = settings.display.profileTheme;
      publicProfile.colors = settings.display.customColors;

      // Solo mostrar actividad si está permitido
      if (settings.privacy.showActivity) {
        const postsCount = await Post.countDocuments({ author: userId });
        publicProfile.stats.posts = postsCount;
      }
    }

    // Verificar si el usuario que solicita es seguidor
    const isFollowing = requesterId && user.followers?.some(
      id => id.toString() === requesterId.toString()
    );
    publicProfile.isFollowing = isFollowing || false;

    console.log('👤 Perfil público completo obtenido');
    res.json(publicProfile);
  } catch (error) {
    console.error('❌ Error obteniendo perfil público:', error);
    res.status(500).json({ message: 'Error obteniendo perfil.' });
  }
});


// ============================================================
// 📩 NOTIFICACIONES
// ============================================================

// Obtener notificaciones del usuario autenticado
app.get('/api/notifications', ensureAuthenticated, async (req, res) => {
  try {
    const notifications = await Notification.find({ recipient: req.user._id })
      .populate('sender', 'username profilePic')
      .sort({ createdAt: -1 })
      .limit(30)
      .lean();

    res.json(notifications);
  } catch (err) {
    console.error('❌ Error obteniendo notificaciones:', err);
    res.status(500).json({ message: 'Error obteniendo notificaciones.' });
  }
});

// Marcar notificaciones como leídas
app.post('/api/notifications/mark-read', ensureAuthenticated, async (req, res) => {
  try {
    await Notification.updateMany(
      { recipient: req.user._id, read: false },
      { $set: { read: true } }
    );
    res.json({ message: 'Notificaciones marcadas como leídas' });
  } catch (err) {
    console.error('❌ Error marcando notificaciones:', err);
    res.status(500).json({ message: 'Error marcando notificaciones.' });
  }
});

// 🔹 Guardar/Desguardar un post
app.post('/api/posts/:id/save', ensureAuthenticated, async (req, res) => {
  try {
    const postId = req.params.id;
    const userId = req.user._id;

    console.log('💾 Guardando/desguar post:', postId);

    const post = await Post.findById(postId);
    if (!post) {
      return res.status(404).json({ message: 'Post no encontrado.' });
    }

    const user = await Usuario.findById(userId);
    
    const isSaved = user.savedPosts.includes(postId);

    if (isSaved) {
      user.savedPosts.pull(postId);
      await user.save();
      console.log('✅ Post removido de guardados');
      res.json({ saved: false, message: 'Post removido de guardados' });
    } else {
      user.savedPosts.push(postId);
      await user.save();
      console.log('✅ Post guardado');
      res.json({ saved: true, message: 'Post guardado correctamente' });
    }
  } catch (err) {
    console.error('❌ Error guardando post:', err);
    res.status(500).json({ 
      message: 'Error al guardar post.',
      error: err.message 
    });
  }
});

// ============================================================
// 🔥 EXPLORAR: POSTS POPULARES
// ============================================================
app.get('/api/explore/trending', ensureAuthenticated, async (req, res) => {
  try {
    const posts = await Post.find({ visibility: 'public' })
      .populate('author', 'username profilePic')
      .sort({ 'likes.length': -1, createdAt: -1 })
      .limit(20)
      .lean();

    res.json(posts);
  } catch (err) {
    console.error('❌ Error en trending:', err);
    res.status(500).json({ message: 'Error cargando publicaciones populares.' });
  }
});

// ============================================================
// 📸 HISTORIAS (STORIES)
// ============================================================

// Subir historia (24h de duración)
app.post('/api/stories', ensureAuthenticated, uploadPostMedia.single('media'), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ message: 'Archivo no recibido.' });

    const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000);
    const story = await Story.create({
      author: req.user._id,
      mediaUrl: req.file.path,
      caption: req.body.caption || '',
      expiresAt
    });

    const populated = await story.populate('author', 'username profilePic');
    io.emit('story-created', { story: populated });

    res.status(201).json(populated);
  } catch (err) {
    console.error('❌ Error subiendo historia:', err);
    res.status(500).json({ message: 'Error subiendo historia.' });
  }
});

// Obtener historias activas (no expiradas)
app.get('/api/stories', ensureAuthenticated, async (req, res) => {
  try {
    const now = new Date();
    const stories = await Story.find({ expiresAt: { $gt: now } })
      .populate('author', 'username profilePic')
      .sort({ createdAt: -1 })
      .lean();

    res.json(stories);
  } catch (err) {
    console.error('❌ Error obteniendo historias:', err);
    res.status(500).json({ message: 'Error obteniendo historias.' });
  }
});

app.post('/api/stories/:id/view', ensureAuthenticated, async (req, res) => {
  try {
    const story = await Story.findById(req.params.id);
    if (!story) return res.status(404).json({ message: 'Historia no encontrada' });
    
    if (!story.viewers.includes(req.user._id)) {
      story.viewers.push(req.user._id);
      await story.save();
    }
    
    res.json({ message: 'Vista registrada' });
  } catch (err) {
    res.status(500).json({ message: 'Error registrando vista' });
  }
});

// 🔹 Obtener recetas que le gustan al usuario
app.get('/api/users/:id/liked-recipes', ensureAuthenticated, async (req, res) => {
  try {
    const userId = req.params.id === 'me' ? req.user._id : req.params.id;
    
    console.log('🍳 Obteniendo recetas que le gustan a:', userId);
    
    const user = await Usuario.findById(userId)
      .populate({
        path: 'recipesLiked',
        populate: { path: 'author', select: 'username profilePic' }
      })
      .lean();

    if (!user) {
      return res.status(404).json({ message: 'Usuario no encontrado.' });
    }

    console.log(`✅ ${user.recipesLiked?.length || 0} recetas encontradas`);
    
    res.json(user.recipesLiked || []);
  } catch (err) {
    console.error('❌ Error obteniendo recetas:', err);
    res.status(500).json({ 
      message: 'Error obteniendo recetas.',
      error: err.message 
    });
  }
});

// 🔹 Dar/quitar like a una receta
app.post('/api/recipes/:id/like', ensureAuthenticated, async (req, res) => {
  try {
    const recipeId = req.params.id;
    const userId = req.user._id;

    console.log('❤️ Like/Unlike receta:', recipeId);

    const recipe = await Recipe.findById(recipeId);
    if (!recipe) {
      return res.status(404).json({ message: 'Receta no encontrada.' });
    }

    const user = await Usuario.findById(userId);
    
    const hasLiked = recipe.likes.includes(userId);
    const userHasLiked = user.recipesLiked.includes(recipeId);

    if (hasLiked) {
      recipe.likes.pull(userId);
      user.recipesLiked.pull(recipeId);
      await recipe.save();
      await user.save();
      console.log('✅ Like removido de receta');
      res.json({ liked: false, likesCount: recipe.likes.length });
    } else {
      recipe.likes.push(userId);
      user.recipesLiked.push(recipeId);
      await recipe.save();
      await user.save();
      console.log('✅ Like agregado a receta');
      res.json({ liked: true, likesCount: recipe.likes.length });
    }
  } catch (err) {
    console.error('❌ Error con like en receta:', err);
    res.status(500).json({ 
      message: 'Error al dar like a receta.',
      error: err.message 
    });
  }
});

// 🔹 Actualizar URL de imagen de perfil (desde URL externa)
app.put('/profile/update-pic-url', ensureAuthenticated, async (req, res) => {
  try {
    const { imageUrl } = req.body;
    
    if (!imageUrl || !imageUrl.trim()) {
      return res.status(400).json({ message: 'URL de imagen requerida.' });
    }

    console.log('🌐 Actualizando foto de perfil con URL:', imageUrl);

    // Validar que sea una URL válida
    try {
      new URL(imageUrl);
    } catch (e) {
      return res.status(400).json({ message: 'URL inválida.' });
    }

    const user = await Usuario.findByIdAndUpdate(
      req.user._id,
      { profilePic: imageUrl },
      { new: true }
    );

    if (!user) {
      return res.status(404).json({ message: 'Usuario no encontrado.' });
    }

    console.log('✅ Foto de perfil actualizada con URL');
    
    res.json({ 
      message: 'Foto de perfil actualizada correctamente.',
      profilePic: user.profilePic 
    });
  } catch (err) {
    console.error('❌ Error actualizando foto con URL:', err);
    res.status(500).json({ 
      message: 'Error al actualizar foto de perfil.',
      error: err.message 
    });
  }
});

// 🔹 Obtener actividad reciente del usuario (últimas acciones)
app.get('/api/users/:id/activity', ensureAuthenticated, async (req, res) => {
  try {
    const userId = req.params.id === 'me' ? req.user._id : req.params.id;
    
    console.log('📊 Obteniendo actividad de:', userId);

    // Obtener últimos posts
    const recentPosts = await Post.find({ author: userId })
      .sort({ createdAt: -1 })
      .limit(5)
      .select('caption images createdAt likes comments')
      .lean();

    // Obtener últimos comentarios
    const recentComments = await Comment.find({ author: userId })
      .sort({ createdAt: -1 })
      .limit(5)
      .populate('postId', 'caption')
      .lean();

    // Obtener últimos likes (posts que ha dado like)
    const recentLikes = await Post.find({ likes: userId })
      .sort({ updatedAt: -1 })
      .limit(5)
      .select('caption author createdAt')
      .populate('author', 'username profilePic')
      .lean();

    const activity = {
      recentPosts,
      recentComments,
      recentLikes,
      summary: {
        postsCount: recentPosts.length,
        commentsCount: recentComments.length,
        likesCount: recentLikes.length
      }
    };

    console.log('✅ Actividad obtenida');
    
    res.json(activity);
  } catch (err) {
    console.error('❌ Error obteniendo actividad:', err);
    res.status(500).json({ 
      message: 'Error obteniendo actividad del usuario.',
      error: err.message 
    });
  }
});

// 🔹 Subir archivo
app.post('/api/files/upload', ensureAuthenticated, uploadFile.single('file'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ message: 'No se recibió ningún archivo.' });
    }

    const { name, description, tags, isPublic } = req.body;

    const file = await File.create({
      name: name || req.file.originalname,
      description: description || '',
      fileUrl: req.file.path,
      fileType: req.file.mimetype,
      size: req.file.size,
      owner: req.user._id,
      tags: tags ? JSON.parse(tags) : [],
      isPublic: isPublic === 'true'
    });

    console.log('✅ Archivo subido:', file.name);
    res.status(201).json({
      message: 'Archivo subido correctamente',
      file
    });
  } catch (error) {
    console.error('❌ Error subiendo archivo:', error);
    res.status(500).json({ message: 'Error subiendo archivo.' });
  }
});

// 🔹 Obtener archivos del usuario
app.get('/api/files', ensureAuthenticated, async (req, res) => {
  try {
    const files = await File.find({ owner: req.user._id })
      .sort({ createdAt: -1 });

    console.log(`📁 ${files.length} archivos encontrados`);
    res.json(files);
  } catch (error) {
    console.error('❌ Error obteniendo archivos:', error);
    res.status(500).json({ message: 'Error obteniendo archivos.' });
  }
});

// 🔹 Obtener un archivo específico
app.get('/api/files/:id', ensureAuthenticated, async (req, res) => {
  try {
    const file = await File.findById(req.params.id);

    if (!file) {
      return res.status(404).json({ message: 'Archivo no encontrado.' });
    }

    // Verificar permisos
    if (!file.isPublic && file.owner.toString() !== req.user._id.toString()) {
      return res.status(403).json({ message: 'No tienes permiso para ver este archivo.' });
    }

    res.json(file);
  } catch (error) {
    console.error('❌ Error obteniendo archivo:', error);
    res.status(500).json({ message: 'Error obteniendo archivo.' });
  }
});

// 🔹 Actualizar archivo
app.put('/api/files/:id', ensureAuthenticated, async (req, res) => {
  try {
    const { name, description, tags, isPublic } = req.body;
    
    const file = await File.findById(req.params.id);
    if (!file) {
      return res.status(404).json({ message: 'Archivo no encontrado.' });
    }

    // Verificar que el usuario sea el propietario
    if (file.owner.toString() !== req.user._id.toString()) {
      return res.status(403).json({ message: 'No tienes permiso para editar este archivo.' });
    }

    if (name) file.name = name;
    if (description !== undefined) file.description = description;
    if (tags) file.tags = tags;
    if (isPublic !== undefined) file.isPublic = isPublic;

    await file.save();

    console.log('✅ Archivo actualizado:', file.name);
    res.json({
      message: 'Archivo actualizado correctamente',
      file
    });
  } catch (error) {
    console.error('❌ Error actualizando archivo:', error);
    res.status(500).json({ message: 'Error actualizando archivo.' });
  }
});

// 🔹 Eliminar archivo
app.delete('/api/files/:id', ensureAuthenticated, async (req, res) => {
  try {
    const file = await File.findById(req.params.id);
    if (!file) {
      return res.status(404).json({ message: 'Archivo no encontrado.' });
    }

    // Verificar que el usuario sea el propietario
    if (file.owner.toString() !== req.user._id.toString()) {
      return res.status(403).json({ message: 'No tienes permiso para eliminar este archivo.' });
    }

    await File.findByIdAndDelete(req.params.id);

    console.log('✅ Archivo eliminado:', file.name);
    res.json({ message: 'Archivo eliminado correctamente' });
  } catch (error) {
    console.error('❌ Error eliminando archivo:', error);
    res.status(500).json({ message: 'Error eliminando archivo.' });
  }
});

// ============================================================
// 🎨 BANNER/PORTADA DE PERFIL
// ============================================================

// Configuración de Cloudinary para banners (después de la config de profile pics)
const bannerStorage = new CloudinaryStorage({
  cloudinary: cloudinary.v2,
  params: {
    folder: process.env.CLOUDINARY_FOLDER_BANNERS || 'banners',
    allowed_formats: ['jpg', 'jpeg', 'png', 'webp'],
    transformation: [{ width: 1500, height: 500, crop: 'fill' }],
  },
});
const uploadBanner = multer({ storage: bannerStorage });

// 📤 Subir banner desde archivo
app.post('/api/users/me/banner', ensureAuthenticated, uploadBanner.single('bannerImage'), async (req, res) => {
  try {
    if (!req.file || !req.file.path) {
      return res.status(400).json({ message: 'No se recibió ninguna imagen.' });
    }

    const bannerUrl = req.file.path || req.file.secure_url;
    
    console.log('🎨 Actualizando banner con archivo:', bannerUrl);

    const updatedUser = await Usuario.findByIdAndUpdate(
      req.user._id,
      { bannerImage: bannerUrl },
      { new: true }
    );

    if (!updatedUser) {
      return res.status(404).json({ message: 'Usuario no encontrado.' });
    }

    console.log('✅ Banner actualizado correctamente');
    
    res.json({ 
      message: 'Banner actualizado correctamente.',
      bannerImage: updatedUser.bannerImage 
    });
  } catch (error) {
    console.error('❌ Error al subir banner:', error);
    res.status(500).json({ 
      message: 'Error al subir banner.',
      error: error.message 
    });
  }
});

// 🌐 Actualizar banner desde URL
app.put('/api/users/me/banner-url', ensureAuthenticated, async (req, res) => {
  try {
    const { imageUrl } = req.body;
    
    if (!imageUrl || !imageUrl.trim()) {
      return res.status(400).json({ message: 'URL de imagen requerida.' });
    }

    console.log('🌐 Actualizando banner con URL:', imageUrl);

    // Validar que sea una URL válida
    try {
      new URL(imageUrl);
    } catch (e) {
      return res.status(400).json({ message: 'URL inválida.' });
    }

    const updatedUser = await Usuario.findByIdAndUpdate(
      req.user._id,
      { bannerImage: imageUrl },
      { new: true }
    );

    if (!updatedUser) {
      return res.status(404).json({ message: 'Usuario no encontrado.' });
    }

    console.log('✅ Banner actualizado con URL');
    
    res.json({ 
      message: 'Banner actualizado correctamente.',
      bannerImage: updatedUser.bannerImage 
    });
  } catch (error) {
    console.error('❌ Error actualizando banner con URL:', error);
    res.status(500).json({ 
      message: 'Error al actualizar banner.',
      error: error.message 
    });
  }
});

// 🔹 Crear una colección
app.post('/api/collections', ensureAuthenticated, async (req, res) => {
  try {
    const { name, description, isPublic, coverImage } = req.body;

    if (!name || !name.trim()) {
      return res.status(400).json({ message: 'El nombre de la colección es requerido.' });
    }

    console.log('📚 Creando nueva colección:', name);

    const collection = await Collection.create({
      name: name.trim(),
      description: description?.trim() || '',
      owner: req.user._id,
      isPublic: isPublic !== undefined ? isPublic : true,
      coverImage: coverImage?.trim() || ''
    });

    const populated = await collection.populate('owner', 'username profilePic');

    console.log('✅ Colección creada:', collection.name);
    res.status(201).json({
      message: 'Colección creada exitosamente',
      collection: populated
    });
  } catch (error) {
    console.error('❌ Error creando colección:', error);
    res.status(500).json({
      message: 'Error al crear colección.',
      error: error.message
    });
  }
});

// 🔹 Obtener todas las colecciones del usuario
app.get('/api/collections', ensureAuthenticated, async (req, res) => {
  try {
    const collections = await Collection.find({ owner: req.user._id })
      .populate('recipes')
      .populate('owner', 'username profilePic')
      .sort({ createdAt: -1 });

    const collectionsWithCount = collections.map(col => ({
      ...col.toObject(),
      recipeCount: col.recipes?.length || 0
    }));

    console.log(`📚 ${collectionsWithCount.length} colecciones encontradas`);
    res.json(collectionsWithCount);
  } catch (error) {
    console.error('❌ Error obteniendo colecciones:', error);
    res.status(500).json({ message: 'Error obteniendo colecciones.' });
  }
});

// 🔹 Obtener una colección específica
app.get('/api/collections/:id', ensureAuthenticated, async (req, res) => {
  try {
    const collection = await Collection.findById(req.params.id)
      .populate('recipes')
      .populate('owner', 'username profilePic');

    if (!collection) {
      return res.status(404).json({ message: 'Colección no encontrada.' });
    }

    // Verificar permisos
    if (!collection.isPublic && collection.owner._id.toString() !== req.user._id.toString()) {
      return res.status(403).json({ message: 'No tienes permiso para ver esta colección.' });
    }

    res.json(collection);
  } catch (error) {
    console.error('❌ Error obteniendo colección:', error);
    res.status(500).json({ message: 'Error obteniendo colección.' });
  }
});

// 🔹 Actualizar una colección
app.put('/api/collections/:id', ensureAuthenticated, async (req, res) => {
  try {
    const { name, description, isPublic, coverImage } = req.body;
    
    const collection = await Collection.findById(req.params.id);
    if (!collection) {
      return res.status(404).json({ message: 'Colección no encontrada.' });
    }

    // Verificar que el usuario sea el propietario
    if (collection.owner.toString() !== req.user._id.toString()) {
      return res.status(403).json({ message: 'No tienes permiso para editar esta colección.' });
    }

    if (name) collection.name = name.trim();
    if (description !== undefined) collection.description = description.trim();
    if (isPublic !== undefined) collection.isPublic = isPublic;
    if (coverImage !== undefined) collection.coverImage = coverImage.trim();

    await collection.save();

    console.log('✅ Colección actualizada:', collection.name);
    res.json({
      message: 'Colección actualizada correctamente',
      collection
    });
  } catch (error) {
    console.error('❌ Error actualizando colección:', error);
    res.status(500).json({ message: 'Error actualizando colección.' });
  }
});

// 🔹 Eliminar una colección
app.delete('/api/collections/:id', ensureAuthenticated, async (req, res) => {
  try {
    const collection = await Collection.findById(req.params.id);
    if (!collection) {
      return res.status(404).json({ message: 'Colección no encontrada.' });
    }

    // Verificar que el usuario sea el propietario
    if (collection.owner.toString() !== req.user._id.toString()) {
      return res.status(403).json({ message: 'No tienes permiso para eliminar esta colección.' });
    }

    await Collection.findByIdAndDelete(req.params.id);

    console.log('✅ Colección eliminada:', collection.name);
    res.json({ message: 'Colección eliminada correctamente' });
  } catch (error) {
    console.error('❌ Error eliminando colección:', error);
    res.status(500).json({ message: 'Error eliminando colección.' });
  }
});

// 🔹 Agregar receta a una colección
app.post('/api/collections/:id/recipes/:recipeId', ensureAuthenticated, async (req, res) => {
  try {
    const { id, recipeId } = req.params;
    
    const collection = await Collection.findById(id);
    if (!collection) {
      return res.status(404).json({ message: 'Colección no encontrada.' });
    }

    // Verificar que el usuario sea el propietario
    if (collection.owner.toString() !== req.user._id.toString()) {
      return res.status(403).json({ message: 'No tienes permiso para modificar esta colección.' });
    }

    // Verificar que la receta existe
    const recipe = await Recipe.findById(recipeId);
    if (!recipe) {
      return res.status(404).json({ message: 'Receta no encontrada.' });
    }

    // Verificar si ya está en la colección
    if (collection.recipes.includes(recipeId)) {
      return res.status(400).json({ message: 'La receta ya está en esta colección.' });
    }

    collection.recipes.push(recipeId);
    await collection.save();

    console.log('✅ Receta agregada a colección');
    res.json({
      message: 'Receta agregada a la colección',
      collection
    });
  } catch (error) {
    console.error('❌ Error agregando receta a colección:', error);
    res.status(500).json({ message: 'Error agregando receta.' });
  }
});

// 🔹 Remover receta de una colección
app.delete('/api/collections/:id/recipes/:recipeId', ensureAuthenticated, async (req, res) => {
  try {
    const { id, recipeId } = req.params;
    
    const collection = await Collection.findById(id);
    if (!collection) {
      return res.status(404).json({ message: 'Colección no encontrada.' });
    }

    // Verificar que el usuario sea el propietario
    if (collection.owner.toString() !== req.user._id.toString()) {
      return res.status(403).json({ message: 'No tienes permiso para modificar esta colección.' });
    }

    collection.recipes.pull(recipeId);
    await collection.save();

    console.log('✅ Receta removida de colección');
    res.json({
      message: 'Receta removida de la colección',
      collection
    });
  } catch (error) {
    console.error('❌ Error removiendo receta:', error);
    res.status(500).json({ message: 'Error removiendo receta.' });
  }
});

// 🔹 Crear entrada de blog
app.post('/api/blog', ensureAuthenticated, async (req, res) => {
  try {
    const { title, content, excerpt, coverImage, tags, category, isPublished } = req.body;

    if (!title || !content) {
      return res.status(400).json({ message: 'Título y contenido son requeridos.' });
    }

    const blogPost = await BlogPost.create({
      title: title.trim(),
      content: content.trim(),
      excerpt: excerpt?.trim() || content.substring(0, 150) + '...',
      coverImage: coverImage?.trim() || '',
      author: req.user._id,
      tags: tags || [],
      category: category || 'General',
      isPublished: isPublished || false,
      publishedAt: isPublished ? new Date() : null
    });

    const populated = await blogPost.populate('author', 'username profilePic');

    console.log('✅ Entrada de blog creada:', blogPost.title);
    res.status(201).json({
      message: 'Entrada de blog creada exitosamente',
      blogPost: populated
    });
  } catch (error) {
    console.error('❌ Error creando entrada de blog:', error);
    res.status(500).json({ message: 'Error creando entrada de blog.' });
  }
});

// 🔹 Obtener todas las entradas del blog del usuario
app.get('/api/blog', ensureAuthenticated, async (req, res) => {
  try {
    const blogPosts = await BlogPost.find({ author: req.user._id })
      .populate('author', 'username profilePic')
      .sort({ createdAt: -1 });

    console.log(`📝 ${blogPosts.length} entradas de blog encontradas`);
    res.json(blogPosts);
  } catch (error) {
    console.error('❌ Error obteniendo blog:', error);
    res.status(500).json({ message: 'Error obteniendo entradas de blog.' });
  }
});

// 🔹 Obtener entradas públicas de un usuario específico
app.get('/api/blog/user/:userId', async (req, res) => {
  try {
    const blogPosts = await BlogPost.find({ 
      author: req.params.userId,
      isPublished: true 
    })
      .populate('author', 'username profilePic')
      .sort({ publishedAt: -1 });

    res.json(blogPosts);
  } catch (error) {
    console.error('❌ Error obteniendo blog público:', error);
    res.status(500).json({ message: 'Error obteniendo entradas de blog.' });
  }
});

// 🔹 Obtener una entrada específica del blog
app.get('/api/blog/:id', async (req, res) => {
  try {
    const blogPost = await BlogPost.findById(req.params.id)
      .populate('author', 'username profilePic');

    if (!blogPost) {
      return res.status(404).json({ message: 'Entrada no encontrada.' });
    }

    // Incrementar vistas
    blogPost.views += 1;
    await blogPost.save();

    res.json(blogPost);
  } catch (error) {
    console.error('❌ Error obteniendo entrada de blog:', error);
    res.status(500).json({ message: 'Error obteniendo entrada de blog.' });
  }
});

// 🔹 Actualizar entrada de blog
app.put('/api/blog/:id', ensureAuthenticated, async (req, res) => {
  try {
    const { title, content, excerpt, coverImage, tags, category, isPublished } = req.body;
    
    const blogPost = await BlogPost.findById(req.params.id);
    if (!blogPost) {
      return res.status(404).json({ message: 'Entrada no encontrada.' });
    }

    // Verificar que el usuario sea el autor
    if (blogPost.author.toString() !== req.user._id.toString()) {
      return res.status(403).json({ message: 'No tienes permiso para editar esta entrada.' });
    }

    if (title) blogPost.title = title.trim();
    if (content) blogPost.content = content.trim();
    if (excerpt !== undefined) blogPost.excerpt = excerpt.trim();
    if (coverImage !== undefined) blogPost.coverImage = coverImage.trim();
    if (tags) blogPost.tags = tags;
    if (category) blogPost.category = category;
    
    // Si se publica por primera vez
    if (isPublished && !blogPost.isPublished) {
      blogPost.publishedAt = new Date();
    }
    if (isPublished !== undefined) blogPost.isPublished = isPublished;

    await blogPost.save();

    console.log('✅ Entrada de blog actualizada:', blogPost.title);
    res.json({
      message: 'Entrada actualizada correctamente',
      blogPost
    });
  } catch (error) {
    console.error('❌ Error actualizando entrada de blog:', error);
    res.status(500).json({ message: 'Error actualizando entrada.' });
  }
});

// 🔹 Eliminar entrada de blog
app.delete('/api/blog/:id', ensureAuthenticated, async (req, res) => {
  try {
    const blogPost = await BlogPost.findById(req.params.id);
    if (!blogPost) {
      return res.status(404).json({ message: 'Entrada no encontrada.' });
    }

    // Verificar que el usuario sea el autor
    if (blogPost.author.toString() !== req.user._id.toString()) {
      return res.status(403).json({ message: 'No tienes permiso para eliminar esta entrada.' });
    }

    await BlogPost.findByIdAndDelete(req.params.id);

    console.log('✅ Entrada de blog eliminada:', blogPost.title);
    res.json({ message: 'Entrada eliminada correctamente' });
  } catch (error) {
    console.error('❌ Error eliminando entrada de blog:', error);
    res.status(500).json({ message: 'Error eliminando entrada.' });
  }
});

// 🔹 Dar like a entrada de blog
app.post('/api/blog/:id/like', ensureAuthenticated, async (req, res) => {
  try {
    const blogPost = await BlogPost.findById(req.params.id);
    if (!blogPost) {
      return res.status(404).json({ message: 'Entrada no encontrada.' });
    }

    const userId = req.user._id.toString();
    const idx = blogPost.likes.findIndex(u => u.toString() === userId);

    let liked = false;
    if (idx >= 0) {
      blogPost.likes.splice(idx, 1);
    } else {
      blogPost.likes.push(req.user._id);
      liked = true;
    }
    await blogPost.save();

    res.json({ liked, likesCount: blogPost.likes.length });
  } catch (error) {
    console.error('❌ Error con like en blog:', error);
    res.status(500).json({ message: 'Error al dar like.' });
  }
});

// ============================================================
// 👥 SISTEMA COMPLETO DE GRUPOS/COMUNIDADES
// ============================================================

const groupSchema = new mongoose.Schema({
  name: { type: String, required: true, unique: true },
  slug: { type: String, required: true, unique: true },
  description: { type: String, default: '' },
  image: { type: String, default: '' },
  members: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  admins: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  posts: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Post' }],
  createdBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  
  // ⚡ NUEVOS CAMPOS
  pinnedPosts: [{ 
    type: mongoose.Schema.Types.ObjectId, 
    ref: 'Post',
    default: [] 
  }],
  isPrivate: { 
    type: Boolean, 
    default: false 
  },
  rules: { 
    type: String, 
    default: '' 
  },
  tags: [{ 
    type: String 
  }]
}, { timestamps: true });

const Group = mongoose.models.Group || mongoose.model('Group', groupSchema);

// 🔹 Crear un nuevo grupo
app.post('/api/groups', ensureAuthenticated, async (req, res) => {
  try {
    const { name, description, image } = req.body;

    if (!name || !name.trim()) {
      return res.status(400).json({ message: 'El nombre del grupo es requerido.' });
    }

    console.log('✨ Creando nuevo grupo:', name);

    // Generar slug del nombre
    const slug = name.toLowerCase()
      .normalize('NFD').replace(/[\u0300-\u036f]/g, '') // Remover acentos
      .replace(/[^a-z0-9]+/g, '-')
      .replace(/^-+|-+$/g, '');

    // Verificar si ya existe
    const existing = await Group.findOne({ slug });
    if (existing) {
      return res.status(400).json({ 
        message: 'Ya existe un grupo con ese nombre.',
        suggestion: `${slug}-${Date.now().toString().slice(-4)}` // Sugerir alternativa
      });
    }

    const group = await Group.create({
      name: name.trim(),
      slug,
      description: description?.trim() || '',
      image: image?.trim() || '',
      members: [req.user._id],
      admins: [req.user._id],
      createdBy: req.user._id,
      posts: []
    });

    const populated = await group.populate('createdBy', 'username profilePic');

    console.log('✅ Grupo creado:', group.name, '| Slug:', group.slug);

    res.status(201).json({
      message: 'Grupo creado exitosamente',
      group: populated
    });
  } catch (error) {
    console.error('❌ Error creando grupo:', error);
    res.status(500).json({
      message: 'Error al crear grupo.',
      error: error.message
    });
  }
});

// 🔹 Listar todos los grupos (públicos)
app.get('/api/groups', ensureAuthenticated, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 20;
    const skip = (page - 1) * limit;

    const groups = await Group.find()
      .select('name slug description image members createdAt')
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(limit)
      .lean();

    const total = await Group.countDocuments();

    const groupsWithInfo = groups.map(group => ({
      ...group,
      memberCount: group.members?.length || 0,
      isMember: group.members?.some(m => m.toString() === req.user._id.toString()) || false
    }));

    console.log(`📋 ${groupsWithInfo.length} grupos encontrados (página ${page})`);

    res.json({
      groups: groupsWithInfo,
      pagination: {
        page,
        limit,
        total,
        pages: Math.ceil(total / limit)
      }
    });
  } catch (error) {
    console.error('❌ Error listando grupos:', error);
    res.status(500).json({ 
      message: 'Error listando grupos.',
      error: error.message 
    });
  }
});

// 🔹 Obtener información de un grupo específico
app.get('/api/groups/:slug', ensureAuthenticated, async (req, res) => {
  try {
    const { slug } = req.params;
    
    console.log('🔍 Buscando grupo con slug:', slug);
    
    const group = await Group.findOne({ slug })
      .populate('members', 'username profilePic status')
      .populate('admins', 'username profilePic')
      .populate('createdBy', 'username profilePic')
      .lean();

    if (!group) {
      return res.status(404).json({ message: 'Grupo no encontrado.' });
    }

    const isMember = group.members.some(
      member => member._id.toString() === req.user._id.toString()
    );

    const isAdmin = group.admins.some(
      admin => admin._id.toString() === req.user._id.toString()
    );

    const response = {
      ...group,
      isMember,
      isAdmin,
      memberCount: group.members.length,
      postCount: group.posts?.length || 0
    };

    console.log('✅ Grupo encontrado:', group.name);
    res.json(response);
  } catch (error) {
    console.error('❌ Error obteniendo grupo:', error);
    res.status(500).json({ 
      message: 'Error obteniendo información del grupo.',
      error: error.message 
    });
  }
});

// 🔹 Unirse o salir de un grupo
app.post('/api/groups/:slug/join', ensureAuthenticated, async (req, res) => {
  try {
    const { slug } = req.params;
    const userId = req.user._id;

    console.log('👥 Usuario', req.user.username, 'intentando unirse/salir del grupo:', slug);

    let group = await Group.findOne({ slug });

    if (!group) {
      // Solo crear automáticamente el grupo "food-emotions-team"
      if (slug === 'food-emotions-team') {
        group = await Group.create({
          name: 'FOOD EMOTIONS TEAM',
          slug: 'food-emotions-team',
          description: 'Comunidad oficial de desarrolladores creativos',
          image: 'https://res.cloudinary.com/demo/image/upload/sample.jpg',
          members: [userId],
          admins: [userId],
          createdBy: userId,
          posts: []
        });
        console.log('✨ Grupo "food-emotions-team" creado automáticamente');
        
        return res.json({
          joined: true,
          memberCount: 1,
          message: `Te has unido al grupo ${group.name}`
        });
      } else {
        return res.status(404).json({ message: 'Grupo no encontrado.' });
      }
    }

    const isMember = group.members.some(
      memberId => memberId.toString() === userId.toString()
    );

    if (isMember) {
      // Salir del grupo
      group.members.pull(userId);
      // Si era admin, también removerlo de admins
      if (group.admins.includes(userId)) {
        group.admins.pull(userId);
      }
      await group.save();
      
      console.log(`👋 ${req.user.username} salió del grupo: ${group.name}`);
      
      res.json({
        joined: false,
        memberCount: group.members.length,
        message: `Has salido del grupo ${group.name}`
      });
    } else {
      // Unirse al grupo
      group.members.push(userId);
      await group.save();
      
      console.log(`✅ ${req.user.username} se unió al grupo: ${group.name}`);
      
      res.json({
        joined: true,
        memberCount: group.members.length,
        message: `Te has unido al grupo ${group.name}`
      });
    }
  } catch (error) {
    console.error('❌ Error en unirse/salir del grupo:', error);
    res.status(500).json({ 
      message: 'Error al procesar solicitud del grupo.',
      error: error.message 
    });
  }
});

// 🔹 Actualizar grupo (solo admins)
app.put('/api/groups/:slug', ensureAuthenticated, async (req, res) => {
  try {
    const { slug } = req.params;
    const { name, description, image } = req.body;
    
    const group = await Group.findOne({ slug });
    if (!group) {
      return res.status(404).json({ message: 'Grupo no encontrado.' });
    }

    // Verificar que el usuario sea admin
    const isAdmin = group.admins.some(
      adminId => adminId.toString() === req.user._id.toString()
    );

    if (!isAdmin) {
      return res.status(403).json({ message: 'Solo los administradores pueden editar el grupo.' });
    }

    // Actualizar campos
    if (name && name.trim()) {
      group.name = name.trim();
      // Regenerar slug si cambió el nombre
      group.slug = name.toLowerCase()
        .normalize('NFD').replace(/[\u0300-\u036f]/g, '')
        .replace(/[^a-z0-9]+/g, '-')
        .replace(/^-+|-+$/g, '');
    }
    if (description !== undefined) group.description = description.trim();
    if (image !== undefined) group.image = image.trim();

    await group.save();

    console.log('✅ Grupo actualizado:', group.name);

    res.json({
      message: 'Grupo actualizado correctamente',
      group
    });
  } catch (error) {
    console.error('❌ Error actualizando grupo:', error);
    res.status(500).json({ 
      message: 'Error al actualizar grupo.',
      error: error.message 
    });
  }
});

// 🔹 Eliminar grupo (solo creador)
app.delete('/api/groups/:slug', ensureAuthenticated, async (req, res) => {
  try {
    const { slug } = req.params;
    
    const group = await Group.findOne({ slug });
    if (!group) {
      return res.status(404).json({ message: 'Grupo no encontrado.' });
    }

    // Verificar que el usuario sea el creador
    if (group.createdBy.toString() !== req.user._id.toString()) {
      return res.status(403).json({ message: 'Solo el creador puede eliminar el grupo.' });
    }

    await Group.findByIdAndDelete(group._id);

    console.log('✅ Grupo eliminado:', group.name);

    res.json({ message: 'Grupo eliminado correctamente' });
  } catch (error) {
    console.error('❌ Error eliminando grupo:', error);
    res.status(500).json({ 
      message: 'Error al eliminar grupo.',
      error: error.message 
    });
  }
});

// 🔹 Obtener posts de un grupo
app.get('/api/groups/:slug/posts', ensureAuthenticated, async (req, res) => {
  try {
    const { slug } = req.params;
    
    const group = await Group.findOne({ slug })
      .populate({
        path: 'posts',
        populate: { 
          path: 'author', 
          select: 'username profilePic' 
        },
        options: { sort: { createdAt: -1 } }
      })
      .lean();

    if (!group) {
      return res.status(404).json({ message: 'Grupo no encontrado.' });
    }

    console.log(`📸 ${group.posts?.length || 0} posts del grupo encontrados`);
    res.json(group.posts || []);
  } catch (error) {
    console.error('❌ Error obteniendo posts del grupo:', error);
    res.status(500).json({ 
      message: 'Error obteniendo posts del grupo.',
      error: error.message 
    });
  }
});

// 🔹 Publicar en un grupo
app.post('/api/groups/:slug/posts', ensureAuthenticated, uploadPostMedia.array('images', 10), async (req, res) => {
  try {
    const { slug } = req.params;
    const { caption = '', visibility = 'public' } = req.body;
    
    const group = await Group.findOne({ slug });
    if (!group) {
      return res.status(404).json({ message: 'Grupo no encontrado.' });
    }

    // Verificar que el usuario sea miembro
    const isMember = group.members.some(
      memberId => memberId.toString() === req.user._id.toString()
    );

    if (!isMember) {
      return res.status(403).json({ message: 'Debes ser miembro para publicar en este grupo.' });
    }

    const images = (req.files || []).map(f => f.path);

    if (!caption.trim() && images.length === 0) {
      return res.status(400).json({ message: 'El post debe tener texto o al menos una imagen.' });
    }

    const post = await Post.create({
      author: req.user._id,
      caption: caption.trim(),
      images,
      visibility,
      groupId: group._id // Importante: relacionar el post con el grupo
    });

    // Agregar post al grupo
    group.posts.push(post._id);
    await group.save();

    const populated = await post.populate('author', 'username profilePic');

    // Emitir evento de socket
    if (global.io) {
      global.io.emit('group-post-created', { 
        groupSlug: slug, 
        post: populated 
      });
    }

    console.log('✅ Post creado en grupo:', group.name);

    res.status(201).json({ 
      message: 'Post creado en el grupo',
      post: populated 
    });
  } catch (error) {
    console.error('❌ Error creando post en grupo:', error);
    res.status(500).json({ 
      message: 'Error al crear post en grupo.',
      error: error.message 
    });
  }
});

// 🔹 Actualizar grupo (solo admins)
app.put('/api/groups/:slug', ensureAuthenticated, async (req, res) => {
  try {
    const { slug } = req.params;
    const { name, description, image } = req.body;
    
    const group = await Group.findOne({ slug });
    if (!group) {
      return res.status(404).json({ message: 'Grupo no encontrado.' });
    }

    // Verificar que el usuario sea admin
    const isAdmin = group.admins.some(
      adminId => adminId.toString() === req.user._id.toString()
    );

    if (!isAdmin) {
      return res.status(403).json({ message: 'Solo los administradores pueden editar el grupo.' });
    }

    if (name) group.name = name.trim();
    if (description !== undefined) group.description = description.trim();
    if (image !== undefined) group.image = image.trim();

    // Si cambió el nombre, regenerar slug
    if (name) {
      group.slug = name.toLowerCase()
        .replace(/[^a-z0-9]+/g, '-')
        .replace(/^-+|-+$/g, '');
    }

    await group.save();

    console.log('✅ Grupo actualizado:', group.name);

    res.json({
      message: 'Grupo actualizado correctamente',
      group
    });
  } catch (error) {
    console.error('❌ Error actualizando grupo:', error);
    res.status(500).json({ 
      message: 'Error al actualizar grupo.',
      error: error.message 
    });
  }
});

// 🔹 Eliminar grupo (solo creador)
app.delete('/api/groups/:slug', ensureAuthenticated, async (req, res) => {
  try {
    const { slug } = req.params;
    
    const group = await Group.findOne({ slug });
    if (!group) {
      return res.status(404).json({ message: 'Grupo no encontrado.' });
    }

    // Verificar que el usuario sea el creador
    if (group.createdBy.toString() !== req.user._id.toString()) {
      return res.status(403).json({ message: 'Solo el creador puede eliminar el grupo.' });
    }

    await Group.findByIdAndDelete(group._id);

    console.log('✅ Grupo eliminado:', group.name);

    res.json({ message: 'Grupo eliminado correctamente' });
  } catch (error) {
    console.error('❌ Error eliminando grupo:', error);
    res.status(500).json({ 
      message: 'Error al eliminar grupo.',
      error: error.message 
    });
  }
});

// 🔹 Agregar/Remover admin (solo creador)
app.post('/api/groups/:slug/admins/:userId', ensureAuthenticated, async (req, res) => {
  try {
    const { slug, userId } = req.params;
    
    const group = await Group.findOne({ slug });
    if (!group) {
      return res.status(404).json({ message: 'Grupo no encontrado.' });
    }

    // Verificar que el usuario sea el creador
    if (group.createdBy.toString() !== req.user._id.toString()) {
      return res.status(403).json({ message: 'Solo el creador puede gestionar administradores.' });
    }

    const isAdmin = group.admins.some(
      adminId => adminId.toString() === userId
    );

    if (isAdmin) {
      // Remover admin
      group.admins.pull(userId);
      await group.save();
      res.json({ message: 'Administrador removido', isAdmin: false });
    } else {
      // Agregar admin
      group.admins.push(userId);
      await group.save();
      res.json({ message: 'Administrador agregado', isAdmin: true });
    }
  } catch (error) {
    console.error('❌ Error gestionando admin:', error);
    res.status(500).json({ 
      message: 'Error al gestionar administrador.',
      error: error.message 
    });
  }
});

// 🔹 Buscar grupos
app.get('/api/groups/search', ensureAuthenticated, async (req, res) => {
  try {
    const query = (req.query.q || '').trim();

    if (!query) {
      return res.status(400).json({ message: 'Se requiere un término de búsqueda.' });
    }

    console.log('🔍 Buscando grupos:', query);

    const groups = await Group.find({
      $or: [
        { name: { $regex: query, $options: 'i' } },
        { description: { $regex: query, $options: 'i' } }
      ]
    })
      .select('name slug description image members createdAt')
      .limit(20)
      .lean();

    const groupsWithInfo = groups.map(group => ({
      ...group,
      memberCount: group.members?.length || 0,
      isMember: group.members?.some(m => m.toString() === req.user._id.toString())
    }));

    console.log(`✅ ${groupsWithInfo.length} grupos encontrados`);
    res.json(groupsWithInfo);
  } catch (error) {
    console.error('❌ Error buscando grupos:', error);
    res.status(500).json({ message: 'Error buscando grupos.' });
  }
});

// 🔹 Obtener grupos del usuario (donde es miembro)
app.get('/api/users/me/groups', ensureAuthenticated, async (req, res) => {
  try {
    const groups = await Group.find({ members: req.user._id })
      .populate('createdBy', 'username profilePic')
      .sort({ createdAt: -1 })
      .lean();

    const groupsWithInfo = groups.map(group => ({
      ...group,
      memberCount: group.members?.length || 0,
      isAdmin: group.admins?.some(a => a.toString() === req.user._id.toString())
    }));

    console.log(`👥 ${groupsWithInfo.length} grupos del usuario`);
    res.json(groupsWithInfo);
  } catch (error) {
    console.error('❌ Error obteniendo grupos del usuario:', error);
    res.status(500).json({ message: 'Error obteniendo grupos.' });
  }
});

// 🔹 Obtener grupos donde el usuario es admin
app.get('/api/users/me/admin-groups', ensureAuthenticated, async (req, res) => {
  try {
    const groups = await Group.find({ admins: req.user._id })
      .populate('createdBy', 'username profilePic')
      .sort({ createdAt: -1 })
      .lean();

    const groupsWithInfo = groups.map(group => ({
      ...group,
      memberCount: group.members?.length || 0
    }));

    console.log(`⚡ ${groupsWithInfo.length} grupos administrados`);
    res.json(groupsWithInfo);
  } catch (error) {
    console.error('❌ Error obteniendo grupos administrados:', error);
    res.status(500).json({ message: 'Error obteniendo grupos.' });
  }
});

// 🔹 Obtener miembros de un grupo
app.get('/api/groups/:slug/members', ensureAuthenticated, async (req, res) => {
  try {
    const { slug } = req.params;
    
    const group = await Group.findOne({ slug })
      .populate('members', 'username profilePic status bio')
      .populate('admins', 'username profilePic')
      .lean();

    if (!group) {
      return res.status(404).json({ message: 'Grupo no encontrado.' });
    }

    // Marcar quiénes son admins
    const members = group.members.map(member => ({
      ...member,
      isAdmin: group.admins.some(admin => admin._id.toString() === member._id.toString())
    }));

    res.json(members);
  } catch (error) {
    console.error('❌ Error obteniendo miembros:', error);
    res.status(500).json({ message: 'Error obteniendo miembros.' });
  }
});

// 🔹 Expulsar miembro del grupo (solo admins)
app.delete('/api/groups/:slug/members/:userId', ensureAuthenticated, async (req, res) => {
  try {
    const { slug, userId } = req.params;
    
    const group = await Group.findOne({ slug });
    if (!group) {
      return res.status(404).json({ message: 'Grupo no encontrado.' });
    }

    // Verificar que el usuario sea admin
    const isAdmin = group.admins.some(
      adminId => adminId.toString() === req.user._id.toString()
    );

    if (!isAdmin) {
      return res.status(403).json({ message: 'Solo los administradores pueden expulsar miembros.' });
    }

    // No se puede expulsar al creador
    if (group.createdBy.toString() === userId) {
      return res.status(400).json({ message: 'No se puede expulsar al creador del grupo.' });
    }

    group.members.pull(userId);
    group.admins.pull(userId); // También remover de admins si lo era
    await group.save();

    console.log('👋 Miembro expulsado del grupo');
    res.json({ message: 'Miembro expulsado correctamente', memberCount: group.members.length });
  } catch (error) {
    console.error('❌ Error expulsando miembro:', error);
    res.status(500).json({ message: 'Error expulsando miembro.' });
  }
});

// 🔹 Eliminar publicación del grupo (autor o admin)
app.delete('/api/groups/:slug/posts/:postId', ensureAuthenticated, async (req, res) => {
  try {
    const { slug, postId } = req.params;
    
    const group = await Group.findOne({ slug });
    if (!group) {
      return res.status(404).json({ message: 'Grupo no encontrado.' });
    }
    
    const post = await Post.findById(postId);
    if (!post) {
      return res.status(404).json({ message: 'Publicación no encontrada.' });
    }
    
    // Verificar que sea el autor o admin
    const isAuthor = post.author.toString() === req.user._id.toString();
    const isAdmin = group.admins.some(
      adminId => adminId.toString() === req.user._id.toString()
    );
    
    if (!isAuthor && !isAdmin) {
      return res.status(403).json({ message: 'No tienes permiso para eliminar esta publicación.' });
    }
    
    // Eliminar post del grupo
    group.posts.pull(postId);
    await group.save();
    
    // Eliminar post de la base de datos
    await Post.findByIdAndDelete(postId);
    
    console.log('🗑️ Publicación eliminada del grupo:', group.name);
    res.json({ message: 'Publicación eliminada correctamente' });
    
  } catch (error) {
    console.error('❌ Error eliminando publicación:', error);
    res.status(500).json({ message: 'Error al eliminar publicación.' });
  }
});

// 🔹 Editar publicación del grupo (solo autor)
app.put('/api/groups/:slug/posts/:postId', ensureAuthenticated, async (req, res) => {
  try {
    const { slug, postId } = req.params;
    const { caption } = req.body;
    
    const group = await Group.findOne({ slug });
    if (!group) {
      return res.status(404).json({ message: 'Grupo no encontrado.' });
    }
    
    const post = await Post.findById(postId);
    if (!post) {
      return res.status(404).json({ message: 'Publicación no encontrada.' });
    }
    
    // Verificar que sea el autor
    if (post.author.toString() !== req.user._id.toString()) {
      return res.status(403).json({ message: 'Solo el autor puede editar esta publicación.' });
    }
    
    post.caption = caption.trim();
    post.edited = true;
    post.editedAt = Date.now();
    await post.save();
    
    const populated = await post.populate('author', 'username profilePic');
    
    console.log('✏️ Publicación editada en grupo:', group.name);
    res.json({ message: 'Publicación editada correctamente', post: populated });
    
  } catch (error) {
    console.error('❌ Error editando publicación:', error);
    res.status(500).json({ message: 'Error al editar publicación.' });
  }
});

// 🔹 Fijar/Desfijar publicación (solo admins)
app.post('/api/groups/:slug/posts/:postId/pin', ensureAuthenticated, async (req, res) => {
  try {
    const { slug, postId } = req.params;
    
    const group = await Group.findOne({ slug });
    if (!group) {
      return res.status(404).json({ message: 'Grupo no encontrado.' });
    }
    
    // Verificar que sea admin
    const isAdmin = group.admins.some(
      adminId => adminId.toString() === req.user._id.toString()
    );
    
    if (!isAdmin) {
      return res.status(403).json({ message: 'Solo los administradores pueden fijar publicaciones.' });
    }
    
    // Inicializar pinnedPosts si no existe
    if (!group.pinnedPosts) {
      group.pinnedPosts = [];
    }
    
    const isPinned = group.pinnedPosts.some(id => id.toString() === postId);
    
    if (isPinned) {
      // Desfijar
      group.pinnedPosts = group.pinnedPosts.filter(id => id.toString() !== postId);
      await group.save();
      res.json({ pinned: false, message: 'Publicación desfijada' });
    } else {
      // Fijar (máximo 3 posts fijados)
      if (group.pinnedPosts.length >= 3) {
        return res.status(400).json({ message: 'Máximo 3 publicaciones fijadas permitidas.' });
      }
      group.pinnedPosts.push(postId);
      await group.save();
      res.json({ pinned: true, message: 'Publicación fijada' });
    }
    
  } catch (error) {
    console.error('❌ Error fijando publicación:', error);
    res.status(500).json({ message: 'Error al fijar publicación.' });
  }
});

// 🔹 Obtener actividad reciente del grupo
app.get('/api/groups/:slug/activity', ensureAuthenticated, async (req, res) => {
  try {
    const { slug } = req.params;
    const { limit = 20 } = req.query;
    
    const group = await Group.findOne({ slug });
    if (!group) {
      return res.status(404).json({ message: 'Grupo no encontrado.' });
    }
    
    // Obtener actividad reciente
    const activity = [];
    
    // Publicaciones recientes
    const recentPosts = await Post.find({
      groupId: group._id
    })
      .populate('author', 'username profilePic')
      .sort({ createdAt: -1 })
      .limit(parseInt(limit));
    
    recentPosts.forEach(post => {
      activity.push({
        type: 'new_post',
        user: post.author,
        post: post,
        timestamp: post.createdAt,
        message: `${post.author.username} publicó en el grupo`
      });
    });
    
    res.json(activity);
    
  } catch (error) {
    console.error('❌ Error obteniendo actividad:', error);
    res.status(500).json({ message: 'Error al obtener actividad.' });
  }
});

// 🔹 Obtener estadísticas detalladas del grupo
app.get('/api/groups/:slug/stats', ensureAuthenticated, async (req, res) => {
  try {
    const { slug } = req.params;
    
    const group = await Group.findOne({ slug })
      .populate('members', '_id')
      .populate('admins', '_id')
      .populate('posts');
    
    if (!group) {
      return res.status(404).json({ message: 'Grupo no encontrado.' });
    }
    
    // Calcular estadísticas
    const totalLikes = group.posts.reduce((sum, post) => {
      return sum + (post.likes?.length || 0);
    }, 0);
    
    const totalComments = group.posts.reduce((sum, post) => {
      return sum + (post.comments?.length || 0);
    }, 0);
    
    const stats = {
      memberCount: group.members.length,
      adminCount: group.admins.length,
      postCount: group.posts.length,
      totalLikes,
      totalComments,
      avgLikesPerPost: group.posts.length > 0 ? (totalLikes / group.posts.length).toFixed(1) : 0,
      avgCommentsPerPost: group.posts.length > 0 ? (totalComments / group.posts.length).toFixed(1) : 0,
    };
    
    console.log('📊 Estadísticas del grupo:', group.name);
    res.json(stats);
    
  } catch (error) {
    console.error('❌ Error obteniendo estadísticas:', error);
    res.status(500).json({ message: 'Error al obtener estadísticas.' });
  }
});

// 🔹 Actualizar preferencias del usuario
app.put('/api/users/preferences', ensureAuthenticated, async (req, res) => {
  try {
    const { interests, notifications, language } = req.body;
    
    console.log('⚙️ Actualizando preferencias del usuario');

    const user = await Usuario.findById(req.user._id);
    
    if (!user) {
      return res.status(404).json({ message: 'Usuario no encontrado.' });
    }

    // Si el esquema no tiene preferences, puedes agregar campos adicionales
    if (interests) user.interests = interests;
    if (notifications !== undefined) user.notificationsEnabled = notifications;
    if (language) user.preferredLanguage = language;

    await user.save();

    console.log('✅ Preferencias actualizadas');
    
    res.json({ 
      message: 'Preferencias actualizadas correctamente.',
      preferences: {
        interests: user.interests,
        notifications: user.notificationsEnabled,
        language: user.preferredLanguage
      }
    });
  } catch (err) {
    console.error('❌ Error actualizando preferencias:', err);
    res.status(500).json({ 
      message: 'Error al actualizar preferencias.',
      error: err.message 
    });
  }
});

// 🔹 Obtener perfil público de un usuario (sin autenticación requerida para ver)
app.get('/api/users/:username/public-profile', async (req, res) => {
  try {
    const username = req.params.username;
    
    console.log('👤 Obteniendo perfil público de:', username);

    const user = await Usuario.findOne({ username })
      .select('username profilePic bio status followers following createdAt')
      .lean();

    if (!user) {
      return res.status(404).json({ message: 'Usuario no encontrado.' });
    }

    // Contar posts públicos
    const postsCount = await Post.countDocuments({ 
      author: user._id,
      visibility: 'public'
    });

    const publicProfile = {
      username: user.username,
      profilePic: user.profilePic,
      bio: user.bio,
      status: user.status,
      stats: {
        posts: postsCount,
        followers: user.followers?.length || 0,
        following: user.following?.length || 0
      },
      memberSince: user.createdAt
    };

    console.log('✅ Perfil público obtenido');
    
    res.json(publicProfile);
  } catch (err) {
    console.error('❌ Error obteniendo perfil público:', err);
    res.status(500).json({ 
      message: 'Error obteniendo perfil público.',
      error: err.message 
    });
  }
});

// 🔹 Verificar disponibilidad de username
app.get('/api/users/check-username/:username', async (req, res) => {
  try {
    const username = req.params.username;
    
    console.log('🔍 Verificando disponibilidad de username:', username);

    const existingUser = await Usuario.findOne({ username });

    res.json({ 
      available: !existingUser,
      message: existingUser 
        ? 'El nombre de usuario ya está en uso' 
        : 'El nombre de usuario está disponible'
    });
  } catch (err) {
    console.error('❌ Error verificando username:', err);
    res.status(500).json({ 
      message: 'Error verificando disponibilidad.',
      error: err.message 
    });
  }
});

// ============================================================
// ✅ FIX: MENSAJES DIRECTOS ENTRE USUARIOS
// ============================================================
const messageSchema = new mongoose.Schema({
  sender: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  recipient: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  text: { type: String, required: true },
  read: { type: Boolean, default: false },
}, { timestamps: true });

const Message = mongoose.model('Message', messageSchema);

app.get('/api/messages/conversations', ensureAuthenticated, async (req, res) => {
  try {
    const userId = req.user._id;
    
    // Populate sender y recipient
    const messages = await Message.find({
      $or: [{ sender: userId }, { recipient: userId }],
    })
      .populate({
        path: 'sender',
        select: 'username profilePic',
        match: { _id: { $ne: null } } // Solo si existe
      })
      .populate({
        path: 'recipient',
        select: 'username profilePic',
        match: { _id: { $ne: null } } // Solo si existe
      })
      .sort({ createdAt: -1 })
      .lean(); // Usar lean() para mejor performance

    const conversations = new Map();
    
    for (const msg of messages) {
      // SALTAR si sender o recipient son null
      if (!msg.sender || !msg.recipient) {
        console.warn('⚠️ Mensaje con usuario null, ID:', msg._id);
        continue;
      }

      // Determinar quién es el otro usuario
      const isFromMe = msg.sender._id.toString() === userId.toString();
      const partner = isFromMe ? msg.recipient : msg.sender;

      if (!partner || !partner._id) {
        console.warn('⚠️ Partner inválido en mensaje:', msg._id);
        continue;
      }

      const partnerId = partner._id.toString();

      // Solo guardar si es la conversación más reciente con ese usuario
      if (!conversations.has(partnerId)) {
        conversations.set(partnerId, {
          user: {
            _id: partner._id,
            username: partner.username || 'Usuario',
            profilePic: partner.profilePic || ''
          },
          lastMessage: msg.text || '',
          timestamp: msg.createdAt,
        });
      }
    }

    res.json(Array.from(conversations.values()));
  } catch (err) {
    console.error('❌ Error obteniendo conversaciones:', err);
    res.status(500).json({ 
      message: 'Error obteniendo conversaciones.',
      error: err.message 
    });
  }
});

// ============================================================
// 💬 CREAR O RECUPERAR CONVERSACIÓN ENTRE USUARIOS
// ============================================================
app.post('/api/messages/start', ensureAuthenticated, async (req, res) => {
  try {
    const { userId } = req.body;
    const currentUserId = req.user._id;

    if (!userId) return res.status(400).json({ message: 'Falta el ID del destinatario.' });
    if (userId === currentUserId.toString()) {
      return res.status(400).json({ message: 'No puedes chatear contigo mismo.' });
    }

    // Buscar si ya existe una conversación entre ambos
    let conversation = await Message.findOne({
      $or: [
        { sender: currentUserId, recipient: userId },
        { sender: userId, recipient: currentUserId },
      ],
    });

    // Si no existe, crear la primera entrada vacía (opcional)
    if (!conversation) {
      const newMsg = new Message({
        sender: currentUserId,
        recipient: userId,
        text: '👋 ¡Hola! Empezaron a chatear.',
      });
      await newMsg.save();
      conversation = newMsg;
    }

    res.json({
      message: 'Conversación lista.',
      recipientId: userId,
      chatId: conversation._id,
      redirectUrl: `/Messages?user=${userId}`,
    });
  } catch (err) {
    console.error('❌ Error creando conversación:', err);
    res.status(500).json({ message: 'Error creando conversación.' });
  }
});

app.get('/api/messages/:userId', ensureAuthenticated, async (req, res) => {
  try {
    const { userId } = req.params;
    const currentUserId = req.user._id;

    const messages = await Message.find({
      $or: [
        { sender: currentUserId, recipient: userId },
        { sender: userId, recipient: currentUserId },
      ],
    })
      .sort({ createdAt: 1 })
      .populate('sender', 'username profilePic')   // 👈 importante para el front
      .populate('recipient', 'username profilePic');

    res.json(messages);
  } catch (err) {
    console.error('❌ Error obteniendo mensajes:', err);
    res.status(500).json({ message: 'Error obteniendo mensajes.' });
  }
});

app.post('/api/messages/send', ensureAuthenticated, async (req, res) => {
  try {
    const { recipientId, text = '', fileUrl, type = 'text' } = req.body;

    if (!recipientId) {
      return res.status(400).json({ message: 'Falta el destinatario (recipientId).' });
    }

    const trimmedText = text.trim();
    if (!trimmedText && !fileUrl) {
      return res.status(400).json({ message: 'El mensaje debe tener texto o un archivo.' });
    }

    const msg = new Message({
      sender: req.user._id,
      recipient: recipientId,
      text: trimmedText,
      fileUrl: fileUrl || undefined,
      type: fileUrl ? (type || 'image') : 'text',
    });

    await msg.save();

    const populated = await Message.findById(msg._id)
      .populate('sender', 'username profilePic')
      .populate('recipient', 'username profilePic');

    // ⚡ Emitir en tiempo real
    const io = global.io;   // ya lo tienes definido

    if (io && populated) {
      const senderId = String(populated.sender._id);
      const receiverId = String(populated.recipient._id);

      // Rooms por usuario → notifica tanto al emisor como al receptor
      io.to(`user:${senderId}`).emit('new-message', populated);
      io.to(`user:${receiverId}`).emit('new-message', populated);
    }

    return res.status(201).json({
      message: 'Mensaje enviado.',
      data: populated,
    });
  } catch (err) {
    console.error('❌ Error enviando mensaje:', err);
    res.status(500).json({ message: 'Error enviando mensaje.' });
  }
});


// ============================================================
// 🗑️ ELIMINAR MENSAJES
// ============================================================

// Eliminar un mensaje individual
app.delete('/api/messages/:messageId', ensureAuthenticated, async (req, res) => {
  try {
    const { messageId } = req.params;
    const message = await Message.findById(messageId);

    if (!message) {
      return res.status(404).json({ message: 'Mensaje no encontrado.' });
    }

    // Verificar que el usuario es el remitente del mensaje
    if (message.sender.toString() !== req.user._id.toString()) {
      return res.status(403).json({ message: 'No tienes permiso para eliminar este mensaje.' });
    }

    await Message.findByIdAndDelete(messageId);

    // Emitir evento de socket para eliminar en tiempo real
    if (global.io) {
      global.io.emit('message-deleted', {
        messageId: messageId,
        senderId: message.sender,
        recipientId: message.recipient
      });
    }

    res.json({ message: 'Mensaje eliminado correctamente.' });
  } catch (err) {
    console.error('❌ Error eliminando mensaje:', err);
    res.status(500).json({ message: 'Error eliminando mensaje.' });
  }
});

// Eliminar toda una conversación con un usuario
app.delete('/api/messages/conversation/:userId', ensureAuthenticated, async (req, res) => {
  try {
    const { userId } = req.params;
    const currentUser = req.user._id;

    // Eliminar todos los mensajes entre ambos usuarios
    const result = await Message.deleteMany({
      $or: [
        { sender: currentUser, recipient: userId },
        { sender: userId, recipient: currentUser }
      ]
    });

    // Emitir evento de socket
    if (global.io) {
      global.io.emit('conversation-deleted', {
        userId1: currentUser.toString(),
        userId2: userId.toString()
      });
    }

    res.json({ 
      message: 'Conversación eliminada correctamente.',
      deletedCount: result.deletedCount 
    });
  } catch (err) {
    console.error('❌ Error eliminando conversación:', err);
    res.status(500).json({ message: 'Error eliminando conversación.' });
  }
});

// GET Feed con paginación y filtro
app.get('/api/posts/feed', ensureAuthenticated, async (req, res) => {
  try {
    const page  = parseInt(req.query.page ?? '1', 10);
    const limit = parseInt(req.query.limit ?? '10', 10);
    const filter = (req.query.filter ?? 'all');

    const q = {}; // simple: todos los públicos
    if (filter === 'following') {
      // solo posts de gente a la que sigo y públicos/seguidores
      const me = await Usuario.findById(req.user._id).select('following');
      q.author = { $in: me.following };
      q.visibility = { $in: ['public', 'followers'] };
    } else if (filter === 'trending') {
      // a falta de métricas reales: ordenamos por likes + reciente
      // lo resolvemos solo ordenando por likes length (post-procesado)
    } else {
      // 'all'
      q.visibility = 'public';
    }

    const posts = await Post.find(q)
      .populate('author', 'username profilePic')
      .sort({ createdAt: -1 })
      .skip((page - 1) * limit)
      .limit(limit)
      .lean();

    if (filter === 'trending') {
      posts.sort((a,b) => (b.likes?.length || 0) - (a.likes?.length || 0));
    }

    res.json({ posts, page, hasMore: posts.length === limit });
  } catch (err) {
    console.error('❌ Error feed:', err);
    res.status(500).json({ message: 'Error al cargar el feed' });
  }
});

// ============================================================
// ✅ FIX: LIKE / UNLIKE POSTS (para Social.astro)
// ============================================================
app.post('/api/posts/:id/like', ensureAuthenticated, async (req, res) => {
  try {
    const post = await Post.findById(req.params.id);
    if (!post) return res.status(404).json({ message: 'Post no encontrado.' });

    const userId = req.user._id.toString();
    const idx = post.likes.findIndex(u => u.toString() === userId);

    let liked = false;
    if (idx >= 0) {
      post.likes.splice(idx, 1);
    } else {
      post.likes.push(req.user._id);
      liked = true;
    }
    await post.save();

    // 🔔 Tiempo real: emite "post-liked"
    io.emit('post-liked', { postId: post._id, userId });

    res.json({ liked, likesCount: post.likes.length });
  } catch (err) {
    console.error('❌ Error like:', err);
    res.status(500).json({ message: 'Error al dar like.' });
  }
});

// ============================================================
// ✅ FIX: CRUD DE PUBLICACIONES (POSTS)
// ============================================================

// 🔹 Obtener todos los posts (feed principal)
app.get('/api/posts', ensureAuthenticated, async (req, res) => {
  try {
    const posts = await Post.find()
      .populate('author', 'username profilePic')
      .populate('comments.author', 'username profilePic')
      .sort({ createdAt: -1 });

    res.json(posts);
  } catch (err) {
    console.error('❌ Error obteniendo posts:', err);
    res.status(500).json({ message: 'Error obteniendo publicaciones.' });
  }
});

// 🔹 Crear una nueva publicación
app.post('/api/posts', ensureAuthenticated, uploadPostMedia.array('images', 10), async (req, res) => {
  try {
    const { caption = '', visibility = 'public' } = req.body;
    const tags = req.body.tags ? JSON.parse(req.body.tags) : [];
    const location = req.body.location || '';

    const images = (req.files || []).map(f => f.path);

    if (!caption.trim() && images.length === 0) {
      return res.status(400).json({ message: 'El post debe tener texto o una imagen.' });
    }

    const post = await Post.create({
      author: req.user._id,
      caption: caption.trim(),
      images,
      tags,
      location,
      visibility
    });

    const populated = await post.populate('author', 'username profilePic');
    // 🔔 Tiempo real: emite "post-created"
    io.emit('post-created', { post: populated });

    res.status(201).json({ message: 'Post creado correctamente.', post: populated });
  } catch (err) {
    console.error('❌ Error creando post:', err);
    res.status(500).json({ message: 'Error al crear post.' });
  }
});

// ============================================================
// 📝 CRUD COMPLETO DE POSTS (AGREGAR DESPUÉS DE app.get('/api/posts/:id'))
// ============================================================

// 🔹 ACTUALIZAR un post (solo el autor)
app.put('/api/posts/:id', ensureAuthenticated, async (req, res) => {
  try {
    const { caption, tags, location, visibility } = req.body;
    const post = await Post.findById(req.params.id);
    
    if (!post) {
      return res.status(404).json({ message: 'Post no encontrado.' });
    }

    // Verificar que el usuario es el autor
    if (post.author.toString() !== req.user._id.toString()) {
      return res.status(403).json({ message: 'No tienes permiso para editar este post.' });
    }

    // Actualizar campos
    if (caption !== undefined) post.caption = caption;
    if (tags !== undefined) post.tags = tags;
    if (location !== undefined) post.location = location;
    if (visibility !== undefined) post.visibility = visibility;

    await post.save();
    
    const updated = await post.populate('author', 'username profilePic');
    
    // Emitir evento de socket
    if (global.io) {
      global.io.emit('post-updated', { post: updated });
    }

    console.log('✅ Post actualizado:', post._id);
    res.json({ message: 'Post actualizado correctamente.', post: updated });
  } catch (err) {
    console.error('❌ Error actualizando post:', err);
    res.status(500).json({ message: 'Error actualizando post.', error: err.message });
  }
});

// 🔹 ELIMINAR un post (solo el autor)
app.delete('/api/posts/:id', ensureAuthenticated, async (req, res) => {
  try {
    const post = await Post.findById(req.params.id);
    
    if (!post) {
      return res.status(404).json({ message: 'Post no encontrado.' });
    }

    // Verificar que el usuario es el autor
    if (post.author.toString() !== req.user._id.toString()) {
      return res.status(403).json({ message: 'No tienes permiso para eliminar este post.' });
    }

    // Eliminar el post
    await Post.findByIdAndDelete(req.params.id);
    
    // Eliminar referencias en usuarios (savedPosts)
    await Usuario.updateMany(
      { savedPosts: req.params.id },
      { $pull: { savedPosts: req.params.id } }
    );

    // Emitir evento de socket
    if (global.io) {
      global.io.emit('post-deleted', { postId: req.params.id });
    }

    console.log('✅ Post eliminado:', req.params.id);
    res.json({ message: 'Post eliminado correctamente.' });
  } catch (err) {
    console.error('❌ Error eliminando post:', err);
    res.status(500).json({ message: 'Error eliminando post.', error: err.message });
  }
});

// 🔹 Obtener posts de un usuario específico
app.get('/api/users/:id/posts', ensureAuthenticated, async (req, res) => {
  try {
    const userId = req.params.id === 'me' ? req.user._id : req.params.id;
    
    console.log('📸 Obteniendo posts de usuario:', userId);

    const posts = await Post.find({ author: userId })
      .populate('author', 'username profilePic')
      .populate('comments.user', 'username profilePic')
      .sort({ createdAt: -1 })
      .lean();

    console.log(`✅ ${posts.length} posts encontrados`);
    res.json(posts);
  } catch (err) {
    console.error('❌ Error obteniendo posts del usuario:', err);
    res.status(500).json({ 
      message: 'Error obteniendo posts del usuario.',
      error: err.message 
    });
  }
});

// ============================================================
// 🔔 SISTEMA DE NOTIFICACIONES MEJORADO
// ============================================================

async function createNotification(recipientId, senderId, type, message, entityId = null) {
  try {
    // No crear notificación si el usuario se interactúa consigo mismo
    if (recipientId.toString() === senderId.toString()) {
      return null;
    }

    const notification = await Notification.create({
      recipient: recipientId,
      sender: senderId,
      type,
      message,
      entityId,
      read: false
    });

    const populated = await notification.populate('sender', 'username profilePic');

    // Emitir evento de socket
    if (global.io) {
      global.io.to(recipientId.toString()).emit('new-notification', populated);
    }

    console.log('🔔 Notificación creada:', type);
    return populated;
  } catch (err) {
    console.error('❌ Error creando notificación:', err);
    return null;
  }
}

// 🔹 LIKE EN POST CON NOTIFICACIÓN (REEMPLAZAR el endpoint existente)
app.post('/api/posts/:id/like', ensureAuthenticated, async (req, res) => {
  try {
    const post = await Post.findById(req.params.id).populate('author', 'username');
    if (!post) {
      return res.status(404).json({ message: 'Post no encontrado.' });
    }

    const userId = req.user._id.toString();
    const idx = post.likes.findIndex(u => u.toString() === userId);

    let liked = false;
    if (idx >= 0) {
      // Unlike
      post.likes.splice(idx, 1);
      console.log('💔 Like removido del post:', post._id);
    } else {
      // Like
      post.likes.push(req.user._id);
      liked = true;
      
      // 🔔 Crear notificación para el autor del post
      await createNotification(
        post.author._id,
        req.user._id,
        'like',
        `${req.user.username} le dio like a tu publicación`,
        post._id
      );
      
      console.log('❤️ Like agregado al post:', post._id);
    }
    
    await post.save();

    // Emitir evento de socket
    if (global.io) {
      global.io.emit('post-liked', { 
        postId: post._id, 
        userId,
        liked,
        likesCount: post.likes.length 
      });
    }

    res.json({ 
      liked, 
      likesCount: post.likes.length,
      message: liked ? 'Like agregado' : 'Like removido'
    });
  } catch (err) {
    console.error('❌ Error en like:', err);
    res.status(500).json({ message: 'Error al dar like.', error: err.message });
  }
});

// 🔹 COMENTAR POST CON NOTIFICACIÓN (REEMPLAZAR el endpoint existente)
app.post('/api/posts/:id/comments', ensureAuthenticated, async (req, res) => {
  try {
    const { text } = req.body;
    if (!text || !text.trim()) {
      return res.status(400).json({ message: 'El comentario no puede estar vacío.' });
    }

    const post = await Post.findById(req.params.id).populate('author', 'username');
    if (!post) {
      return res.status(404).json({ message: 'Post no encontrado.' });
    }

    const newComment = {
      user: req.user._id,
      text: text.trim(),
      createdAt: new Date(),
    };

    post.comments.push(newComment);
    await post.save();

    // 🔹 OBTENER COMENTARIOS DE UN POST
app.get('/api/posts/:id/comments', async (req, res) => {
  try {
    const post = await Post.findById(req.params.id)
      .populate({
        path: 'comments.user',
        select: 'username avatar'
      });
    
    if (!post) {
      return res.status(404).json({ message: 'Post no encontrado.' });
    }

    // Devolver solo los comentarios
    res.json(post.comments || []);
  } catch (error) {
    console.error('Error al obtener comentarios:', error);
    res.status(500).json({ message: 'Error al obtener comentarios.' });
  }
});

    // Poblar el comentario recién creado
    const populatedComment = await Post.populate(
      post.comments[post.comments.length - 1],
      { path: 'user', select: 'username profilePic' }
    );

    // 🔔 Crear notificación para el autor del post
    await createNotification(
      post.author._id,
      req.user._id,
      'comment',
      `${req.user.username} comentó tu publicación`,
      post._id
    );

    // Emitir evento de socket
    if (global.io) {
      global.io.emit('comment-added', {
        postId: post._id,
        comment: populatedComment,
        commentsCount: post.comments.length
      });
    }

    console.log('💬 Comentario agregado al post:', post._id);
    res.status(201).json({
      comment: populatedComment,
      commentsCount: post.comments.length
    });
  } catch (err) {
    console.error('❌ Error agregando comentario:', err);
    res.status(500).json({ message: 'Error al agregar comentario.', error: err.message });
  }
});

// 🔹 SEGUIR USUARIO CON NOTIFICACIÓN (REEMPLAZAR el endpoint existente)
app.post('/api/users/:id/follow', ensureAuthenticated, async (req, res) => {
  try {
    const targetId = req.params.id;
    const currentUserId = req.user._id;

    if (targetId === currentUserId.toString()) {
      return res.status(400).json({ message: 'No puedes seguirte a ti mismo.' });
    }

    const targetUser = await Usuario.findById(targetId);
    const currentUser = await Usuario.findById(currentUserId);

    if (!targetUser) {
      return res.status(404).json({ message: 'Usuario no encontrado.' });
    }

    const isFollowing = currentUser.following.includes(targetId);

    if (isFollowing) {
      // Unfollow
      currentUser.following.pull(targetId);
      targetUser.followers.pull(currentUserId);
      console.log(`👋 ${currentUser.username} dejó de seguir a ${targetUser.username}`);
    } else {
      // Follow
      currentUser.following.push(targetId);
      targetUser.followers.push(currentUserId);
      
      // 🔔 Crear notificación
      await createNotification(
        targetUser._id,
        currentUser._id,
        'follow',
        `${currentUser.username} comenzó a seguirte`
      );
      
      console.log(`✅ ${currentUser.username} ahora sigue a ${targetUser.username}`);
    }

    await currentUser.save();
    await targetUser.save();

    // Emitir evento de socket
    if (global.io) {
      global.io.emit('user-followed', {
        followerId: currentUserId,
        followedId: targetId,
        following: !isFollowing
      });
    }

    res.json({ 
      following: !isFollowing,
      followersCount: targetUser.followers.length,
      message: isFollowing 
        ? `Has dejado de seguir a ${targetUser.username}`
        : `Ahora sigues a ${targetUser.username}`
    });
  } catch (err) {
    console.error('❌ Error en follow:', err);
    res.status(500).json({ 
      message: 'Error al seguir o dejar de seguir usuario.',
      error: err.message 
    });
  }
});

// 🔹 Obtener notificaciones NO LEÍDAS del usuario
app.get('/api/notifications/unread', ensureAuthenticated, async (req, res) => {
  try {
    const notifications = await Notification.find({ 
      recipient: req.user._id,
      read: false 
    })
      .populate('sender', 'username profilePic')
      .sort({ createdAt: -1 })
      .limit(20)
      .lean();

    console.log(`🔔 ${notifications.length} notificaciones no leídas`);
    res.json(notifications);
  } catch (err) {
    console.error('❌ Error obteniendo notificaciones:', err);
    res.status(500).json({ message: 'Error obteniendo notificaciones.', error: err.message });
  }
});

// 🔹 Contar notificaciones no leídas
app.get('/api/notifications/unread-count', ensureAuthenticated, async (req, res) => {
  try {
    const count = await Notification.countDocuments({ 
      recipient: req.user._id,
      read: false 
    });

    res.json({ count });
  } catch (err) {
    console.error('❌ Error contando notificaciones:', err);
    res.status(500).json({ message: 'Error contando notificaciones.', error: err.message });
  }
});

// 🔹 Marcar una notificación específica como leída
app.put('/api/notifications/:id/read', ensureAuthenticated, async (req, res) => {
  try {
    const notification = await Notification.findOneAndUpdate(
      { _id: req.params.id, recipient: req.user._id },
      { read: true },
      { new: true }
    ).populate('sender', 'username profilePic');

    if (!notification) {
      return res.status(404).json({ message: 'Notificación no encontrada.' });
    }

    res.json({ message: 'Notificación marcada como leída', notification });
  } catch (err) {
    console.error('❌ Error marcando notificación:', err);
    res.status(500).json({ message: 'Error marcando notificación.', error: err.message });
  }
});

// 🔹 Eliminar una notificación
app.delete('/api/notifications/:id', ensureAuthenticated, async (req, res) => {
  try {
    const result = await Notification.findOneAndDelete({
      _id: req.params.id,
      recipient: req.user._id
    });

    if (!result) {
      return res.status(404).json({ message: 'Notificación no encontrada.' });
    }

    res.json({ message: 'Notificación eliminada correctamente.' });
  } catch (err) {
    console.error('❌ Error eliminando notificación:', err);
    res.status(500).json({ message: 'Error eliminando notificación.', error: err.message });
  }
});

// ============================================================
// 🔧 ENDPOINTS ADICIONALES ÚTILES
// ============================================================

// 🔹 Verificar si un usuario sigue a otro
app.get('/api/users/:id/is-following', ensureAuthenticated, async (req, res) => {
  try {
    const targetId = req.params.id;
    const currentUser = await Usuario.findById(req.user._id).select('following');
    
    const isFollowing = currentUser.following.some(
      id => id.toString() === targetId
    );

    res.json({ isFollowing });
  } catch (err) {
    console.error('❌ Error verificando follow:', err);
    res.status(500).json({ message: 'Error verificando seguimiento.', error: err.message });
  }
});

// 🔹 Verificar si un post está guardado
app.get('/api/posts/:id/is-saved', ensureAuthenticated, async (req, res) => {
  try {
    const postId = req.params.id;
    const user = await Usuario.findById(req.user._id).select('savedPosts');
    
    const isSaved = user.savedPosts.some(
      id => id.toString() === postId
    );

    res.json({ isSaved });
  } catch (err) {
    console.error('❌ Error verificando guardado:', err);
    res.status(500).json({ message: 'Error verificando guardado.', error: err.message });
  }
});

// 🔹 Verificar si un post tiene like del usuario
app.get('/api/posts/:id/is-liked', ensureAuthenticated, async (req, res) => {
  try {
    const postId = req.params.id;
    const post = await Post.findById(postId).select('likes');
    
    if (!post) {
      return res.status(404).json({ message: 'Post no encontrado.' });
    }

    const isLiked = post.likes.some(
      id => id.toString() === req.user._id.toString()
    );

    res.json({ 
      isLiked,
      likesCount: post.likes.length 
    });
  } catch (err) {
    console.error('❌ Error verificando like:', err);
    res.status(500).json({ message: 'Error verificando like.', error: err.message });
  }
});

// 🔹 Búsqueda de posts por hashtag
app.get('/api/posts/search/tags', ensureAuthenticated, async (req, res) => {
  try {
    const { tag } = req.query;
    
    if (!tag) {
      return res.status(400).json({ message: 'Tag requerido.' });
    }

    console.log('🔍 Buscando posts con tag:', tag);

    const posts = await Post.find({ 
      tags: { $regex: tag, $options: 'i' },
      visibility: 'public'
    })
      .populate('author', 'username profilePic')
      .sort({ createdAt: -1 })
      .limit(50)
      .lean();

    console.log(`✅ ${posts.length} posts encontrados con tag`);
    res.json(posts);
  } catch (err) {
    console.error('❌ Error buscando por tag:', err);
    res.status(500).json({ message: 'Error buscando posts.', error: err.message });
  }
});

// 🔹 Búsqueda general de posts
app.get('/api/posts/search/query', ensureAuthenticated, async (req, res) => {
  try {
    const { q } = req.query;
    
    if (!q) {
      return res.status(400).json({ message: 'Query requerido.' });
    }

    console.log('🔍 Buscando posts con query:', q);

    const posts = await Post.find({
      $or: [
        { caption: { $regex: q, $options: 'i' } },
        { tags: { $regex: q, $options: 'i' } },
        { location: { $regex: q, $options: 'i' } }
      ],
      visibility: 'public'
    })
      .populate('author', 'username profilePic')
      .sort({ createdAt: -1 })
      .limit(50)
      .lean();

    console.log(`✅ ${posts.length} posts encontrados`);
    res.json(posts);
  } catch (err) {
    console.error('❌ Error en búsqueda:', err);
    res.status(500).json({ message: 'Error buscando posts.', error: err.message });
  }
});

// ============================================================
// 📊 ESTADÍSTICAS MEJORADAS
// ============================================================

// 🔹 Dashboard completo del usuario
app.get('/api/users/me/dashboard', ensureAuthenticated, async (req, res) => {
  try {
    const userId = req.user._id;

    // Obtener datos del usuario
    const user = await Usuario.findById(userId)
      .select('username email profilePic bio followers following savedPosts')
      .lean();

    // Contar posts
    const postsCount = await Post.countDocuments({ author: userId });

    // Calcular likes totales recibidos
    const userPosts = await Post.find({ author: userId }).select('likes').lean();
    const totalLikesReceived = userPosts.reduce((sum, post) => sum + (post.likes?.length || 0), 0);

    // Contar comentarios recibidos
    const commentsReceived = userPosts.reduce((sum, post) => sum + (post.comments?.length || 0), 0);

    // Notificaciones no leídas
    const unreadNotifications = await Notification.countDocuments({
      recipient: userId,
      read: false
    });

    // Posts guardados
    const savedPostsCount = user.savedPosts?.length || 0;

    const dashboard = {
      user: {
        username: user.username,
        email: user.email,
        profilePic: user.profilePic,
        bio: user.bio
      },
      stats: {
        posts: postsCount,
        followers: user.followers?.length || 0,
        following: user.following?.length || 0,
        likesReceived: totalLikesReceived,
        commentsReceived: commentsReceived,
        savedPosts: savedPostsCount,
        unreadNotifications: unreadNotifications
      }
    };

    console.log('📊 Dashboard generado para:', user.username);
    res.json(dashboard);
  } catch (err) {
    console.error('❌ Error generando dashboard:', err);
    res.status(500).json({ message: 'Error generando dashboard.', error: err.message });
  }
});

// ============================================================
// 🔍 BUSCAR USUARIOS (para SearchBar)
// ============================================================
app.get('/api/users/search', ensureAuthenticated, async (req, res) => {
  try {
    const query = req.query.q?.trim();

    if (!query) {
      return res.status(400).json({ message: 'Se requiere un término de búsqueda.' });
    }

    // Buscar usuarios cuyo nombre contenga la query (ignorando mayúsculas/minúsculas)
    const users = await Usuario.find({
      username: { $regex: query, $options: 'i' }
    })
      .select('username profilePic bio _id') // solo los datos necesarios
      .limit(10);

    res.json(users);
  } catch (error) {
    console.error('❌ Error buscando usuarios:', error);
    res.status(500).json({ message: 'Error en la búsqueda de usuarios.', error: error.message });
  }
});

const httpServer = http.createServer(app);

const io = new SocketIOServer(httpServer, {
  cors: {
    origin: process.env.CLIENT_URL || 'http://localhost:4321',
    credentials: true,
  }
});
global.io = io; // para usar io en rutas

// Mapa opcional para saber quién está online (no es obligatorio, pero es útil)
const onlineUsers = new Map(); // userId -> Set(socketId)

io.on('connection', (socket) => {
  console.log('🔌 Nuevo socket conectado:', socket.id);

  // 1) Usuario se conecta (desde el frontend ya estás emitiendo 'user-connected')
  socket.on('user-connected', (userId) => {
    if (!userId) return;
    const cleanId = String(userId).replace(/"/g, '');

    if (!onlineUsers.has(cleanId)) {
      onlineUsers.set(cleanId, new Set());
    }
    onlineUsers.get(cleanId).add(socket.id);

    // Room por usuario
    socket.join(`user:${cleanId}`);
    console.log(`👤 Usuario ${cleanId} asociado al socket ${socket.id}`);
  });

  // 2) Entrada a un chat específico (room por conversación)
  socket.on('join-chat', ({ userId, recipientId }) => {
    if (!userId || !recipientId) return;
    const room = getChatRoomName(userId, recipientId);
    socket.join(room);
    console.log(`💬 Socket ${socket.id} se unió a room ${room}`);
  });

  // 3) Salir de un chat específico
  socket.on('leave-chat', ({ userId, recipientId }) => {
    if (!userId || !recipientId) return;
    const room = getChatRoomName(userId, recipientId);
    socket.leave(room);
    console.log(`↩️ Socket ${socket.id} salió de room ${room}`);
  });

  socket.on('disconnect', () => {
    // Limpieza rápida
    for (const [userId, sockets] of onlineUsers.entries()) {
      sockets.delete(socket.id);
      if (sockets.size === 0) {
        onlineUsers.delete(userId);
      }
    }
    console.log('❌ Socket desconectado:', socket.id);
  });
});

// Helper para generar un nombre único de room por par de usuarios
function getChatRoomName(userId1, userId2) {
  const a = String(userId1).replace(/"/g, '');
  const b = String(userId2).replace(/"/g, '');
  return a < b ? `chat:${a}:${b}` : `chat:${b}:${a}`;
}

// ============================================================
// ✅ INICIAR SERVIDOR CON SOCKET.IO
// ============================================================
const PORT = process.env.PORT || 3000;
httpServer.listen(PORT, () => {
  console.log(`🚀 Servidor con Socket.IO corriendo en http://localhost:${PORT}`);
  console.log('Esperando a que los modelos de IA terminen de cargar...');
});