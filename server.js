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

// Conexión a MongoDB
const mongoUri = process.env.MONGODB_URI || 'mongodb://localhost:27017/mi_base_de_datos';
mongoose.connect(mongoUri)
  .then(() => console.log('✅ Conexión exitosa a MongoDB'))
  .catch(err => console.error('❌ Error conectando a MongoDB:', err));

// Configuración Cloudinary
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

// Modelos Mongoose
const usuarioSchema = new mongoose.Schema({
  googleId: String,
  username: String,
  email: { type: String, required: true, unique: true },
  telefono: String,
  password: String,
  profilePic: String,
  bio: String,
  status: { type: String, default: 'Offline' },
  followers: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  following: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
}, { timestamps: true });

const Usuario = mongoose.model('User', usuarioSchema);

const recipeSchema = new mongoose.Schema({
  name: String,
  description: String,
  ingredients: [String],
  steps: [String],
  rating: { type: Number, min: 0, max: 5 },
}, { timestamps: true });

const Recipe = mongoose.model('Recipe', recipeSchema);

const chatSessionSchema = new mongoose.Schema({
  title: { type: String, default: 'Nueva conversación' },
  createdBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null },
  messages: [
    {
      role: { type: String, enum: ['user', 'assistant'], required: true },
      text: { type: String, required: true },
      ts: { type: Date, default: Date.now },
    }
  ],
}, { timestamps: true });

const ChatSession = mongoose.model('ChatSession', chatSessionSchema);

// Sesión y Passport
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
    let user = await Usuario.findOne({ googleId: profile.id });
    if (!user) {
      user = await Usuario.create({
        googleId: profile.id,
        username: profile.displayName,
        email: profile.emails?.[0]?.value,
        profilePic: profile._json?.picture,
        bio: '',
        status: 'Online',
      });
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

// Autenticación Google
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

// Perfil de usuario
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

// Seguir / dejar de seguir
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

// Recetas
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
// 🔊 MODELO DE VOZ (Text-to-Speech)
// ============================================================

let ttsPipeline = null;

(async () => {
  try {
    console.log("Cargando modelo de voz (SpeechT5-TTS)...");
    ttsPipeline = await pipeline("text-to-speech", "Xenova/speecht5_tts", {
      vocoder: "Xenova/unet_vocoder",
    });
    console.log("✅ Modelo de voz cargado correctamente.");
  } catch (err) {
    console.error("❌ Error cargando modelo de voz:", err.message);
  }
})();

// Configuración modelos de IA
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

async function localTranslate(text, to = "eng_Latn") {
  try {
    if (!translatePipeline) return text;
    const res = await translatePipeline(text, {
      tgt_lang: to,
      src_lang: to === "eng_Latn" ? "spa_Latn" : "eng_Latn"
    });
    return res?.[0]?.translation_text || text;
  } catch (err) {
    console.warn("Falló traducción local:", err.message);
    return text;
  }
}

function detectEmotion(text) {
  const t = (text || "").toLowerCase();
  if (/(feliz|contento|alegre|animado|genial|excelente)/.test(t)) return "happy";
  if (/(triste|mal|deprimido|solo|llorar)/.test(t)) return "sad";
  if (/(enojado|molesto|furioso|rabia|odio)/.test(t)) return "angry";
  if (/(tranquilo|relajado|en paz|calmado|sereno)/.test(t)) return "calm";
  return "neutral";
}

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

async function generateSpanishReply({ message, mode, history = [] }) {
  try {
    if (!chatPipeline || !translatePipeline) {
      return "Los modelos aún se están cargando, inténtalo en unos segundos.";
    }

    const englishInput = await localTranslate(message, "eng_Latn");
    const rolePrompt = getRolePrompt(mode);
    let prompt = `<|system|>\n${rolePrompt}</s>\n`;
    
    const recentHistory = history.slice(-3);
    for (const msg of recentHistory) {
      if (msg.role === "user") {
        prompt += `<|user|>\n${msg.text}</s>\n`;
      } else {
        prompt += `<|assistant|>\n${msg.text}</s>\n`;
      }
    }
    
    prompt += `<|user|>\n${englishInput}</s>\n<|assistant|>\n`;

    const gen = await chatPipeline(prompt, {
      max_new_tokens: 80,
      temperature: 0.7,
      top_p: 0.9,
      repetition_penalty: 1.2,
      return_full_text: false
    });

    let replyEn = gen?.[0]?.generated_text || "";
    replyEn = replyEn
      .replace(/<\|system\|>|<\|user\|>|<\|assistant\|>|<\/s>/g, "")
      .replace(/^(Assistant:|Roy:)/i, "")
      .split('\n')[0]
      .trim();
    
    if (replyEn.length > 500) {
      replyEn = replyEn.substring(0, 500).trim();
    }

    const replyEs = await localTranslate(replyEn, "spa_Latn");
    return replyEs.trim() || "Lo siento, no pude generar una respuesta adecuada.";
  } catch (err) {
    console.error("Error en generación:", err.message);
    return "Ocurrió un problema generando la respuesta. Por favor, intenta de nuevo.";
  }
}

// Endpoints de chat
app.post("/api/chat", async (req, res) => {
  try {
    if (!chatPipeline || !translatePipeline) {
      return res.status(503).json({ 
        error: "Modelos cargando...",
        message: "Los modelos de IA se están inicializando. Espera unos segundos."
      });
    }

    const { message, mode = "general" } = req.body || {};
    
    if (!message || !message.trim()) {
      return res.status(400).json({ error: "Mensaje vacío" });
    }

    const reply = await generateSpanishReply({ 
      message: message.trim(), 
      mode 
    });
    
    const emotion = detectEmotion(message);

    console.log(`Roy (${mode}): ${reply.substring(0, 100)}...`);
    
    res.json({ 
      reply, 
      emotion,
      mode,
      timestamp: new Date().toISOString()
    });
  } catch (err) {
    console.error("Error en chat:", err);
    res.status(500).json({ 
      error: "Error en el servidor del chat Roy.",
      details: err.message 
    });
  }
});

// ============================================================
// 🔉 ENDPOINT DE CHAT CON VOZ
// ============================================================

app.post("/api/chat/voice", async (req, res) => {
  try {
    if (!chatPipeline || !translatePipeline || !ttsPipeline) {
      return res.status(503).json({
        error: "Modelos cargando...",
        message: "Espera a que se inicialicen los modelos de IA y voz.",
      });
    }

    const { message, mode = "general" } = req.body || {};
    if (!message || !message.trim()) {
      return res.status(400).json({ error: "Mensaje vacío" });
    }

    // 1️⃣ Generar respuesta de texto
    const reply = await generateSpanishReply({ message: message.trim(), mode });
    const emotion = detectEmotion(message);

    // 2️⃣ Generar audio de la respuesta
    console.log("🎙️ Generando voz para la respuesta...");
    const audioResult = await ttsPipeline(reply);
    const audioBase64 = audioResult.audio[0];
    const audioBuffer = Buffer.from(audioBase64, "base64");

    // 3️⃣ Guardar archivo temporal
    const audioPath = path.resolve(`./audio_${Date.now()}.wav`);
    fs.writeFileSync(audioPath, audioBuffer);

    // 4️⃣ Enviar JSON con la ruta del audio y el texto
    res.json({
      reply,
      emotion,
      mode,
      audioUrl: `/audio/${path.basename(audioPath)}`,
      timestamp: new Date().toISOString(),
    });
  } catch (err) {
    console.error("❌ Error en /api/chat/voice:", err);
    res.status(500).json({
      error: "Error generando respuesta con voz.",
      details: err.message,
    });
  }
});

// Servir los audios generados
app.use("/audio", express.static(path.resolve("./")));

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
      history: chat.messages 
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
      timestamp: new Date().toISOString()
    });
  } catch (err) {
    console.error("Error en chat con historial:", err);
    res.status(500).json({ 
      error: "No se pudo procesar el mensaje.",
      details: err.message 
    });
  }
});

app.get("/api/status", (req, res) => {
  res.json({
    status: chatPipeline && translatePipeline ? "ready" : "loading",
    models: {
      chat: chatPipeline ? "loaded" : "loading",
      translate: translatePipeline ? "loaded" : "loading"
    }
  });
});

// Registro y login
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

    const isMatch = await bcrypt.compare(password, user.password || '');
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

// Iniciar servidor
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 Servidor corriendo en http://localhost:${PORT}`);
  console.log('Esperando a que los modelos de IA terminen de cargar...');
});
