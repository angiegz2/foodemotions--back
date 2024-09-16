const express = require('express');
const session = require('express-session');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const dotenv = require('dotenv');
const cors = require('cors');
const mongoose = require('mongoose'); // Asegúrate de instalar mongoose con `npm install mongoose`

// Cargar variables de entorno
dotenv.config();

const app = express();
app.use(express.json()); // Para poder recibir datos en formato JSON

// Conectar a MongoDB
mongoose.connect('mongodb://localhost:27017/mi_base_de_datos', {
    useNewUrlParser: true,
    useUnifiedTopology: true,
}).then(() => {
    console.log('Conexión exitosa a MongoDB');
}).catch((err) => {
    console.error('Error conectando a MongoDB', err);
});

// Definir un esquema y modelo de usuario
const usuarioSchema = new mongoose.Schema({
    googleId: String, // Agrega un campo para almacenar el ID de Google
    username: String,
    email: String,
    telefono: String
});

const Usuario = mongoose.model('Usuario', usuarioSchema);

// Configuración de CORS
app.use(cors({ origin: 'http://localhost:4321' }));

// Configuración de express-session
app.use(session({
  secret: 'your-secret-key', 
  resave: false,
  saveUninitialized: true
}));

// Inicializa Passport y usa sesiones
app.use(passport.initialize());
app.use(passport.session());

// Configuración de Passport para Google OAuth
passport.use(new GoogleStrategy({
  clientID: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  callbackURL: "http://localhost:3000/auth/google/callback"
}, async function(accessToken, refreshToken, profile, done) {
  try {
    // Buscar o crear el usuario en la base de datos
    let user = await Usuario.findOne({ googleId: profile.id });
    if (!user) {
      user = new Usuario({
        googleId: profile.id,
        username: profile.displayName, // Usar el nombre del perfil como nombre de usuario
        email: profile.emails[0].value
      });
      await user.save();
    }
    return done(null, user);
  } catch (error) {
    return done(error);
  }
}));

passport.serializeUser((user, done) => {
  done(null, user);
});

passport.deserializeUser((obj, done) => {
  done(null, obj);
});

// Ruta para la raíz
app.get('/', (req, res) => {
  res.send('Bienvenido a la página de inicio!');
});

// Rutas para Google OAuth
app.get('/auth/google',
  passport.authenticate('google', { scope: ['profile', 'email'] })
);

app.get('/auth/google/callback', 
  passport.authenticate('google', { failureRedirect: '/login' }),
  function(req, res) {
    // Autenticación exitosa, redirigir al home
    res.redirect('/');
  });

// Ruta POST para insertar datos de prueba en la base de datos
app.post('/test-data', async (req, res) => {
  const { username, email, telefono, password } = req.body;

  try {
    // Crear un nuevo documento de usuario
    const nuevoUsuario = new Usuario({
      username,
      email,
      telefono,
      password
    });

    // Guardar el usuario en la base de datos
    await nuevoUsuario.save();

    res.status(200).json({ message: 'Datos de prueba guardados correctamente.' });
  } catch (error) {
    res.status(500).json({ message: 'Error guardando los datos.', error });
  }
});

// Iniciar servidor
app.listen(3000, () => {
  console.log('Servidor corriendo en http://localhost:3000');
})