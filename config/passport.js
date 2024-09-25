const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const dotenv = require('dotenv');
const Usuario = require('./models/Usuario'); // Ajusta la ruta según tu estructura de archivos

// Cargar variables de entorno
dotenv.config();

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
          username: profile.displayName,
          email: profile.emails[0].value,
          profilePic: profile._json.picture, // Foto del perfil de Google
          bio: '', // Opcional: Agregar bio si la base de datos tiene un campo para ello
          status: 'Online' // Opcional: Estado del usuario
        });
        await user.save();
      }
      // Llamar a done con el usuario
      return done(null, user);
    } catch (error) {
      return done(error);
    }
  }
));

passport.serializeUser((user, done) => {
  done(null, user.id); // Solo serializar el ID del usuario
});

passport.deserializeUser(async (id, done) => {
  try {
    const user = await Usuario.findById(id);
    done(null, user);
  } catch (error) {
    done(error);
  }
});
