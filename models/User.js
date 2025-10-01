const mongoose = require('mongoose');
const bcrypt = require('bcrypt');

const userSchema = new mongoose.Schema({
  googleId: { type: String }, // Para login con Google (opcional)
  username: { type: String }, // Nombre de usuario general
  firstName: { type: String },
  lastName: { type: String },
  email: { 
    type: String, 
    required: true, 
    unique: true, 
    match: /.+\@.+\..+/ 
  }, 
  phone: { type: String },
  password: { type: String }, // será requerido solo en registro manual
  profilePic: { type: String },
  bio: { type: String },
  status: { type: String, default: 'Offline' },
}, { timestamps: true });

// Hash de la contraseña antes de guardar
userSchema.pre('save', async function(next) {
  if (!this.isModified('password') || !this.password) return next();
  try {
    const salt = await bcrypt.genSalt(10);
    this.password = await bcrypt.hash(this.password, salt);
    next();
  } catch (err) {
    next(err);
  }
});

// Método para comparar contraseñas
userSchema.methods.comparePassword = async function(password) {
  if (!this.password) return false; // usuario creado con Google no tiene pass
  return await bcrypt.compare(password, this.password);
};

module.exports = mongoose.model('User', userSchema);

