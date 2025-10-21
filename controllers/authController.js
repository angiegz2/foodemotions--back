const User = require('../models/User');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

// 🔹 Registro manual
exports.registerUser = async (req, res) => {
  try {
    const { username, email, phone, password } = req.body;

    // Validar si ya existe
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ message: 'El User ya existe.' });
    }

    // Crear y guardar User
    const newUser = new User({ username, email, phone, password });
    await newUser.save();

    // Generar token JWT
    const token = jwt.sign({ id: newUser._id }, process.env.JWT_SECRET, { expiresIn: '1d' });

    res.status(201).json({
      message: 'User registrado correctamente',
      user: newUser,
      token
    });
  } catch (err) {
    console.error('Error al registrar User:', err);
    res.status(500).json({ message: 'Error del servidor', error: err.message });
  }
};

// 🔹 Inicio de sesión manual
exports.loginUser = async (req, res) => {
  try {
    const { email, password } = req.body;

    // Verificar User
    const user = await User.findOne({ email });
    if (!user)
      return res.status(404).json({ message: 'User no encontrado' });

    // Comparar contraseñas
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch)
      return res.status(401).json({ message: 'Contraseña incorrecta' });

    // Generar token
    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '1d' });

    res.status(200).json({
      message: 'Inicio de sesión exitoso',
      user: {
        id: user._id,
        username: user.username,
        email: user.email
      },
      token
    });
  } catch (err) {
    console.error('Error en login:', err);
    res.status(500).json({ message: 'Error del servidor', error: err.message });
  }
};
