const mongoose = require('mongoose');
const User = require('./models/User'); // tu modelo definido en user.js

// Conectar a MongoDB
mongoose.connect('mongodb://localhost:27017/mi_base_de_datos')
  .then(async () => {
    // Crear un nuevo usuario
    const nuevoUsuario = new User({
      username: "prueba",
      firstName: "Test",
      lastName: "Ejemplo",
      email: "prueba@example.com",
      password: "123456",   // ⚡ se encripta automáticamente
      phone: "123456789"
    });

    // Guardar en la base
    await nuevoUsuario.save();
    console.log("✅ Usuario creado correctamente:", nuevoUsuario);

    // Cerrar conexión
    mongoose.disconnect();
  })
  .catch(err => console.error("❌ Error al guardar:", err));
