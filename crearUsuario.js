const mongoose = require('mongoose');
const User = require('./models/User'); // tu modelo definido en user.js

// Conectar a MongoDB
mongoose.connect('mongodb://localhost:27017/mi_base_de_datos')
  .then(async () => {
    // Crear un nuevo User
    const nuevoUser = new User({
      username: "prueba",
      firstName: "Test",
      lastName: "Ejemplo",
      email: "prueba@example.com",
      password: "123456",   // ⚡ se encripta automáticamente
      phone: "123456789"
    });

    // Guardar en la base
    await nuevoUser.save();
    console.log("✅ User creado correctamente:", nuevoUser);

    // Cerrar conexión
    mongoose.disconnect();
  })
  .catch(err => console.error("❌ Error al guardar:", err));
