// models/User.js
import mongoose from "mongoose";
import bcrypt from "bcrypt";

const userSchema = new mongoose.Schema(
  {
    googleId: { type: String, default: null },

    // 🔹 Datos básicos del User
    username: { type: String, required: true },
    firstName: { type: String },
    lastName: { type: String },
    email: {
      type: String,
      required: true,
      unique: true,
      match: [/.+\@.+\..+/, "Correo electrónico inválido"],
    },
    phone: { type: String },
    password: { type: String, select: false }, // select:false evita enviarlo por error

    // 🔹 Personalización de perfil
    profilePic: {
      type: String,
      default: "https://ui-avatars.com/api/?name=User&background=72B340&color=fff",
    },
    bio: { type: String, default: "" },
    status: { type: String, default: "Online" },

    // 🔹 Relaciones sociales
    followers: [{ type: mongoose.Schema.Types.ObjectId, ref: "User" }],
    following: [{ type: mongoose.Schema.Types.ObjectId, ref: "User" }],

    // 🔹 Interacciones
    savedPosts: [{ type: mongoose.Schema.Types.ObjectId, ref: "Post" }],
    likedPosts: [{ type: mongoose.Schema.Types.ObjectId, ref: "Post" }],

    // 🔹 Estadísticas
    stats: {
      posts: { type: Number, default: 0 },
      followers: { type: Number, default: 0 },
      following: { type: Number, default: 0 },
    },
  },
  { timestamps: true }
);

// ============================================================
// 🔐 HASH AUTOMÁTICO DE CONTRASEÑA
// ============================================================
userSchema.pre("save", async function (next) {
  if (!this.isModified("password") || !this.password) return next();
  try {
    const salt = await bcrypt.genSalt(10);
    this.password = await bcrypt.hash(this.password, salt);
    next();
  } catch (err) {
    next(err);
  }
});

// ============================================================
// 🧩 MÉTODO PARA COMPARAR CONTRASEÑAS
// ============================================================
userSchema.methods.comparePassword = async function (password) {
  if (!this.password) return false;
  return await bcrypt.compare(password, this.password);
};

const User = mongoose.model("User", userSchema);
export default User;



