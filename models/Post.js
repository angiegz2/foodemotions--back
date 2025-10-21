// models/Post.js
import mongoose from "mongoose";

const postSchema = new mongoose.Schema(
  {
    // 🔹 Autor del post
    author: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
    },

    // 🔹 Texto o descripción
    caption: {
      type: String,
      maxlength: 1000,
      trim: true,
    },

    // 🔹 Imágenes (subidas con Cloudinary)
    images: [
      {
        type: String,
        required: false,
      },
    ],

    // 🔹 Likes
    likes: [
      {
        type: mongoose.Schema.Types.ObjectId,
        ref: "User",
      },
    ],

    // 🔹 Comentarios (relación con Comment.js)
    comments: [
      {
        type: mongoose.Schema.Types.ObjectId,
        ref: "Comment",
      },
    ],

    // 🔹 Users que guardaron el post
    savedBy: [
      {
        type: mongoose.Schema.Types.ObjectId,
        ref: "User",
      },
    ],

    // 🔹 Para futuras categorías o etiquetas
    tags: [
      {
        type: String,
        trim: true,
      },
    ],
  },
  {
    timestamps: true, // crea createdAt y updatedAt automáticamente
  }
);

// ============================================================
// 📊 VIRTUAL: contador de likes y comentarios
// ============================================================
postSchema.virtual("likeCount").get(function () {
  return this.likes.length;
});

postSchema.virtual("commentCount").get(function () {
  return this.comments.length;
});

// ============================================================
// 🔹 POPULATE AUTOMÁTICO EN CONSULTAS
// ============================================================
postSchema.pre(/^find/, function (next) {
  this.populate("author", "username profilePic");
  next();
});

// ============================================================
// 🔹 LIMPIEZA AUTOMÁTICA DE COMENTARIOS RELACIONADOS
// ============================================================
postSchema.pre("remove", async function (next) {
  const Comment = mongoose.model("Comment");
  await Comment.deleteMany({ post: this._id });
  next();
});

const Post = mongoose.model("Post", postSchema);
export default Post;
