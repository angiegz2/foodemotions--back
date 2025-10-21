// models/Comment.js
import mongoose from "mongoose";

const commentSchema = new mongoose.Schema(
  {
    // 🔹 Publicación a la que pertenece el comentario
    post: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Post",
      required: true,
    },

    // 🔹 Autor del comentario
    author: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
    },

    // 🔹 Texto del comentario
    text: {
      type: String,
      required: [true, "El comentario no puede estar vacío"],
      trim: true,
      maxlength: 500,
    },

    // 🔹 Likes en comentarios (opcional para escalabilidad futura)
    likes: [
      {
        type: mongoose.Schema.Types.ObjectId,
        ref: "User",
      },
    ],
  },
  { timestamps: true }
);

// ============================================================
// 🔹 POPULATE AUTOMÁTICO DE AUTOR
// ============================================================
commentSchema.pre(/^find/, function (next) {
  this.populate("author", "username profilePic");
  next();
});

const Comment = mongoose.model("Comment", commentSchema);
export default Comment;
