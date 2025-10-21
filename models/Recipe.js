// models/Recipe.js
import mongoose from "mongoose";

const recipeSchema = new mongoose.Schema(
  {
    name: {
      type: String,
      required: true,
      trim: true,
    },
    description: {
      type: String,
      required: true,
      trim: true,
    },
    ingredients: {
      type: [String],
      required: true,
      validate: {
        validator: (arr) => arr.length > 0,
        message: "Debe incluir al menos un ingrediente.",
      },
    },
    steps: {
      type: [String],
      required: true,
      validate: {
        validator: (arr) => arr.length > 0,
        message: "Debe incluir al menos un paso de preparación.",
      },
    },
    rating: {
      type: Number,
      min: 0,
      max: 5,
      default: 0,
    },
    createdBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
    },
  },
  { timestamps: true }
);

export default mongoose.model("Recipe", recipeSchema);
