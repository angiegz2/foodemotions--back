const mongoose = require('mongoose');

const RecipeSchema = new mongoose.Schema({
  name: String,
  description: String,
  ingredients: [String],
  steps: [String],
  rating: { type: Number, min: 0, max: 5 }
});

module.exports = mongoose.model('Recipe', RecipeSchema);
