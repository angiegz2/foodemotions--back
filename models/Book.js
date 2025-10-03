const mongoose = require('mongoose');

const BookSchema = new mongoose.Schema({
  title: { type: String, required: true },
  author: { type: String },
  genre: { type: String },
  description: { type: String },
  rating: { type: Number, min: 0, max: 5 }
}, { timestamps: true });

module.exports = mongoose.model('Book', BookSchema);
