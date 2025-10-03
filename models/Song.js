const mongoose = require('mongoose');

const SongSchema = new mongoose.Schema({
  title: { type: String, required: true },
  artist: { type: String },
  album: { type: String },
  url: { type: String }, // link a Spotify/YouTube
  rating: { type: Number, min: 0, max: 5 }
}, { timestamps: true });

module.exports = mongoose.model('Song', SongSchema);
