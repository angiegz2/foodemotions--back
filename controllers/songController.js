const Song = require('../models/Song');

exports.createSong = async (req, res) => {
  try {
    const song = await Song.create(req.body);
    res.status(201).json(song);
  } catch (err) {
    res.status(400).json({ message: 'Error creando canción', error: err.message });
  }
};

exports.getSongs = async (req, res) => {
  try {
    const songs = await Song.find();
    res.json(songs);
  } catch (err) {
    res.status(500).json({ message: 'Error obteniendo canciones' });
  }
};

exports.getSongById = async (req, res) => {
  try {
    const song = await Song.findById(req.params.id);
    if (!song) return res.status(404).json({ message: 'Canción no encontrada' });
    res.json(song);
  } catch (err) {
    res.status(500).json({ message: 'Error obteniendo canción' });
  }
};

exports.updateSong = async (req, res) => {
  try {
    const song = await Song.findByIdAndUpdate(req.params.id, req.body, { new: true });
    if (!song) return res.status(404).json({ message: 'Canción no encontrada' });
    res.json(song);
  } catch (err) {
    res.status(400).json({ message: 'Error actualizando canción', error: err.message });
  }
};

exports.deleteSong = async (req, res) => {
  try {
    const song = await Song.findByIdAndDelete(req.params.id);
    if (!song) return res.status(404).json({ message: 'Canción no encontrada' });
    res.json({ message: 'Canción eliminada correctamente' });
  } catch (err) {
    res.status(500).json({ message: 'Error eliminando canción' });
  }
};
