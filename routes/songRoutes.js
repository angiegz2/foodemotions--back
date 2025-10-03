const express = require('express');
const { createSong, getSongs, getSongById, updateSong, deleteSong } = require('../controllers/songController');
const router = express.Router();

router.post('/', createSong);
router.get('/', getSongs);
router.get('/:id', getSongById);
router.put('/:id', updateSong);
router.delete('/:id', deleteSong);

module.exports = router;
