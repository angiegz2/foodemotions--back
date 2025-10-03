const Recipe = require('../models/Recipe');

// Crear receta
exports.createRecipe = async (req, res) => {
  try {
    const recipe = await Recipe.create(req.body);
    res.status(201).json(recipe);
  } catch (err) {
    res.status(400).json({ message: 'Error creando receta', error: err.message });
  }
};

// Obtener todas las recetas
exports.getRecipes = async (req, res) => {
  try {
    const recipes = await Recipe.find();
    res.json(recipes);
  } catch (err) {
    res.status(500).json({ message: 'Error obteniendo recetas' });
  }
};

// Obtener una receta por ID
exports.getRecipeById = async (req, res) => {
  try {
    const recipe = await Recipe.findById(req.params.id);
    if (!recipe) return res.status(404).json({ message: 'Receta no encontrada' });
    res.json(recipe);
  } catch (err) {
    res.status(500).json({ message: 'Error obteniendo receta' });
  }
};

// Actualizar receta
exports.updateRecipe = async (req, res) => {
  try {
    const recipe = await Recipe.findByIdAndUpdate(req.params.id, req.body, { new: true });
    if (!recipe) return res.status(404).json({ message: 'Receta no encontrada' });
    res.json(recipe);
  } catch (err) {
    res.status(400).json({ message: 'Error actualizando receta', error: err.message });
  }
};

// Eliminar receta
exports.deleteRecipe = async (req, res) => {
  try {
    const recipe = await Recipe.findByIdAndDelete(req.params.id);
    if (!recipe) return res.status(404).json({ message: 'Receta no encontrada' });
    res.json({ message: 'Receta eliminada correctamente' });
  } catch (err) {
    res.status(500).json({ message: 'Error eliminando receta' });
  }
};
