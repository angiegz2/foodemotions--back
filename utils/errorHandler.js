exports.handleError = (res, error, message = 'Error en el servidor') => {
  console.error(error);
  res.status(500).json({ message, error: error.message });
};
