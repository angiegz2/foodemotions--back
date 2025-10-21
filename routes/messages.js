// routes/messages.js
import express from "express";
import Message from "../models/Message.js";
import User from "../models/User.js";
import { ensureAuthenticated } from "../middleware/auth.js";

const router = express.Router();

/* ======================================================
   💬 Enviar mensaje directo (única ruta de envío)
   ====================================================== */
router.post("/send", ensureAuthenticated, async (req, res) => {
  try {
    const { recipientId, text } = req.body;
    const senderId = req.user._id;

    if (!recipientId || !text) {
      return res.status(400).json({ message: "Datos incompletos." });
    }

    const newMessage = new Message({
      sender: senderId,
      recipient: recipientId,
      text,
    });

    await newMessage.save();

    // 🔥 Notificar en tiempo real
    if (global.io) {
      global.io.emit("new-message", {
        senderId,
        recipientId,
        text,
        createdAt: newMessage.createdAt,
      });
    }

    res.status(201).json({
      message: "Mensaje enviado correctamente.",
      data: newMessage,
    });
  } catch (error) {
    console.error("❌ Error enviando mensaje:", error);
    res.status(500).json({ message: "Error interno del servidor." });
  }
});

/* ======================================================
   📜 Obtener mensajes entre dos usuarios
   ====================================================== */
router.get("/:userId", ensureAuthenticated, async (req, res) => {
  try {
    const currentUserId = req.user._id;
    const otherUserId = req.params.userId;

    const messages = await Message.find({
      $or: [
        { sender: currentUserId, recipient: otherUserId },
        { sender: otherUserId, recipient: currentUserId },
      ],
    })
      .populate("sender", "username profilePic")
      .populate("recipient", "username profilePic")
      .sort({ createdAt: 1 });

    res.status(200).json(messages);
  } catch (error) {
    console.error("❌ Error obteniendo mensajes:", error);
    res.status(500).json({ message: "Error interno del servidor." });
  }
});

/* ======================================================
   💬 Listar conversaciones del usuario autenticado
   ====================================================== */
router.get("/conversations/list", ensureAuthenticated, async (req, res) => {
  try {
    const currentUserId = req.user._id;

    // Obtener las últimas conversaciones únicas
    const messages = await Message.find({
      $or: [{ sender: currentUserId }, { recipient: currentUserId }],
    })
      .sort({ createdAt: -1 })
      .populate("sender", "username profilePic isOnline")
      .populate("recipient", "username profilePic isOnline");

    const conversationsMap = new Map();

    messages.forEach((msg) => {
      const participant =
        msg.sender._id.toString() === currentUserId.toString()
          ? msg.recipient
          : msg.sender;

      if (!conversationsMap.has(participant._id.toString())) {
        conversationsMap.set(participant._id.toString(), {
          participant,
          lastMessage: msg,
          unreadCount: 0,
        });
      }
    });

    res.status(200).json([...conversationsMap.values()]);
  } catch (error) {
    console.error("❌ Error listando conversaciones:", error);
    res.status(500).json({ message: "Error interno del servidor." });
  }
});

export default router;
