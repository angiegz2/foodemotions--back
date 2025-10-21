// models/ChatSession.js
import mongoose from "mongoose";

const chatSessionSchema = new mongoose.Schema({
  title: { type: String, default: "Nueva conversación" },
  createdBy: { type: mongoose.Schema.Types.ObjectId, ref: "User", default: null },
  messages: [
    {
      role: { type: String, enum: ["user", "assistant"], required: true },
      text: { type: String, required: true },
      ts: { type: Date, default: Date.now },
    },
  ],
}, { timestamps: true });

export default mongoose.model("ChatSession", chatSessionSchema);
