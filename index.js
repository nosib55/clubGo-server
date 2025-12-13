import express from "express";
import dotenv from "dotenv";

dotenv.config();

const app = express();

// Root route
app.get("/", (req, res) => {
  res.send("ClubSphere Backend Running");
});

// Start server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log("🚀 Server running on port", PORT);
});
