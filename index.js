import express from "express";
import dotenv from "dotenv";
import cors from "cors";
import cookieParser from "cookie-parser";

dotenv.config();

const app = express();

// --------------------------------
// Middleware
// --------------------------------
const CLIENT_URL = process.env.CLIENT_URL || "http://localhost:5173";

app.use(express.json());

app.use(
  cors({
    origin: CLIENT_URL,
    credentials: true,
  })
);

app.use(cookieParser());

// --------------------------------
// Root route
// --------------------------------
app.get("/", (req, res) => {
  res.send("ClubSphere Backend Running");
});

// --------------------------------
// Start server
// --------------------------------
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log("🚀 Server running on port", PORT);
});
