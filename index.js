import express from "express";
import dotenv from "dotenv";
import cors from "cors";
import cookieParser from "cookie-parser";
import { MongoClient } from "mongodb";
import jwt from "jsonwebtoken";

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
// MongoDB Connection
// --------------------------------
const client = new MongoClient(process.env.MONGO_URI);
let db;

async function connectDB() {
  try {
    await client.connect();
    db = client.db("clubsphere");
    console.log("🔥 MongoDB Connected Successfully");
  } catch (error) {
    console.error("❌ MongoDB Connection Error:", error);
  }
}
connectDB();

// --------------------------------
// Collections
// --------------------------------
const Users = () => db.collection("users");
const Clubs = () => db.collection("clubs");
const Memberships = () => db.collection("memberships");

// --------------------------------
// JWT Middleware
// --------------------------------
function verifyToken(req, res, next) {
  const token = req.cookies.token;

  if (!token) {
    return res.status(401).json({ message: "No token found" });
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) {
      return res.status(403).json({ message: "Invalid token" });
    }

    req.user = decoded; // { email, role }
    next();
  });
}

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
