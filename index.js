import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import { MongoClient, ObjectId } from "mongodb";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import cookieParser from "cookie-parser";
import Stripe from "stripe";

dotenv.config();
const app = express();

// --------------------------------
// Config
// --------------------------------
const CLIENT_URL = process.env.CLIENT_URL || "http://localhost:5173";
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);

// --------------------------------
// Middleware
// --------------------------------
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
    console.log("🔥 MongoDB Connected");
  } catch (err) {
    console.error("❌ MongoDB Error:", err);
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
  if (!token) return res.status(401).json({ message: "No token" });

  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) return res.status(403).json({ message: "Invalid token" });
    req.user = decoded; // { email, role }
    next();
  });
}

// --------------------------------
// ROOT
// --------------------------------
app.get("/", (req, res) => {
  res.send("ClubSphere Backend Running");
});

// --------------------------------
// AUTH
// --------------------------------
app.post("/register", async (req, res) => {
  try {
    const { name, email, password } = req.body;
    if (!name || !email || !password)
      return res.status(400).json({ message: "All fields required" });

    const cleanEmail = email.toLowerCase();
    const exists = await Users().findOne({ email: cleanEmail });
    if (exists)
      return res.status(400).json({ message: "User already exists" });

    const hashed = await bcrypt.hash(password, 10);

    await Users().insertOne({
      name,
      email: cleanEmail,
      password: hashed,
      role: "member",
      createdAt: new Date(),
    });

    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ message: "Server error" });
  }
});

app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    const cleanEmail = email.toLowerCase();

    const user = await Users().findOne({ email: cleanEmail });
    if (!user) return res.status(400).json({ message: "Invalid credentials" });

    const match = await bcrypt.compare(password, user.password);
    if (!match)
      return res.status(400).json({ message: "Invalid credentials" });

    const token = jwt.sign(
      { email: user.email, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: "7d" }
    );

    res.cookie("token", token, {
      httpOnly: true,
      secure: false,
      sameSite: "lax",
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });

    res.json({ success: true, user });
  } catch (err) {
    res.status(500).json({ message: "Server error" });
  }
});

app.post("/logout", (req, res) => {
  res.clearCookie("token");
  res.json({ success: true });
});

// --------------------------------
// USER ROLE
// --------------------------------
app.get("/users/role/:email", verifyToken, async (req, res) => {
  if (req.params.email.toLowerCase() !== req.user.email)
    return res.status(403).json({ message: "Forbidden" });

  const user = await Users().findOne({ email: req.user.email });
  res.json({ role: user?.role || "member" });
});

// --------------------------------
// ADMIN — USERS
// --------------------------------
app.get("/admin/users", verifyToken, async (req, res) => {
  if (req.user.role !== "admin")
    return res.status(403).json({ message: "Admin only" });

  const users = await Users().find().toArray();
  res.json(users);
});

app.patch("/admin/users/role/:email", verifyToken, async (req, res) => {
  if (req.user.role !== "admin")
    return res.status(403).json({ message: "Admin only" });

  await Users().updateOne(
    { email: req.params.email.toLowerCase() },
    { $set: { role: req.body.role } }
  );

  res.json({ success: true });
});

app.delete("/admin/users/:email", verifyToken, async (req, res) => {
  if (req.user.role !== "admin")
    return res.status(403).json({ message: "Admin only" });

  await Users().deleteOne({ email: req.params.email.toLowerCase() });
  res.json({ success: true });
});

// --------------------------------
// MANAGER — CLUBS
// --------------------------------
app.post("/manager/clubs", verifyToken, async (req, res) => {
  if (req.user.role !== "manager")
    return res.status(403).json({ message: "Manager only" });

  const club = {
    ...req.body,
    membershipFee: Number(req.body.membershipFee) || 0,
    status: "pending",
    managerEmail: req.user.email,
    createdAt: new Date(),
  };

  await Clubs().insertOne(club);
  res.json({ success: true });
});

app.get("/manager/clubs", verifyToken, async (req, res) => {
  if (req.user.role !== "manager")
    return res.status(403).json({ message: "Manager only" });

  const clubs = await Clubs()
    .find({ managerEmail: req.user.email })
    .toArray();
  res.json(clubs);
});

// --------------------------------
// ADMIN — CLUB APPROVAL
// --------------------------------
app.get("/admin/clubs", verifyToken, async (req, res) => {
  if (req.user.role !== "admin")
    return res.status(403).json({ message: "Admin only" });

  const clubs = await Clubs().find().toArray();
  res.json(clubs);
});

app.patch("/admin/clubs/approve/:id", verifyToken, async (req, res) => {
  if (req.user.role !== "admin")
    return res.status(403).json({ message: "Admin only" });

  await Clubs().updateOne(
    { _id: new ObjectId(req.params.id) },
    { $set: { status: "approved" } }
  );

  res.json({ success: true });
});

app.patch("/admin/clubs/reject/:id", verifyToken, async (req, res) => {
  if (req.user.role !== "admin")
    return res.status(403).json({ message: "Admin only" });

  await Clubs().updateOne(
    { _id: new ObjectId(req.params.id) },
    { $set: { status: "rejected" } }
  );

  res.json({ success: true });
});

// --------------------------------
// PUBLIC — CLUBS
// --------------------------------
app.get("/clubs", async (req, res) => {
  const clubs = await Clubs().find({ status: "approved" }).toArray();
  res.json(clubs);
});

app.get("/clubs/:id", async (req, res) => {
  const id = new ObjectId(req.params.id);
  const club = await Clubs().findOne({ _id: id });
  const memberCount = await Memberships().countDocuments({ clubId: id });
  res.json({ ...club, memberCount });
});

app.get("/featured-clubs", async (req, res) => {
  const clubs = await Clubs()
    .find({ status: "approved" })
    .sort({ createdAt: -1 })
    .limit(6)
    .toArray();
  res.json(clubs);
});

// --------------------------------
// MEMBER — JOIN CLUB (FREE)
// --------------------------------
app.post("/clubs/join", verifyToken, async (req, res) => {
  const id = new ObjectId(req.body.clubId);
  const club = await Clubs().findOne({ _id: id });

  if (!club) return res.status(404).json({ message: "Club not found" });
  if (club.membershipFee > 0)
    return res.status(400).json({ message: "Paid club" });

  const exists = await Memberships().findOne({
    userEmail: req.user.email,
    clubId: id,
  });

  if (exists) return res.json({ alreadyJoined: true });

  await Memberships().insertOne({
    userEmail: req.user.email,
    clubId: id,
    status: "active",
    joinedAt: new Date(),
    expiryDate: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000),
  });

  res.json({ success: true });
});

// --------------------------------
// STRIPE — CLUB PAYMENT
// --------------------------------
app.post("/clubs/create-payment-intent", verifyToken, async (req, res) => {
  const id = new ObjectId(req.body.clubId);
  const club = await Clubs().findOne({ _id: id });

  if (!club || club.membershipFee <= 0)
    return res.status(400).json({ message: "Invalid club" });

  const amount = Math.round(club.membershipFee * 100);

  const intent = await stripe.paymentIntents.create({
    amount,
    currency: "usd",
    metadata: {
      clubId: club._id.toString(),
      userEmail: req.user.email,
    },
  });

  res.json({ clientSecret: intent.client_secret, amount });
});

app.post("/clubs/join/confirm", verifyToken, async (req, res) => {
  const { clubId, paymentIntentId } = req.body;
  const id = new ObjectId(clubId);

  const intent = await stripe.paymentIntents.retrieve(paymentIntentId);
  if (intent.status !== "succeeded")
    return res.status(400).json({ message: "Payment failed" });

  await Memberships().insertOne({
    userEmail: req.user.email,
    clubId: id,
    status: "active",
    joinedAt: new Date(),
    expiryDate: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000),
    paymentId: paymentIntentId,
  });

  res.json({ success: true });
});

// --------------------------------
// MEMBER — JOINED CLUBS
// --------------------------------
app.get("/member/clubs", verifyToken, async (req, res) => {
  const memberships = await Memberships()
    .find({ userEmail: req.user.email })
    .toArray();

  const clubIds = memberships.map((m) => m.clubId);
  const clubs = await Clubs()
    .find({ _id: { $in: clubIds } })
    .toArray();

  const result = memberships.map((m) => ({
    ...clubs.find((c) => String(c._id) === String(m.clubId)),
    joinedAt: m.joinedAt,
    expiryDate: m.expiryDate,
  }));

  res.json(result);
});

// --------------------------------
// START SERVER
// --------------------------------
const PORT = process.env.PORT || 5000;
app.listen(PORT, () =>
  console.log("🚀 Server running on port", PORT)
);
