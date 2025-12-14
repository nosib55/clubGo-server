

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
const stripeSecret = process.env.STRIPE_SECRET_KEY;
const stripe = new Stripe(stripeSecret);

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
console.log("DB URI Loaded:", process.env.MONGO_URI);
const client = new MongoClient(process.env.MONGO_URI);

let db;

async function connectDB() {
  try {
    await client.connect();
    db = client.db("clubsphere");
    console.log("🔥 MongoDB Connected Successfully");
  } catch (err) {
    console.error("❌ MongoDB Connection Error:", err);
  }
}
connectDB();

// --------------------------------
// Collections
// --------------------------------
const Users = () => db.collection("users");
const Clubs = () => db.collection("clubs");
const ManagerRequests = () => db.collection("managerRequests");
const Memberships = () => db.collection("memberships");
const Events = () => db.collection("events");
const EventRegistrations = () => db.collection("eventRegistrations");
const Payments = () => db.collection("payments");

// --------------------------------
// JWT Middleware
// --------------------------------
function verifyToken(req, res, next) {
  const token = req.cookies.token;

  if (!token) return res.status(401).json({ message: "No token found" });

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ message: "Invalid token" });

    req.user = user; // { email, role }
    next();
  });
}

// --------------------------------
// ROOT ROUTE
// --------------------------------
app.get("/", (req, res) => {
  res.send("ClubSphere Backend Running (Stripe Version)");
});

// ===============================
// ⭐ AUTH (Firebase users)
// ===============================
app.post("/auth", async (req, res) => {
  try {
    const { name, email, photoURL } = req.body;
    if (!email) return res.status(400).json({ message: "Email required" });

    const cleanEmail = email.toLowerCase();

    let user = await Users().findOne({ email: cleanEmail });

    if (!user) {
      user = {
        name,
        email: cleanEmail,
        photoURL: photoURL || "",
        role: "member",
        createdAt: new Date(),
      };
      await Users().insertOne(user);
    }

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
  } catch (error) {
    console.error("AUTH ERROR:", error);
    res.status(500).json({ message: "Server error" });
  }
});

// optional password register/login (can be kept or removed)
app.post("/register", async (req, res) => {
  try {
    const { name, email, password, photoURL } = req.body;

    if (!email || !password || !name) {
      return res.status(400).json({ message: "Required fields missing" });
    }

    const cleanEmail = email.toLowerCase();
    const exist = await Users().findOne({ email: cleanEmail });
    if (exist) return res.status(400).json({ message: "User already exists" });

    const hashed = await bcrypt.hash(password, 10);

    const newUser = {
      name,
      email: cleanEmail,
      password: hashed,
      photoURL: photoURL || "",
      role: "member",
      createdAt: new Date(),
    };

    await Users().insertOne(newUser);
    res.json({ message: "Registration successful" });
  } catch (error) {
    console.error("REGISTER ERROR:", error);
    res.status(500).json({ message: "Server error" });
  }
});

app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    const cleanEmail = email.toLowerCase();

    const user = await Users().findOne({ email: cleanEmail });
    if (!user) return res.status(400).json({ message: "Invalid email" });

    const match = await bcrypt.compare(password, user.password || "");
    if (!match) return res.status(400).json({ message: "Wrong password" });

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

    res.json({ message: "Login done", user });
  } catch (error) {
    console.error("LOGIN ERROR:", error);
    res.status(500).json({ message: "Server error" });
  }
});

app.post("/logout", (req, res) => {
  res.clearCookie("token", {
    httpOnly: true,
    secure: false,
    sameSite: "lax",
  });
  res.json({ success: true });
});

// ===============================
// ⭐ USER ROLE FETCH (useRole hook)
// ===============================
app.get("/users/role/:email", verifyToken, async (req, res) => {
  try {
    const email = req.params.email.toLowerCase();

    if (email !== req.user.email) {
      return res.status(403).json({ message: "Forbidden" });
    }

    const user = await Users().findOne({ email });
    res.json({ role: user?.role || "member" });
  } catch (error) {
    console.error("ROLE FETCH ERROR:", error);
    res.status(500).json({ message: "Server error" });
  }
});

// ===============================
// ⭐ ADMIN — Manage Users
// ===============================
app.get("/admin/users", verifyToken, async (req, res) => {
  try {
    if (req.user.role !== "admin")
      return res.status(403).json({ message: "Admin only" });

    const users = await Users().find().toArray();
    res.json(users);
  } catch (error) {
    console.error("ADMIN USERS ERROR:", error);
    res.status(500).json({ message: "Server error" });
  }
});

app.patch("/admin/users/role/:email", verifyToken, async (req, res) => {
  try {
    if (req.user.role !== "admin")
      return res.status(403).json({ message: "Admin only" });

    await Users().updateOne(
      { email: req.params.email.toLowerCase() },
      { $set: { role: req.body.role } }
    );

    res.json({ success: true, message: "Role updated" });
  } catch (error) {
    console.error("ROLE UPDATE ERROR:", error);
    res.status(500).json({ message: "Server error" });
  }
});

app.delete("/admin/users/:email", verifyToken, async (req, res) => {
  try {
    if (req.user.role !== "admin")
      return res.status(403).json({ message: "Admin only" });

    await Users().deleteOne({ email: req.params.email.toLowerCase() });
    res.json({ success: true, message: "User deleted" });
  } catch (error) {
    console.error("ADMIN DELETE USER ERROR:", error);
    res.status(500).json({ message: "Server error" });
  }
});

// ===============================
// ⭐ MANAGER — Create Club
// ===============================
app.post("/manager/clubs", verifyToken, async (req, res) => {
  try {
    if (req.user.role !== "manager")
      return res.status(403).json({ message: "Manager only" });

    const {
      clubName,
      description,
      category,
      location,
      bannerImage,
      membershipFee,
    } = req.body;

    if (!clubName || !description || !category || !location || !bannerImage) {
      return res.status(400).json({ message: "All fields required" });
    }

    const newClub = {
      clubName,
      description,
      category,
      location,
      bannerImage,
      membershipFee: Number(membershipFee) || 0,
      status: "pending",
      managerEmail: req.user.email,
      createdAt: new Date(),
      updatedAt: new Date(),
    };

    await Clubs().insertOne(newClub);

    res.json({
      success: true,
      message: "Club created, waiting approval",
      newClub,
    });
  } catch (error) {
    console.error("CREATE CLUB ERROR:", error);
    res.status(500).json({ message: "Server error" });
  }
});

// ===============================
// ⭐ MANAGER — Get Own Clubs
// ===============================
app.get("/manager/clubs", verifyToken, async (req, res) => {
  try {
    if (req.user.role !== "manager")
      return res.status(403).json({ message: "Manager only" });

    const clubs = await Clubs()
      .find({ managerEmail: req.user.email })
      .toArray();

    res.json(clubs);
  } catch (error) {
    console.error("MANAGER CLUBS ERROR:", error);
    res.status(500).json({ message: "Server error" });
  }
});

// ===============================
// ⭐ ADMIN — Clubs
// ===============================
app.get("/admin/clubs", verifyToken, async (req, res) => {
  try {
    if (req.user.role !== "admin")
      return res.status(403).json({ message: "Admin only" });

    const clubs = await Clubs().find().toArray();
    res.json(clubs);
  } catch (error) {
    console.error("ADMIN CLUBS ERROR:", error);
    res.status(500).json({ message: "Server error" });
  }
});

app.patch("/admin/clubs/approve/:id", verifyToken, async (req, res) => {
  try {
    if (req.user.role !== "admin")
      return res.status(403).json({ message: "Admin only" });

    await Clubs().updateOne(
      { _id: new ObjectId(req.params.id) },
      { $set: { status: "approved" } }
    );

    res.json({ success: true });
  } catch (error) {
    console.error("APPROVE CLUB ERROR:", error);
    res.status(500).json({ message: "Server error" });
  }
});

app.patch("/admin/clubs/reject/:id", verifyToken, async (req, res) => {
  try {
    if (req.user.role !== "admin")
      return res.status(403).json({ message: "Admin only" });

    await Clubs().updateOne(
      { _id: new ObjectId(req.params.id) },
      { $set: { status: "rejected" } }
    );

    res.json({ success: true });
  } catch (error) {
    console.error("REJECT CLUB ERROR:", error);
    res.status(500).json({ message: "Server error" });
  }
});

// ===============================
// ⭐ PUBLIC — Clubs
// ===============================
app.get("/clubs", async (req, res) => {
  try {
    const { search, category, sort } = req.query;

    const query = { status: "approved" };

    if (search) {
      query.clubName = { $regex: search, $options: "i" };
    }

    if (category) {
      query.category = category;
    }

    let sortOption = {};
    if (sort === "newest") sortOption = { createdAt: -1 };
    if (sort === "oldest") sortOption = { createdAt: 1 };
    if (sort === "fee_high") sortOption = { membershipFee: -1 };
    if (sort === "fee_low") sortOption = { membershipFee: 1 };

    const clubs = await Clubs()
      .find(query)
      .sort(sortOption)
      .toArray();

    res.json(clubs);
  } catch (error) {
    console.error("GET CLUBS ERROR:", error);
    res.status(500).json({ message: "Server error" });
  }
});

//get club details with member count

app.get("/clubs/:id", async (req, res) => {
  try {
    if (!ObjectId.isValid(req.params.id)) {
      return res.status(400).json({ message: "Invalid club ID" });
    }

    const clubId = new ObjectId(req.params.id);
    const club = await Clubs().findOne({ _id: clubId });

    if (!club) {
      return res.status(404).json({ message: "Club not found" });
    }

    const memberCount = await Memberships().countDocuments({ clubId });
    res.json({ ...club, memberCount });

  } catch (err) {
    res.status(500).json({ message: "Server error" });
  }
});


app.get("/member/events/available", verifyToken, async (req, res) => {
  try {
    const memberships = await Memberships()
      .find({ userEmail: req.user.email })
      .toArray();

    if (!memberships.length) return res.json([]);

    // 🔧 convert ObjectId → string
    const clubIds = memberships.map(m => m.clubId.toString());

    const events = await Events()
      .find({ clubId: { $in: clubIds } })
      .sort({ eventDate: 1 })
      .toArray();

    res.json(events);
  } catch (err) {
    console.error("MEMBER EVENTS ERROR:", err);
    res.status(500).json({ message: "Server error" });
  }
});




// ⭐ FEATURED CLUBS
// ===============================
app.get("/featured-clubs", async (req, res) => {
  try {
    const clubs = await Clubs()
      .find({ status: "approved" })
      .sort({ createdAt: -1 })
      .limit(6)
      .toArray();

    res.json(clubs);
  } catch (error) {
    console.error("FEATURED CLUBS ERROR:", error);
    res.status(500).json({ message: "Server error" });
  }
});

// ===============================
// ⭐ MEMBER — Join Club FREE
// ===============================
app.post("/clubs/join", verifyToken, async (req, res) => {
  try {
    const { clubId } = req.body;
    const id = new ObjectId(clubId);

    const club = await Clubs().findOne({ _id: id });
    if (!club) return res.status(404).json({ message: "Club not found" });

    if (club.membershipFee > 0)
      return res.status(400).json({ message: "This is a paid club" });

    const exists = await Memberships().findOne({
      userEmail: req.user.email,
      clubId: id,
    });

    if (exists)
      return res.json({ message: "Already joined", alreadyJoined: true });

    const membership = {
      userEmail: req.user.email,
      clubId: id,
      status: "active",
      joinedAt: new Date(),
      expiryDate: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000),
      paymentId: null,
    };

    await Memberships().insertOne(membership);

    res.json({ success: true, membership });
  } catch (error) {
    console.log("JOIN CLUB ERROR:", error);
    res.status(500).json({ message: "Server error" });
  }
});


// ===============================
// ⭐ STRIPE — Club Payment Intent
// ===============================
app.post("/clubs/create-payment-intent", verifyToken, async (req, res) => {
  try {
    const { clubId } = req.body;
    const id = new ObjectId(clubId);

    const club = await Clubs().findOne({ _id: id, status: "approved" });
    if (!club) return res.status(404).json({ message: "Club not found" });

    const fee = Number(club.membershipFee) || 0;
    if (fee <= 0)
      return res.status(400).json({ message: "This club is free to join" });

    const exists = await Memberships().findOne({
      userEmail: req.user.email,
      clubId: id,
    });
    if (exists) return res.json({ message: "Already joined" });

    const amount = Math.round(fee * 100); // in cents

    const paymentIntent = await stripe.paymentIntents.create({
      amount,
      currency: "usd",
      metadata: {
        type: "club_membership",
        clubId: club._id.toString(),
        userEmail: req.user.email,
      },
    });

    res.json({
      clientSecret: paymentIntent.client_secret,
      clubName: club.clubName,
      amount,
    });
  } catch (error) {
    console.error("CLUB PAYMENT INTENT ERROR:", error);
    res.status(500).json({ message: "Server error" });
  }
});

// ===============================
// ⭐ STRIPE — Confirm Club Join
// ===============================
app.post("/clubs/join/confirm", verifyToken, async (req, res) => {
  try {
    const { clubId, paymentIntentId, amount } = req.body;
    const id = new ObjectId(clubId);

    const club = await Clubs().findOne({ _id: id });
    if (!club) return res.status(404).json({ message: "Club not found" });

    const paymentIntent = await stripe.paymentIntents.retrieve(paymentIntentId);
    if (paymentIntent.status !== "succeeded")
      return res.status(400).json({ message: "Payment not completed" });

    const exists = await Memberships().findOne({
      userEmail: req.user.email,
      clubId: id,
    });

    if (exists) return res.json({ message: "Already joined" });

    // Save payment
    const paymentDoc = {
      userEmail: req.user.email,
      clubId: id,
      amount: amount / 100,
      currency: "usd",
      paymentIntentId,
      type: "club",
      createdAt: new Date(),
    };

    const insertPayment = await Payments().insertOne(paymentDoc);

    // Create membership
    const membership = {
      userEmail: req.user.email,
      clubId: id,
      status: "active",
      joinedAt: new Date(),
      expiryDate: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000),
      paymentId: insertPayment.insertedId,
    };

    await Memberships().insertOne(membership);

    res.json({ success: true, membership });
  } catch (error) {
    console.log("CONFIRM CLUB PAYMENT ERROR:", error);
    res.status(500).json({ message: "Server error" });
  }
});

// ⭐ STRIPE — Club Checkout Session
app.post("/clubs/create-checkout-session", verifyToken, async (req, res) => {
  try {
    const { clubId } = req.body;
    const id = new ObjectId(clubId);

    const club = await Clubs().findOne({ _id: id, status: "approved" });
    if (!club) return res.status(404).json({ message: "Club not found" });

    if (club.membershipFee <= 0) {
      return res.status(400).json({ message: "This club is free" });
    }

    const existing = await Memberships().findOne({
      userEmail: req.user.email,
      clubId: id,
    });
    if (existing) return res.json({ message: "Already joined" });

    const session = await stripe.checkout.sessions.create({
      mode: "payment",
      payment_method_types: ["card"],
      customer_email: req.user.email,

      line_items: [
        {
          price_data: {
            currency: "usd",
            product_data: {
              name: club.clubName,
              description: "Club Membership",
            },
            unit_amount: Math.round(club.membershipFee * 100),
          },
          quantity: 1,
        },
      ],

success_url: `${CLIENT_URL}/clubs/${clubId}?success=true&session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: `${CLIENT_URL}/clubs/${clubId}?canceled=true`,

      metadata: {
        type: "club",
        clubId: clubId,
        userEmail: req.user.email,
      },
    });

    res.json({ url: session.url });
  } catch (error) {
    console.error("CHECKOUT SESSION ERROR:", error);
    res.status(500).json({ message: "Server error" });
  }
});



// ===============================
// ⭐ MEMBER — Joined Clubs
// ===============================
app.get("/member/clubs", verifyToken, async (req, res) => {
  try {
    const memberships = await Memberships()
      .find({ userEmail: req.user.email })
      .toArray();

    if (memberships.length === 0) {
      return res.json([]);
    }

    const clubIds = memberships.map((m) => m.clubId);

    const clubs = await Clubs()
      .find({ _id: { $in: clubIds } })
      .toArray();

    // merge membership + club
    const result = memberships.map((m) => {
      const club = clubs.find(
        (c) => String(c._id) === String(m.clubId)
      );

      return {
        ...club,
        membershipStatus: m.status,
        joinedAt: m.joinedAt,
        expiryDate: m.expiryDate,
        paymentId: m.paymentId,
      };
    });

    res.json(result);
  } catch (error) {
    console.error("MEMBER CLUBS ERROR:", error);
    res.status(500).json({ message: "Server error" });
  }
});



// ===============================
// ⭐ MANAGER — Create Event
// ===============================
app.post("/manager/events", verifyToken, async (req, res) => {
  try {
    if (req.user.role !== "manager")
      return res.status(403).json({ message: "Manager only" });

    const {
      clubId,
      title,
      description,
      eventDate,
      location,
      isPaid,
      eventFee,
      maxAttendees,
    } = req.body;

    if (!clubId || !title || !description || !eventDate || !location) {
      return res.status(400).json({ message: "Required fields missing" });
    }

    const eventDoc = {
      clubId,
      title,
      description,
      eventDate,
      location,
      isPaid: Boolean(isPaid),
      eventFee: isPaid ? Number(eventFee) || 0 : 0,
      maxAttendees: maxAttendees ? Number(maxAttendees) : null,
      managerEmail: req.user.email,
      createdAt: new Date(),
    };

    await Events().insertOne(eventDoc);

    res.json({ success: true, newEvent: eventDoc });
  } catch (error) {
    console.error("CREATE EVENT ERROR:", error);
    res.status(500).json({ message: "Server error" });
  }
});

// ===============================
// ⭐ PUBLIC — Events
// ===============================
app.get("/events", async (req, res) => {
  try {
    const events = await Events().find().toArray();
    res.json(events);
  } catch (error) {
    console.error("GET EVENTS ERROR:", error);
    res.status(500).json({ message: "Server error" });
  }
});

app.get("/events/:id", async (req, res) => {
  try {
    const event = await Events().findOne({
      _id: new ObjectId(req.params.id),
    });
    res.json(event);
  } catch (error) {
    console.error("GET EVENT DETAIL ERROR:", error);
    res.status(500).json({ message: "Server error" });
  }
});

// ===============================
// ⭐ MANAGER — Own Events
// ===============================
app.get("/manager/events", verifyToken, async (req, res) => {
  try {
    if (req.user.role !== "manager")
      return res.status(403).json({ message: "Manager only" });

    const events = await Events()
      .find({ managerEmail: req.user.email })
      .toArray();

    res.json(events);
  } catch (error) {
    console.error("MANAGER EVENTS ERROR:", error);
    res.status(500).json({ message: "Server error" });
  }
});

// ===============================
// ⭐ MEMBER — Register for Event
// ===============================
app.post("/events/join", verifyToken, async (req, res) => {
  try {
    const { eventId } = req.body;
    if (!eventId)
      return res.status(400).json({ message: "Event ID required" });

    const id = new ObjectId(eventId);

    const event = await Events().findOne({ _id: id });
    if (!event) return res.status(404).json({ message: "Event not found" });

    const exists = await EventRegistrations().findOne({
      eventId: id,
      userEmail: req.user.email,
    });

    if (exists) return res.json({ message: "Already registered" });

    if (event.maxAttendees) {
      const count = await EventRegistrations().countDocuments({ eventId: id });
      if (count >= event.maxAttendees) {
        return res.status(400).json({ message: "Event is full" });
      }
    }

    const registration = {
      eventId: id,
      clubId: new ObjectId(event.clubId),
      userEmail: req.user.email,
      status: event.isPaid ? "pending_payment" : "registered",
      paidAmount: event.isPaid ? event.eventFee : 0,
      joinedAt: new Date(),
    };

    await EventRegistrations().insertOne(registration);

    res.json({
      success: true,
      message: "Event registration created",
      registration,
    });
  } catch (error) {
    console.error("JOIN EVENT ERROR:", error);
    res.status(500).json({ message: "Server error" });
  }
});

// ===============================
// ⭐ STRIPE — Event Payment Intent
// ===============================
app.post("/events/create-payment-intent", verifyToken, async (req, res) => {
  try {
    const { eventId } = req.body;
    const id = new ObjectId(eventId);

    const event = await Events().findOne({ _id: id });
    if (!event) return res.status(404).json({ message: "Event not found" });

    if (!event.isPaid || !event.eventFee) {
      return res.status(400).json({ message: "This event is free" });
    }

    const fee = Number(event.eventFee) || 0;
    const amount = Math.round(fee * 100);

    const paymentIntent = await stripe.paymentIntents.create({
      amount,
      currency: "usd",
      metadata: {
        type: "event_registration",
        eventId: event._id.toString(),
        userEmail: req.user.email,
      },
    });

    res.json({
      clientSecret: paymentIntent.client_secret,
      title: event.title,
      amount,
    });
  } catch (error) {
    console.error("EVENT PAYMENT INTENT ERROR:", error);
    res.status(500).json({ message: "Server error" });
  }
});

// ===============================
// ⭐ STRIPE — Confirm Event Payment
// ===============================
app.post("/events/join/confirm", verifyToken, async (req, res) => {
  try {
    const { eventId, paymentIntentId, transactionId, amount } = req.body;
    const id = new ObjectId(eventId);

    const event = await Events().findOne({ _id: id });
    if (!event) return res.status(404).json({ message: "Event not found" });

    let paymentIntent = null;
    if (paymentIntentId) {
      paymentIntent = await stripe.paymentIntents.retrieve(paymentIntentId);
      if (paymentIntent.status !== "succeeded") {
        return res.status(400).json({ message: "Payment not completed" });
      }
    }

    const reg = await EventRegistrations().findOne({
      eventId: id,
      userEmail: req.user.email,
    });

    if (!reg) {
      return res.status(400).json({ message: "Registration not found" });
    }

    // save payment
    const paymentDoc = {
      userEmail: req.user.email,
      clubId: new ObjectId(event.clubId),
      eventId: id,
      type: "event",
      amount: Number(amount) || Number(event.eventFee) || 0,
      currency: "usd",
      paymentIntentId: paymentIntentId || null,
      transactionId: transactionId || null,
      createdAt: new Date(),
    };

    const paymentResult = await Payments().insertOne(paymentDoc);

    await EventRegistrations().updateOne(
      { _id: reg._id },
      {
        $set: {
          status: "registered",
          paidAmount: paymentDoc.amount,
          paymentId: paymentResult.insertedId,
        },
      }
    );

    res.json({ success: true });
  } catch (error) {
    console.error("CONFIRM EVENT PAYMENT ERROR:", error);
    res.status(500).json({ message: "Server error" });
  }
});

// ===============================
// ⭐ MEMBER — Joined Events (full)
// ===============================
app.get("/member/events", verifyToken, async (req, res) => {
  try {
    const regs = await EventRegistrations()
      .find({ userEmail: req.user.email })
      .toArray();

    if (regs.length === 0) return res.json([]);

    const eventIds = regs.map((r) => r.eventId);

    const events = await Events()
      .find({ _id: { $in: eventIds } })
      .toArray();

    res.json(events);
  } catch (error) {
    console.error("MEMBER JOINED EVENTS ERROR:", error);
    res.status(500).json({ message: "Server error" });
  }
});

// ===============================
// ⭐ MANAGER — View Registrations for Event
// ===============================
app.get(
  "/manager/events/registrations/:eventId",
  verifyToken,
  async (req, res) => {
    try {
      if (req.user.role !== "manager")
        return res.status(403).json({ message: "Manager only" });

      const eventId = new ObjectId(req.params.eventId);

      const event = await Events().findOne({
        _id: eventId,
        managerEmail: req.user.email,
      });

      if (!event) {
        return res
          .status(403)
          .json({ message: "Event does not belong to this manager" });
      }

      const registrations = await EventRegistrations()
        .find({ eventId })
        .toArray();

      res.json(registrations);
    } catch (error) {
      console.error("EVENT REGISTRATIONS VIEW ERROR:", error);
      res.status(500).json({ message: "Server error" });
    }
  }
);

// ===============================
// ⭐ MEMBER — Request Manager Role
// ===============================
app.post("/manager/request", verifyToken, async (req, res) => {
  try {
    const { email, name } = req.body;

    if (!email || !name) {
      return res.status(400).json({ message: "Name and email required" });
    }

    const cleanEmail = email.toLowerCase();

    const user = await Users().findOne({ email: cleanEmail });
    if (user && user.role === "manager") {
      return res.status(400).json({ message: "Already a manager" });
    }

    const existing = await ManagerRequests().findOne({
      email: cleanEmail,
      status: "pending",
    });

    if (existing) {
      return res.status(400).json({
        message: "Request already submitted, waiting admin approval",
      });
    }

    const request = {
      email: cleanEmail,
      name,
      status: "pending",
      createdAt: new Date(),
    };

    await ManagerRequests().insertOne(request);

    res.json({ success: true, message: "Request submitted successfully" });
  } catch (error) {
    console.error("MANAGER REQUEST ERROR:", error);
    res.status(500).json({ message: "Server error" });
  }
});

// ===============================
// ⭐ ADMIN — Manager Requests
// ===============================
app.get("/admin/manager/requests", verifyToken, async (req, res) => {
  try {
    if (req.user.role !== "admin")
      return res.status(403).json({ message: "Admin only" });

    const requests = await ManagerRequests()
      .find()
      .sort({ createdAt: -1 })
      .toArray();

    res.json(requests);
  } catch (error) {
    console.error("GET MANAGER REQUESTS ERROR:", error);
    res.status(500).json({ message: "Server error" });
  }
});

app.patch(
  "/admin/manager/requests/approve/:email",
  verifyToken,
  async (req, res) => {
    try {
      if (req.user.role !== "admin")
        return res.status(403).json({ message: "Admin only" });

      const email = req.params.email.toLowerCase();

      await Users().updateOne({ email }, { $set: { role: "manager" } });
      await ManagerRequests().updateOne(
        { email },
        { $set: { status: "approved" } }
      );

      res.json({ success: true, message: "Manager role approved" });
    } catch (error) {
      console.error("APPROVE MANAGER REQUEST ERROR:", error);
      res.status(500).json({ message: "Server error" });
    }
  }
);

app.patch(
  "/admin/manager/requests/reject/:email",
  verifyToken,
  async (req, res) => {
    try {
      if (req.user.role !== "admin")
        return res.status(403).json({ message: "Admin only" });

      const email = req.params.email.toLowerCase();

      await ManagerRequests().updateOne(
        { email },
        { $set: { status: "rejected" } }
      );

      res.json({ success: true, message: "Manager request rejected" });
    } catch (error) {
      console.error("REJECT MANAGER REQUEST ERROR:", error);
      res.status(500).json({ message: "Server error" });
    }
  }
);

// ===============================
// ⭐ ADMIN — Payments Dashboard
// ===============================
app.get("/admin/payments", verifyToken, async (req, res) => {
  try {
    if (req.user.role !== "admin") {
      return res.status(403).json({ message: "Admin only" });
    }

    const payments = await Payments()
      .find()
      .sort({ createdAt: -1 })
      .toArray();

    if (payments.length === 0) return res.json([]);

    // Collect unique IDs
    const clubIds = [
      ...new Set(
        payments
          .filter((p) => p.clubId)
          .map((p) => new ObjectId(p.clubId))
      ),
    ];

    const eventIds = [
      ...new Set(
        payments
          .filter((p) => p.eventId)
          .map((p) => new ObjectId(p.eventId))
      ),
    ];

    // Fetch names
    const clubs = await Clubs()
      .find({ _id: { $in: clubIds } })
      .toArray();

    const events = await Events()
      .find({ _id: { $in: eventIds } })
      .toArray();

    // Create lookup maps
    const clubMap = {};
    clubs.forEach((c) => (clubMap[c._id] = c.clubName));

    const eventMap = {};
    events.forEach((e) => (eventMap[e._id] = e.title));

    // attach names to payments
    const result = payments.map((p) => ({
      ...p,
      clubName: p.clubId ? clubMap[p.clubId] : null,
      eventName: p.eventId ? eventMap[p.eventId] : null,
    }));

    res.json(result);
  } catch (err) {
    console.log("ADMIN PAYMENTS ERROR:", err);
    res.status(500).json({ message: "Server error" });
  }
});

app.get("/events/:eventId/my-status", verifyToken, async (req, res) => {
  try {
    const eventId = new ObjectId(req.params.eventId);

    const reg = await EventRegistrations().findOne({
      eventId,
      userEmail: req.user.email,
    });

    if (!reg) {
      return res.json({
        joined: false,
        paid: false,
        reg: null,
      });
    }

    return res.json({
      joined: true,
      paid: reg.paidAmount > 0,
      reg,
    });

  } catch (err) {
    console.error("MY STATUS EVENT ERROR:", err);
    res.status(500).json({ message: "Server error" });
  }
});

// ======================
// STRIPE CHECKOUT SUCCESS (🔥 MAIN FIX)
// ======================
app.post("/clubs/checkout-success", verifyToken, async (req, res) => {
  const { clubId, sessionId } = req.body;

  const session = await stripe.checkout.sessions.retrieve(sessionId);
  if (session.payment_status !== "paid") {
    return res.status(400).json({ message: "Payment not completed" });
  }

  const id = new ObjectId(clubId);

  const exists = await Memberships().findOne({
    userEmail: req.user.email,
    clubId: id,
  });
  if (exists) return res.json({ message: "Already joined" });

  // ✅ SAVE PAYMENT
  const paymentResult = await Payments().insertOne({
    userEmail: req.user.email,
    clubId: id,
    amount: session.amount_total / 100,
    currency: session.currency,
    paymentIntentId: session.payment_intent,
    type: "club",
    createdAt: new Date(),
  });

  // ✅ CREATE MEMBERSHIP
  await Memberships().insertOne({
    userEmail: req.user.email,
    clubId: id,
    status: "active",
    joinedAt: new Date(),
    expiryDate: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000),
    paymentId: paymentResult.insertedId,
  });

  res.json({ success: true });
});

// Event check out payment
app.post("/events/create-checkout-session", verifyToken, async (req, res) => {
  try {
    const { eventId } = req.body;
    const id = new ObjectId(eventId);

    const event = await Events().findOne({ _id: id });
    if (!event) return res.status(404).json({ message: "Event not found" });

    if (!event.isPaid || event.eventFee <= 0) {
      return res.status(400).json({ message: "This event is free" });
    }

    // ❌ already registered?
    const existing = await EventRegistrations().findOne({
      eventId: id,
      userEmail: req.user.email,
    });

    if (existing && existing.paidAmount > 0) {
      return res.json({ message: "Already paid" });
    }

    const session = await stripe.checkout.sessions.create({
      mode: "payment",
      payment_method_types: ["card"],
      customer_email: req.user.email,

      line_items: [
        {
          price_data: {
            currency: "usd",
            product_data: {
              name: event.title,
              description: "Event Registration",
            },
            unit_amount: Math.round(event.eventFee * 100),
          },
          quantity: 1,
        },
      ],

      success_url: `${CLIENT_URL}/events/${eventId}?success=true&session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: `${CLIENT_URL}/events/${eventId}?canceled=true`,

      metadata: {
        type: "event",
        eventId: eventId,
        userEmail: req.user.email,
      },
    });

    res.json({ url: session.url });
  } catch (err) {
    console.error("EVENT CHECKOUT ERROR:", err);
    res.status(500).json({ message: "Server error" });
  }
});

//event sucess
app.post("/events/checkout-success", verifyToken, async (req, res) => {
  try {
    const { eventId, sessionId } = req.body;

    const session = await stripe.checkout.sessions.retrieve(sessionId);
    if (session.payment_status !== "paid") {
      return res.status(400).json({ message: "Payment not completed" });
    }

    // 🔒 prevent duplicate payment
    const existingPayment = await Payments().findOne({
      paymentIntentId: session.payment_intent,
    });
    if (existingPayment) {
      return res.json({ success: true, message: "Already processed" });
    }

    const id = new ObjectId(eventId);

    // ensure registration exists
    let reg = await EventRegistrations().findOne({
      eventId: id,
      userEmail: req.user.email,
    });

    if (!reg) {
      const regInsert = await EventRegistrations().insertOne({
        eventId: id,
        clubId: new ObjectId(session.metadata?.clubId || null),
        userEmail: req.user.email,
        status: "registered",
        joinedAt: new Date(),
        paidAmount: session.amount_total / 100,
      });
      reg = { _id: regInsert.insertedId };
    }

    // save payment
    const paymentResult = await Payments().insertOne({
      userEmail: req.user.email,
      eventId: id,
      type: "event",
      amount: session.amount_total / 100,
      currency: session.currency,
      paymentIntentId: session.payment_intent,
      createdAt: new Date(),
    });

    // update registration
    await EventRegistrations().updateOne(
      { _id: reg._id },
      {
        $set: {
          status: "registered",
          paidAmount: session.amount_total / 100,
          paymentId: paymentResult.insertedId,
        },
      }
    );

    res.json({ success: true });
  } catch (err) {
    if (err.code === 11000) {
      return res.json({ success: true, message: "Already processed" });
    }
    console.error("EVENT CHECKOUT SUCCESS ERROR:", err);
    res.status(500).json({ message: "Server error" });
  }
});

// ADMIN — Dashboard Stats
// ===============================
app.get("/admin/stats", verifyToken, async (req, res) => {
  try {
    if (req.user.role !== "admin") {
      return res.status(403).json({ message: "Admin only" });
    }

    const [
      totalUsers,
      totalClubs,
      totalEvents,
      payments,
    ] = await Promise.all([
      Users().countDocuments(),
      Clubs().countDocuments(),
      Events().countDocuments(),
      Payments().find().toArray(),
    ]);

    let clubRevenue = 0;
    let eventRevenue = 0;

    payments.forEach((p) => {
      if (p.type === "club") clubRevenue += p.amount;
      if (p.type === "event") eventRevenue += p.amount;
    });

    res.json({
      totalUsers,
      totalClubs,
      totalEvents,
      totalRevenue: clubRevenue + eventRevenue,
      clubRevenue,
      eventRevenue,
    });
  } catch (err) {
    console.error("ADMIN STATS ERROR:", err);
    res.status(500).json({ message: "Server error" });
  }
});

// ===============================
// ⭐ MEMBER — My Payments
// ===============================
app.get("/member/payments", verifyToken, async (req, res) => {
  try {
    const payments = await Payments()
      .find({ userEmail: req.user.email })
      .sort({ createdAt: -1 })
      .toArray();

    if (payments.length === 0) {
      return res.json([]);
    }

    // collect clubIds
    const clubIds = [
      ...new Set(
        payments
          .filter(p => p.clubId)
          .map(p => new ObjectId(p.clubId))
      )
    ];

    // fetch clubs
    const clubs = await Clubs()
      .find({ _id: { $in: clubIds } })
      .toArray();

    // map club names
    const clubMap = {};
    clubs.forEach(c => {
      clubMap[c._id.toString()] = c.clubName;
    });

    // attach clubName
    const result = payments.map(p => ({
      ...p,
      clubName: p.clubId
        ? clubMap[p.clubId.toString()] || "Unknown Club"
        : "—",
    }));

    res.json(result);
  } catch (error) {
    console.error("MEMBER PAYMENTS ERROR:", error);
    res.status(500).json({ message: "Server error" });
  }
});

// ===============================
// START SERVER
// ===============================
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log("🚀 Server running on port", PORT));
