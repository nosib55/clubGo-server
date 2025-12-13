// ===============================
// MANAGER — Create Club
// ===============================
app.post("/manager/clubs", verifyToken, async (req, res) => {
  try {
    if (req.user.role !== "manager") {
      return res.status(403).json({ message: "Manager only" });
    }

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
// MANAGER — Get Own Clubs
// ===============================
app.get("/manager/clubs", verifyToken, async (req, res) => {
  try {
    if (req.user.role !== "manager") {
      return res.status(403).json({ message: "Manager only" });
    }

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
// ADMIN — View All Clubs
// ===============================
app.get("/admin/clubs", verifyToken, async (req, res) => {
  try {
    if (req.user.role !== "admin") {
      return res.status(403).json({ message: "Admin only" });
    }

    const clubs = await Clubs().find().toArray();
    res.json(clubs);
  } catch (error) {
    console.error("ADMIN CLUBS ERROR:", error);
    res.status(500).json({ message: "Server error" });
  }
});

// ===============================
// ADMIN — Approve Club
// ===============================
app.patch("/admin/clubs/approve/:id", verifyToken, async (req, res) => {
  try {
    if (req.user.role !== "admin") {
      return res.status(403).json({ message: "Admin only" });
    }

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

// ===============================
// ADMIN — Reject Club
// ===============================
app.patch("/admin/clubs/reject/:id", verifyToken, async (req, res) => {
  try {
    if (req.user.role !== "admin") {
      return res.status(403).json({ message: "Admin only" });
    }

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
