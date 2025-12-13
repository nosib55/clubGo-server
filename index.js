// ===============================
// PUBLIC — Clubs
// ===============================
app.get("/clubs", async (req, res) => {
  try {
    const clubs = await Clubs()
      .find({ status: "approved" })
      .toArray();

    res.json(clubs);
  } catch (error) {
    console.error("GET CLUBS ERROR:", error);
    res.status(500).json({ message: "Server error" });
  }
});

// Get club details with member count
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
  } catch (error) {
    console.error("GET CLUB DETAIL ERROR:", error);
    res.status(500).json({ message: "Server error" });
  }
});

// ===============================
// FEATURED CLUBS
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
