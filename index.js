// ===============================
// USER ROLE FETCH
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
// ADMIN — Manage Users
// ===============================
app.get("/admin/users", verifyToken, async (req, res) => {
  try {
    if (req.user.role !== "admin") {
      return res.status(403).json({ message: "Admin only" });
    }

    const users = await Users().find().toArray();
    res.json(users);
  } catch (error) {
    console.error("ADMIN USERS ERROR:", error);
    res.status(500).json({ message: "Server error" });
  }
});

app.patch("/admin/users/role/:email", verifyToken, async (req, res) => {
  try {
    if (req.user.role !== "admin") {
      return res.status(403).json({ message: "Admin only" });
    }

    const email = req.params.email.toLowerCase();
    const { role } = req.body;

    await Users().updateOne(
      { email },
      { $set: { role } }
    );

    res.json({ success: true, message: "Role updated" });
  } catch (error) {
    console.error("ROLE UPDATE ERROR:", error);
    res.status(500).json({ message: "Server error" });
  }
});

app.delete("/admin/users/:email", verifyToken, async (req, res) => {
  try {
    if (req.user.role !== "admin") {
      return res.status(403).json({ message: "Admin only" });
    }

    const email = req.params.email.toLowerCase();
    await Users().deleteOne({ email });

    res.json({ success: true, message: "User deleted" });
  } catch (error) {
    console.error("DELETE USER ERROR:", error);
    res.status(500).json({ message: "Server error" });
  }
});
