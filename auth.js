const mysql = require("mysql");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const { promisify } = require("util");
const hbs = require("hbs");

// Database connection
const db = mysql.createConnection({
  host: process.env.DATABASE_HOST,
  user: process.env.DATABASE_USER,
  password: process.env.DATABASE_PASSWORD,
  database: process.env.DATABASE,
});

// Handlebars Helpers
hbs.registerHelper("priorityDropdown", (selectedPriority) => {
  const priorities = ["Low", "Medium", "High"];
  return priorities
    .map(
      (priority) =>
        `<option value="${priority}" ${priority === selectedPriority ? "selected" : ""}>${priority}</option>`
    )
    .join("");
});

hbs.registerHelper("formatDate", (date) => {
  if (!date) return "N/A";
  const parsedDate = new Date(date);
  if (isNaN(parsedDate.getTime())) return "Invalid Date";
  return parsedDate.toLocaleString(undefined, {
    hour: "numeric",
    minute: "numeric",
    second: "numeric",
    timeZone: "America/Chicago",
    timeZoneName: "short",
  });
});

// Middleware for Role Check
exports.hasRole = (role) => (req, res, next) => {
  if (req.user && req.user.role === role) {
    next();
  } else {
    res.status(403).send("Forbidden");
  }
};

// Middleware for Authentication Check
exports.isAuthenticated = (req, res, next) => {
  if (req.isAuthenticated()) {
    return next();
  }
  res.redirect("/login");
};

// User Login
exports.login = async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).render("login", { message: "Please provide an email and password" });
    }

    db.query("SELECT * FROM users WHERE email = ?", [email], async (error, results) => {
      if (!results || !(await bcrypt.compare(password, results[0].password))) {
        return res.status(401).render("login", { message: "Email or Password is incorrect" });
      }

      const id = results[0].id;
      const token = jwt.sign({ id }, process.env.JWT_SECRET, {
        expiresIn: process.env.JWT_EXPIRES_IN,
      });

      res.cookie("jwt", token, {
        expires: new Date(Date.now() + process.env.JWT_COOKIE_EXPIRES * 24 * 60 * 60 * 1000),
        httpOnly: true,
      });
      res.status(200).redirect("/");
    });
  } catch (error) {
    console.error(error);
  }
};

// User Registration
exports.register = async (req, res) => {
  const { name, email, password, passwordConfirm } = req.body;
  if (password !== passwordConfirm) {
    return res.render("register", { message: "Passwords do not match" });
  }

  db.query("SELECT email FROM users WHERE email = ?", [email], async (error, results) => {
    if (results.length > 0) {
      return res.render("register", { message: "That email is already in use" });
    }

    const hashedPassword = await bcrypt.hash(password, 8);
    db.query(
      "INSERT INTO users SET ?",
      { name, email, password: hashedPassword, role: "user" },
      (err) => {
        if (err) {
          console.error(err);
        } else {
          res.render("register", { message: "User registered" });
        }
      }
    );
  });
};

// Fetch User Details
exports.fetchUserDetails = (req, res) => {
  const userId = req.params.id;
  db.query("SELECT name, email FROM users WHERE id = ?", [userId], (error, userDetails) => {
    if (error) {
      return res.status(500).json({ error: "Internal server error" });
    }
    if (userDetails.length === 0) {
      return res.status(404).json({ error: "User not found" });
    }
    res.json(userDetails[0]);
  });
};

// Update Ticket State
exports.updateTicketState = (req, res) => {
  const ticketId = req.body.ticketId;
  const newState = req.body.newState;

  const updateFields = {
    ticket_state: newState,
    closed_at: newState === "closed" ? new Date() : null,
  };

  db.query("UPDATE tickets SET ? WHERE id = ?", [updateFields, ticketId], (err) => {
    if (err) {
      return res.status(500).json({ error: "Internal Server Error" });
    }
    res.json({ message: "Ticket state updated successfully." });
  });
};

// Submit Comment
exports.submitComment = (req, res) => {
  const { ticketId, userId, userName, comment } = req.body;
  db.query(
    "INSERT INTO comments (ticket_id, user_id, user_name, comment, timestamp) VALUES (?, ?, ?, ?, ?)",
    [ticketId, userId, userName, comment, new Date().toISOString()],
    (error) => {
      if (error) {
        return res.status(500).json({ error: "Failed to insert comment" });
      }
      res.status(200).json({ message: "Comment inserted successfully" });
    }
  );
};

// Delete Ticket
exports.deleteTicket = (req, res) => {
  const ticketId = req.params.id;
  db.query("DELETE FROM tickets WHERE id = ?", [ticketId], (err, result) => {
    if (err) {
      return res.status(500).json({ error: "Internal Server Error" });
    }
    if (result.affectedRows === 0) {
      return res.status(404).json({ error: "Ticket not found" });
    }
    res.json({ message: "Ticket successfully deleted." });
  });
};

// Logout
exports.logout = (req, res) => {
  res.clearCookie("jwt", { httpOnly: true });
  res.status(200).redirect("/login");
};
