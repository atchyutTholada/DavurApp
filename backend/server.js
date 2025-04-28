// Import required modules
const express = require("express");
const cors = require("cors");
const bodyParser = require("body-parser");
const jwt = require("jsonwebtoken");
const mysql = require("mysql");
const bcrypt = require("bcrypt");

// Initialize the Express app
const app = express();
const PORT = 5000;
const SECRET_KEY = "your_secret_key";

// Middleware setup
app.use(cors({
  origin: "http://localhost:3000",
  methods: ["GET", "POST"],
  credentials: true,
}));
app.use(bodyParser.json());

// Configure MySQL database connection
const db = mysql.createConnection({
  host: "localhost",
  user: "root",
  password: "",
  database: "crud"
});

// Test database connection
db.connect((err) => {
  if (err) {
    console.error("Database connection failed:", err);
    process.exit(1);
  } else {
    console.log("Connected to the database successfully.");
  }
});

// Middleware to verify JWT
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1]; // Bearer <token>
  if (!token) {
    return res.status(401).json({ message: 'Unauthorized: No token provided' });
  }

  jwt.verify(token, SECRET_KEY, (err, user) => {
    if (err) {
      return res.status(403).json({ message: 'Unauthorized: Invalid token' });
    }
    req.user = user;
    next();
  });
};

// Register API
app.post("/register", (req, res) => {
  const { email, password } = req.body;
  console.log("Registering user:", email);
  if (!email || !password) {
    return res.status(400).json({ message: "Email and password are required" });
  }
  const hashedPassword = bcrypt.hashSync(password, 10);
  console.log("Hashed Password:", hashedPassword, "Length:", hashedPassword.length);
  if (hashedPassword.length < 60) {
    console.error("Invalid hash generated:", hashedPassword);
    return res.status(500).json({ message: "Password hashing error" });
  }
  const sql = "INSERT INTO register (email, password) VALUES (?, ?)";
  db.query(sql, [email, hashedPassword], (err, result) => {
    if (err) {
      console.error("Registration error:", err);
      if (err.code === "ER_DUP_ENTRY") {
        return res.status(400).json({ message: "User already exists" });
      }
      return res.status(500).json({ message: "Database error" });
    }
    console.log("User registered:", result.insertId);
    res.status(201).json({ message: "User registered successfully" });
  });
});

// Login API
app.post("/login", (req, res) => {
  const { email, password } = req.body;

  console.log("Request body:", req.body);

  if (!email || !password) {
    console.log("Email or Password missing!");
    return res.status(400).json({ message: "Email and password are required" });
  }

  const sql = "SELECT * FROM register WHERE LOWER(email) = LOWER(?)";

  console.log("Running SQL Query:", sql, "with email:", email);

  db.query(sql, [email], async (err, results) => {
    if (err) {
      console.log("Database Query Error:", err.sqlMessage);
      return res.status(500).json({ message: "Database error" });
    }

    console.log("SQL Query Results Length:", results.length);
    console.log("SQL Query Full Results:", JSON.stringify(results, null, 2));

    if (results.length === 0) {
      console.log("No user found with that email");
      return res.status(401).json({ message: "Invalid credentials" });
    }

    const user = results[0];
    console.log("User from DB:", user);

    try {
      const isPasswordValid = await bcrypt.compare(password, user.password);
      console.log("Password comparison result:", isPasswordValid);

      if (!isPasswordValid) {
        console.log("Passwords do not match");
        return res.status(401).json({ message: "Invalid credentials" });
      }

      const token = jwt.sign({ email: user.email }, SECRET_KEY, { expiresIn: "1h" });
      console.log("Generated JWT Token:", token);

      res.json({ message: "Login successful. Navigate to home screen.", token });
    } catch (err) {
      console.error("Bcrypt error:", err);
      return res.status(500).json({ message: "Password verification error" });
    }
  });
});

// Home endpoint
app.get('/home', authenticateToken, (req, res) => {
  res.json({ message: 'Welcome to the home page', user: req.user });
});

// Start the server
app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));