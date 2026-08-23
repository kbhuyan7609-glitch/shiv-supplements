require("dotenv").config();

const express = require("express");
const path = require("path");
const crypto = require("crypto");
const Database = require("better-sqlite3");
const session = require("express-session");

const app = express();
const PORT = Number(process.env.PORT) || 10000;

/* =========================
   DATABASE
========================= */

const db = new Database(
  process.env.DB_PATH || path.join(__dirname, "shiv_supplements.db")
);

db.pragma("journal_mode = WAL");

db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  phone TEXT UNIQUE NOT NULL,
  email TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS orders (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER,
  name TEXT NOT NULL,
  phone TEXT NOT NULL,
  email TEXT NOT NULL,
  address TEXT NOT NULL,
  items_json TEXT NOT NULL,
  amount_paise INTEGER NOT NULL,
  status TEXT DEFAULT 'pending',
  payment_method TEXT DEFAULT 'UPI',
  payment_ref TEXT,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
`);

// Migrate older databases without breaking existing orders.
const orderColumns = db.prepare("PRAGMA table_info(orders)").all();
const hasColumn = (name) => orderColumns.some((c) => c.name === name);

if (!hasColumn("payment_method")) {
  db.exec("ALTER TABLE orders ADD COLUMN payment_method TEXT DEFAULT 'UPI'");
}
if (!hasColumn("payment_ref")) {
  db.exec("ALTER TABLE orders ADD COLUMN payment_ref TEXT");
}

/* =========================
   EXPRESS
========================= */

app.use(express.json({ limit: "1mb" }));
app.use(express.urlencoded({ extended: true }));
app.set("trust proxy", 1);

app.use(
  session({
    secret: process.env.SESSION_SECRET || "CHANGE_THIS_SESSION_SECRET",
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      sameSite: "lax",
      secure: process.env.NODE_ENV === "production",
      maxAge: 7 * 24 * 60 * 60 * 1000
    }
  })
);

app.use(express.static(__dirname));

/* =========================
   HELPERS
========================= */

function hashPassword(password) {
  return crypto.createHash("sha256").update(String(password)).digest("hex");
}

function safeUser(user) {
  if (!user) return null;
  return {
    id: user.id,
    name: user.name,
    phone: user.phone,
    email: user.email
  };
}

function normalizePhone(phone) {
  return String(phone || "").replace(/\D/g, "").slice(-10);
}

function validEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(String(email || ""));
}

function validPhone(phone) {
  return /^[6-9]\d{9}$/.test(String(phone || ""));
}

function requireLogin(req, res, next) {
  if (!req.session.user) {
    return res.status(401).json({
      success: false,
      message: "Please login first"
    });
  }
  next();
}

function requireAdmin(req, res, next) {
  if (!req.session.admin) {
    return res.status(401).json({
      success: false,
      message: "Admin login required"
    });
  }
  next();
}

function parseItems(items) {
  if (!Array.isArray(items) || items.length === 0) return null;
  return items.map((item) => ({
    id: item.id ?? null,
    name: String(item.name || "Product").slice(0, 200),
    price: Number(item.price) || 0,
    qty: Math.max(1, Number(item.qty || item.quantity || 1))
  }));
}

function createPendingOrder(req, body) {
  const { name, phone, email, address, items, amount } = body;

  if (!name || !phone || !email || !address || amount === undefined) {
    throw Object.assign(new Error("All order details are required"), { status: 400 });
  }

  const cleanPhone = normalizePhone(phone);
  const cleanEmail = String(email).trim().toLowerCase();
  const cleanItems = parseItems(items);
  const numericAmount = Number(amount);

  if (!validPhone(cleanPhone)) {
    throw Object.assign(new Error("Enter a valid 10-digit mobile number"), { status: 400 });
  }
  if (!validEmail(cleanEmail)) {
    throw Object.assign(new Error("Enter a valid email address"), { status: 400 });
  }
  if (!cleanItems) {
    throw Object.assign(new Error("Order items are required"), { status: 400 });
  }
  if (!Number.isFinite(numericAmount) || numericAmount <= 0) {
    throw Object.assign(new Error("Invalid order amount"), { status: 400 });
  }

  const result = db.prepare(`
    INSERT INTO orders (
      user_id, name, phone, email, address,
      items_json, amount_paise, status, payment_method
    ) VALUES (?, ?, ?, ?, ?, ?, ?, 'pending', 'UPI')
  `).run(
    req.session.user.id,
    String(name).trim().slice(0, 150),
    cleanPhone,
    cleanEmail,
    String(address).trim().slice(0, 1000),
    JSON.stringify(cleanItems),
    Math.round(numericAmount * 100)
  );

  return {
    id: Number(result.lastInsertRowid),
    amount: numericAmount,
    currency: "INR",
    status: "pending",
    paymentMethod: "UPI"
  };
}

/* =========================
   HEALTH / USER
========================= */

app.get("/api/health", (req, res) => {
  res.json({ success: true, message: "Shiv Supplements server is running" });
});

app.get("/api/me", (req, res) => {
  res.json({ success: true, user: req.session.user || null });
});

/* =========================
   REGISTER
========================= */

app.post("/api/register", (req, res) => {
  try {
    const { name, phone, email, password } = req.body;

    if (!name || !phone || !email || !password) {
      return res.status(400).json({ success: false, message: "Name, phone, email and password are required" });
    }

    const cleanPhone = normalizePhone(phone);
    const cleanEmail = String(email).trim().toLowerCase();

    if (!validPhone(cleanPhone)) {
      return res.status(400).json({ success: false, message: "Enter a valid 10-digit mobile number" });
    }
    if (!validEmail(cleanEmail)) {
      return res.status(400).json({ success: false, message: "Enter a valid email address" });
    }
    if (String(password).length < 6) {
      return res.status(400).json({ success: false, message: "Password must contain at least 6 characters" });
    }

    const existing = db.prepare("SELECT id FROM users WHERE phone = ? OR email = ?").get(cleanPhone, cleanEmail);
    if (existing) {
      return res.status(409).json({ success: false, message: "Phone number or email is already registered" });
    }

    const result = db.prepare(`
      INSERT INTO users (name, phone, email, password_hash)
      VALUES (?, ?, ?, ?)
    `).run(String(name).trim(), cleanPhone, cleanEmail, hashPassword(password));

    const user = db.prepare("SELECT id, name, phone, email FROM users WHERE id = ?").get(result.lastInsertRowid);
    req.session.user = user;

    res.json({ success: true, message: "Registration successful", user: safeUser(user) });
  } catch (error) {
    console.error("REGISTER ERROR:", error);
    res.status(500).json({ success: false, message: "Registration failed" });
  }
});

/* =========================
   LOGIN / LOGOUT
========================= */

app.post("/api/login", (req, res) => {
  try {
    const identifier = String(req.body.phone || req.body.email || "").trim();
    const password = String(req.body.password || "");

    if (!identifier || !password) {
      return res.status(400).json({ success: false, message: "Phone/email and password are required" });
    }

    const user = db.prepare(`
      SELECT * FROM users
      WHERE phone = ? OR email = ?
    `).get(normalizePhone(identifier), identifier.toLowerCase());

    if (!user || hashPassword(password) !== user.password_hash) {
      return res.status(401).json({ success: false, message: "Invalid login details" });
    }

    req.session.user = safeUser(user);
    res.json({ success: true, message: "Login successful", user: req.session.user });
  } catch (error) {
    console.error("LOGIN ERROR:", error);
    res.status(500).json({ success: false, message: "Login failed" });
  }
});

app.post("/api/logout", (req, res) => {
  req.session.destroy(() => {
    res.json({ success: true, message: "Logged out successfully" });
  });
});

/* =========================
   MSG91 OTP
========================= */

app.post("/api/send-otp", async (req, res) => {
  try {
    const phone = normalizePhone(req.body.mobile || req.body.phone);

    if (!validPhone(phone)) {
      return res.status(400).json({ success: false, message: "Enter a valid 10-digit mobile number" });
    }
    if (!process.env.MSG91_AUTH_KEY || !process.env.MSG91_TEMPLATE_ID) {
      return res.status(500).json({ success: false, message: "MSG91 OTP is not configured" });
    }

    const response = await fetch("https://control.msg91.com/api/v5/otp", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        authkey: process.env.MSG91_AUTH_KEY
      },
      body: JSON.stringify({
        template_id: process.env.MSG91_TEMPLATE_ID,
        mobile: "91" + phone,
        otp_length: 6,
        otp_expiry: 10
      })
    });

    const data = await response.json();
    console.log("MSG91 SEND OTP:", data);

    if (data.type === "success" || data.type === "successfully") {
      return res.json({ success: true, message: "OTP sent successfully" });
    }

    res.status(400).json({ success: false, message: data.message || "Unable to send OTP" });
  } catch (error) {
    console.error("MSG91 SEND OTP ERROR:", error);
    res.status(500).json({ success: false, message: "OTP service error" });
  }
});

app.post("/api/verify-otp", async (req, res) => {
  try {
    const phone = normalizePhone(req.body.mobile || req.body.phone);
    const otp = String(req.body.otp || "").trim();

    if (!validPhone(phone) || !otp) {
      return res.status(400).json({ success: false, message: "Mobile and OTP are required" });
    }
    if (!process.env.MSG91_AUTH_KEY) {
      return res.status(500).json({ success: false, message: "MSG91 OTP is not configured" });
    }

    const response = await fetch(
      `https://control.msg91.com/api/v5/otp/verify?mobile=91${phone}&otp=${encodeURIComponent(otp)}`,
      { headers: { authkey: process.env.MSG91_AUTH_KEY } }
    );

    const data = await response.json();
    console.log("MSG91 VERIFY OTP:", data);

    if (data.type === "success") {
      return res.json({ success: true, message: "OTP verified successfully" });
    }

    res.status(400).json({ success: false, message: data.message || "Invalid OTP" });
  } catch (error) {
    console.error("MSG91 VERIFY OTP ERROR:", error);
    res.status(500).json({ success: false, message: "OTP verification error" });
  }
});

/* =========================
   ORDERS — NO RAZORPAY
========================= */

// Creates a pending UPI order. No online payment gateway is used.
app.post("/api/create-order", requireLogin, (req, res) => {
  try {
    const order = createPendingOrder(req, req.body);
    res.json({
      success: true,
      message: "Order created. Pay by UPI and submit your UTR.",
      order
    });
  } catch (error) {
    console.error("CREATE ORDER ERROR:", error);
    res.status(error.status || 500).json({ success: false, message: error.message || "Could not create order" });
  }
});

// Submits the UPI transaction/reference number for admin verification.
app.post("/api/manual-order", requireLogin, (req, res) => {
  try {
    const orderId = Number(req.body.localOrderId || req.body.orderId || req.body.id);
    const utr = String(req.body.utr || req.body.paymentRef || "").trim().slice(0, 100);

    if (!Number.isInteger(orderId) || orderId <= 0 || !utr) {
      return res.status(400).json({ success: false, message: "Order ID and UTR are required" });
    }

    const order = db.prepare("SELECT * FROM orders WHERE id = ? AND user_id = ?").get(orderId, req.session.user.id);
    if (!order) {
      return res.status(404).json({ success: false, message: "Order not found" });
    }
    if (order.status !== "pending") {
      return res.status(400).json({ success: false, message: "This order is no longer pending" });
    }

    db.prepare(`UPDATE orders SET payment_ref = ?, payment_method = 'UPI' WHERE id = ?`).run(utr, orderId);

    res.json({
      success: true,
      message: "UTR submitted. Your payment will be verified by the admin.",
      order: { id: orderId, status: "pending", paymentRef: utr }
    });
  } catch (error) {
    console.error("MANUAL PAYMENT ERROR:", error);
    res.status(500).json({ success: false, message: "Could not submit payment details" });
  }
});

app.get("/api/orders", requireLogin, (req, res) => {
  try {
    const orders = db.prepare(`
      SELECT id, name, phone, email, address, items_json,
             amount_paise, status, payment_method, payment_ref, created_at
      FROM orders
      WHERE user_id = ?
      ORDER BY id DESC
    `).all(req.session.user.id);

    res.json({
      success: true,
      orders: orders.map((order) => ({
        ...order,
        amount: order.amount_paise / 100,
        items: JSON.parse(order.items_json)
      }))
    });
  } catch (error) {
    console.error("GET ORDERS ERROR:", error);
    res.status(500).json({ success: false, message: "Could not load orders" });
  }
});

/* =========================
   ADMIN AUTH
========================= */

app.post("/api/admin/login", (req, res) => {
  try {
    const username = String(req.body.username || "");
    const password = String(req.body.password || "");

    if (!username || !password) {
      return res.status(400).json({ success: false, message: "Username and password are required" });
    }
    if (!process.env.ADMIN_USERNAME || !process.env.ADMIN_PASSWORD) {
      return res.status(500).json({ success: false, message: "Admin credentials are not configured" });
    }
    if (username !== process.env.ADMIN_USERNAME || password !== process.env.ADMIN_PASSWORD) {
      return res.status(401).json({ success: false, message: "Invalid admin credentials" });
    }

    req.session.admin = true;
    res.json({ success: true, message: "Admin login successful" });
  } catch (error) {
    console.error("ADMIN LOGIN ERROR:", error);
    res.status(500).json({ success: false, message: "Admin login failed" });
  }
});

app.post("/api/admin/logout", (req, res) => {
  delete req.session.admin;
  res.json({ success: true, message: "Admin logged out" });
});

app.get("/api/admin/me", (req, res) => {
  res.json({ success: true, loggedIn: !!req.session.admin });
});

app.use("/api/admin", requireAdmin);

/* =========================
   ADMIN ORDERS
========================= */

app.get("/api/admin/orders", (req, res) => {
  try {
    const orders = db.prepare("SELECT * FROM orders ORDER BY id DESC").all();
    res.json({
      success: true,
      orders: orders.map((order) => ({
        ...order,
        amount: order.amount_paise / 100,
        items: JSON.parse(order.items_json)
      }))
    });
  } catch (error) {
    console.error("ADMIN ORDERS ERROR:", error);
    res.status(500).json({ success: false, message: "Could not load orders" });
  }
});

app.patch("/api/admin/orders/:id/approve-payment", (req, res) => {
  try {
    const orderId = Number(req.params.id);
    if (!Number.isInteger(orderId) || orderId <= 0) {
      return res.status(400).json({ success: false, message: "Invalid order ID" });
    }

    const order = db.prepare("SELECT * FROM orders WHERE id = ?").get(orderId);
    if (!order) return res.status(404).json({ success: false, message: "Order not found" });
    if (order.status !== "pending") {
      return res.status(400).json({ success: false, message: "Only pending orders can be approved" });
    }
    if (!order.payment_ref) {
      return res.status(400).json({ success: false, message: "No UTR/payment reference submitted" });
    }

    db.prepare("UPDATE orders SET status = 'paid' WHERE id = ?").run(orderId);
    res.json({ success: true, message: "Payment approved successfully" });
  } catch (error) {
    console.error("APPROVE PAYMENT ERROR:", error);
    res.status(500).json({ success: false, message: "Could not approve payment" });
  }
});

app.patch("/api/admin/orders/:id", (req, res) => {
  try {
    const status = String(req.body.status || "");
    const allowed = ["pending", "paid", "processing", "shipped", "delivered", "cancelled"];

    if (!allowed.includes(status)) {
      return res.status(400).json({ success: false, message: "Invalid order status" });
    }

    const result = db.prepare("UPDATE orders SET status = ? WHERE id = ?").run(status, req.params.id);
    if (!result.changes) return res.status(404).json({ success: false, message: "Order not found" });

    res.json({ success: true, message: "Order status updated" });
  } catch (error) {
    console.error("UPDATE ORDER ERROR:", error);
    res.status(500).json({ success: false, message: "Could not update order" });
  }
});

/* =========================
   SPA FALLBACK
========================= */

app.get("/{*splat}", (req, res) => {
  res.sendFile(path.join(__dirname, "index.html"));
});

/* =========================
   START
========================= */

app.listen(PORT, "0.0.0.0", () => {
  console.log(`Shiv Supplements server running on port ${PORT}`);
});
