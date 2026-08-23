require("dotenv").config();

const express = require("express");
const path = require("path");
const crypto = require("crypto");
const Database = require("better-sqlite3");
const Razorpay = require("razorpay");
const session = require("express-session");

const app = express();
const PORT = process.env.PORT || 10000;

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
  razorpay_order_id TEXT,
  razorpay_payment_id TEXT,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
`);

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
   RAZORPAY
========================= */

let razorpay = null;

if (
  process.env.RAZORPAY_KEY_ID &&
  process.env.RAZORPAY_KEY_SECRET
) {
  razorpay = new Razorpay({
    key_id: process.env.RAZORPAY_KEY_ID,
    key_secret: process.env.RAZORPAY_KEY_SECRET
  });
}

/* =========================
   HELPERS
========================= */

function hashPassword(password) {
  return crypto
    .createHash("sha256")
    .update(password)
    .digest("hex");
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
  return String(phone || "")
    .replace(/\D/g, "")
    .slice(-10);
}

function validEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function validPhone(phone) {
  return /^[6-9]\d{9}$/.test(phone);
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

/* =========================
   HEALTH CHECK
========================= */

app.get("/api/health", (req, res) => {
  res.json({
    success: true,
    message: "Shiv Supplements server is running"
  });
});

/* =========================
   CURRENT USER
========================= */

app.get("/api/me", (req, res) => {
  res.json({
    success: true,
    user: req.session.user || null
  });
});

/* =========================
   REGISTER
========================= */

app.post("/api/register", (req, res) => {
  try {
    const { name, phone, email, password } = req.body;

    if (!name || !phone || !email || !password) {
      return res.status(400).json({
        success: false,
        message: "Name, phone, email and password are required"
      });
    }

    const cleanPhone = normalizePhone(phone);
    const cleanEmail = String(email).trim().toLowerCase();

    if (!validPhone(cleanPhone)) {
      return res.status(400).json({
        success: false,
        message: "Enter a valid 10-digit mobile number"
      });
    }

    if (!validEmail(cleanEmail)) {
      return res.status(400).json({
        success: false,
        message: "Enter a valid email address"
      });
    }

    if (String(password).length < 6) {
      return res.status(400).json({
        success: false,
        message: "Password must contain at least 6 characters"
      });
    }

    const existing = db
      .prepare(
        "SELECT id FROM users WHERE phone = ? OR email = ?"
      )
      .get(cleanPhone, cleanEmail);

    if (existing) {
      return res.status(409).json({
        success: false,
        message: "Phone number or email is already registered"
      });
    }

    const passwordHash = hashPassword(password);

    const result = db
      .prepare(
        `
        INSERT INTO users
        (name, phone, email, password_hash)
        VALUES (?, ?, ?, ?)
        `
      )
      .run(
        String(name).trim(),
        cleanPhone,
        cleanEmail,
        passwordHash
      );

    const user = db
      .prepare(
        "SELECT id, name, phone, email FROM users WHERE id = ?"
      )
      .get(result.lastInsertRowid);

    req.session.user = user;

    res.json({
      success: true,
      message: "Registration successful",
      user: safeUser(user)
    });
  } catch (error) {
    console.error("REGISTER ERROR:", error);

    res.status(500).json({
      success: false,
      message: "Registration failed"
    });
  }
});

/* =========================
   LOGIN
========================= */

app.post("/api/login", (req, res) => {
  try {
    const { phone, email, password } = req.body;

    const identifier = String(phone || email || "").trim();

    if (!identifier || !password) {
      return res.status(400).json({
        success: false,
        message: "Phone/email and password are required"
      });
    }

    const user = db
      .prepare(
        `
        SELECT *
        FROM users
        WHERE phone = ? OR email = ?
        `
      )
      .get(
        normalizePhone(identifier),
        identifier.toLowerCase()
      );

    if (!user) {
      return res.status(401).json({
        success: false,
        message: "Invalid login details"
      });
    }

    const passwordHash = hashPassword(password);

    if (passwordHash !== user.password_hash) {
      return res.status(401).json({
        success: false,
        message: "Invalid login details"
      });
    }

    const sessionUser = safeUser(user);

    req.session.user = sessionUser;

    res.json({
      success: true,
      message: "Login successful",
      user: sessionUser
    });
  } catch (error) {
    console.error("LOGIN ERROR:", error);

    res.status(500).json({
      success: false,
      message: "Login failed"
    });
  }
});

/* =========================
   LOGOUT
========================= */

app.post("/api/logout", (req, res) => {
  req.session.destroy(() => {
    res.json({
      success: true,
      message: "Logged out successfully"
    });
  });
});

/* =========================
   OTP - SEND
========================= */

app.post("/api/send-otp", async (req, res) => {
  try {
    const { mobile } = req.body;

    if (!mobile) {
      return res.status(400).json({
        success: false,
        message: "Mobile number is required"
      });
    }

    const phone = normalizePhone(mobile);

    if (!validPhone(phone)) {
      return res.status(400).json({
        success: false,
        message: "Enter a valid 10-digit mobile number"
      });
    }

    /*
      MSG91 configuration.

      Add these variables in Render:

      MSG91_AUTH_KEY
      MSG91_TEMPLATE_ID
    */

    if (!process.env.MSG91_AUTH_KEY) {
      return res.status(500).json({
        success: false,
        message: "MSG91_AUTH_KEY is not configured"
      });
    }

    const response = await fetch(
      "https://control.msg91.com/api/v5/otp",
      {
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
      }
    );

    const data = await response.json();

    console.log("MSG91 SEND OTP:", data);

    if (
      data.type === "success" ||
      data.type === "successfully"
    ) {
      return res.json({
        success: true,
        message: "OTP sent successfully"
      });
    }

    res.status(400).json({
      success: false,
      message: data.message || "Unable to send OTP"
    });
  } catch (error) {
    console.error("MSG91 SEND OTP ERROR:", error);

    res.status(500).json({
      success: false,
      message: "OTP service error"
    });
  }
});

/* =========================
   OTP - VERIFY
========================= */

app.post("/api/verify-otp", async (req, res) => {
  try {
    const { mobile, otp } = req.body;

    if (!mobile || !otp) {
      return res.status(400).json({
        success: false,
        message: "Mobile and OTP are required"
      });
    }

    const phone = normalizePhone(mobile);

    if (!validPhone(phone)) {
      return res.status(400).json({
        success: false,
        message: "Invalid mobile number"
      });
    }

    if (!process.env.MSG91_AUTH_KEY) {
      return res.status(500).json({
        success: false,
        message: "MSG91_AUTH_KEY is not configured"
      });
    }

    const response = await fetch(
      `https://control.msg91.com/api/v5/otp/verify?mobile=91${phone}&otp=${encodeURIComponent(
        otp
      )}`,
      {
        method: "GET",
        headers: {
          authkey: process.env.MSG91_AUTH_KEY
        }
      }
    );

    const data = await response.json();

    console.log("MSG91 VERIFY OTP:", data);

    if (data.type === "success") {
      return res.json({
        success: true,
        message: "OTP verified successfully"
      });
    }

    res.status(400).json({
      success: false,
      message: data.message || "Invalid OTP"
    });
  } catch (error) {
    console.error("MSG91 VERIFY OTP ERROR:", error);

    res.status(500).json({
      success: false,
      message: "OTP verification error"
    });
  }
});

/* =========================
   CREATE RAZORPAY ORDER
========================= */

app.post("/api/create-order", async (req, res) => {
  try {
    if (!razorpay) {
      return res.status(500).json({
        success: false,
        message: "Razorpay is not configured"
      });
    }

    const {
      name,
      phone,
      email,
      address,
      items,
      amount
    } = req.body;

    if (
      !name ||
      !phone ||
      !email ||
      !address ||
      !items ||
      amount === undefined
    ) {
      return res.status(400).json({
        success: false,
        message: "All order details are required"
      });
    }

    const numericAmount = Number(amount);

    if (
      !Number.isFinite(numericAmount) ||
      numericAmount <= 0
    ) {
      return res.status(400).json({
        success: false,
        message: "Invalid amount"
      });
    }

    const amountPaise = Math.round(numericAmount * 100);

    const razorpayOrder = await razorpay.orders.create({
      amount: amountPaise,
      currency: "INR",
      receipt:
        "shiv_" +
        Date.now() +
        "_" +
        crypto.randomBytes(3).toString("hex")
    });

    const result = db
      .prepare(
        `
        INSERT INTO orders
        (
          user_id,
          name,
          phone,
          email,
          address,
          items_json,
          amount_paise,
          status,
          razorpay_order_id
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        `
      )
      .run(
        req.session.user ? req.session.user.id : null,
        String(name).trim(),
        normalizePhone(phone),
        String(email).trim().toLowerCase(),
        String(address).trim(),
        JSON.stringify(items),
        amountPaise,
        "pending",
        razorpayOrder.id
      );

    res.json({
      success: true,
      order: {
        id: result.lastInsertRowid,
        razorpayOrderId: razorpayOrder.id,
        amount: razorpayOrder.amount,
        currency: razorpayOrder.currency
      }
    });
  } catch (error) {
    console.error("CREATE ORDER ERROR:", error);

    res.status(500).json({
      success: false,
      message: "Could not create payment order"
    });
  }
});

/* =========================
   VERIFY RAZORPAY PAYMENT
========================= */

app.post("/api/verify-payment", (req, res) => {
  try {
    const {
      razorpay_order_id,
      razorpay_payment_id,
      razorpay_signature
    } = req.body;

    if (
      !razorpay_order_id ||
      !razorpay_payment_id ||
      !razorpay_signature
    ) {
      return res.status(400).json({
        success: false,
        message: "Payment details are incomplete"
      });
    }

    if (!process.env.RAZORPAY_KEY_SECRET) {
      return res.status(500).json({
        success: false,
        message: "Razorpay secret is not configured"
      });
    }

    const generatedSignature = crypto
      .createHmac(
        "sha256",
        process.env.RAZORPAY_KEY_SECRET
      )
      .update(
        razorpay_order_id +
          "|" +
          razorpay_payment_id
      )
      .digest("hex");

    if (generatedSignature !== razorpay_signature) {
      return res.status(400).json({
        success: false,
        message: "Invalid payment signature"
      });
    }

    db.prepare(
      `
      UPDATE orders
      SET
        status = 'paid',
        razorpay_payment_id = ?
      WHERE razorpay_order_id = ?
      `
    ).run(
      razorpay_payment_id,
      razorpay_order_id
    );

    res.json({
      success: true,
      message: "Payment verified successfully"
    });
  } catch (error) {
    console.error("PAYMENT VERIFY ERROR:", error);

    res.status(500).json({
      success: false,
      message: "Payment verification failed"
    });
  }
});

/* =========================
   GET USER ORDERS
========================= */

app.get("/api/orders", requireLogin, (req, res) => {
  try {
    const orders = db
      .prepare(
        `
        SELECT
          id,
          name,
          phone,
          email,
          address,
          items_json,
          amount_paise,
          status,
          razorpay_order_id,
          razorpay_payment_id,
          created_at
        FROM orders
        WHERE user_id = ?
        ORDER BY id DESC
        `
      )
      .all(req.session.user.id);

    const formattedOrders = orders.map((order) => ({
      ...order,
      amount: order.amount_paise / 100,
      items: JSON.parse(order.items_json)
    }));

    res.json({
      success: true,
      orders: formattedOrders
    });
  } catch (error) {
    console.error("GET ORDERS ERROR:", error);

    res.status(500).json({
      success: false,
      message: "Could not load orders"
    });
  }
});
/* =========================
   MANUAL UPI ORDER
========================= */

app.post("/api/manual-order", requireLogin, (req, res) => {
  try {
    const {
      name,
      phone,
      email,
      address,
      items,
      amount,
      utr
    } = req.body;

    if (
      !name ||
      !phone ||
      !email ||
      !address ||
      !Array.isArray(items) ||
      !items.length ||
      !utr
    ) {
      return res.status(400).json({
        success: false,
        message: "All order details and UTR are required"
      });
    }

    const numericAmount = Number(amount);

    if (!Number.isFinite(numericAmount) || numericAmount <= 0) {
      return res.status(400).json({
        success: false,
        message: "Invalid order amount"
      });
    }

    const cleanPhone = normalizePhone(phone);
    const cleanEmail = String(email).trim().toLowerCase();
    const cleanUtr = String(utr).trim().slice(0, 100);

    if (!validPhone(cleanPhone)) {
      return res.status(400).json({
        success: false,
        message: "Enter a valid 10-digit mobile number"
      });
    }

    if (!validEmail(cleanEmail)) {
      return res.status(400).json({
        success: false,
        message: "Enter a valid email address"
      });
    }

    const amountPaise = Math.round(numericAmount * 100);

    const manualOrderId =
      "UPI-MANUAL-" +
      Date.now() +
      "-" +
      crypto.randomBytes(3).toString("hex");

    const result = db.prepare(`
      INSERT INTO orders (
        user_id,
        name,
        phone,
        email,
        address,
        items_json,
        amount_paise,
        status,
        razorpay_order_id,
        razorpay_payment_id
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      req.session.user ? req.session.user.id : null,
      String(name).trim(),
      cleanPhone,
      cleanEmail,
      String(address).trim(),
      JSON.stringify(items),
      amountPaise,
      "pending",
      manualOrderId,
      cleanUtr
    );

    return res.json({
      success: true,
      message: "Order submitted successfully",
      order: {
        id: result.lastInsertRowid,
        status: "pending",
        utr: cleanUtr
      }
    });

  } catch (error) {
    console.error("MANUAL ORDER ERROR:", error);

    return res.status(500).json({
      success: false,
      message: "Could not create manual payment order"
    });
  }
});
/* =========================
   ADMIN ORDERS
========================= */

app.get("/api/admin/orders", (req, res) => {
  try {
    const orders = db
      .prepare(
        `
        SELECT *
        FROM orders
        ORDER BY id DESC
        `
      )
      .all();

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

    res.status(500).json({
      success: false,
      message: "Could not load orders"
    });
  }
});

/* =========================
   UPDATE ORDER STATUS
========================= */

/* =========================
   ADMIN APPROVE PAYMENT
========================= */

app.patch("/api/admin/orders/:id/approve-payment", (req, res) => {
  try {
    const orderId = Number(req.params.id);

    if (!Number.isInteger(orderId)) {
      return res.status(400).json({
        success: false,
        message: "Invalid order ID"
      });
    }

    const order = db
      .prepare("SELECT * FROM orders WHERE id = ?")
      .get(orderId);

    if (!order) {
      return res.status(404).json({
        success: false,
        message: "Order not found"
      });
    }

    if (order.status === "paid") {
      return res.status(400).json({
        success: false,
        message: "Payment is already approved"
      });
    }

    if (order.status !== "pending") {
      return res.status(400).json({
        success: false,
        message: "Only pending orders can be approved"
      });
    }

    db.prepare(`
      UPDATE orders
      SET status = 'paid'
      WHERE id = ?
    `).run(orderId);

    res.json({
      success: true,
      message: "Payment approved successfully"
    });

  } catch (error) {
    console.error("APPROVE PAYMENT ERROR:", error);

    res.status(500).json({
      success: false,
      message: "Could not approve payment"
    });
  }
});


/* =========================
   UPDATE ORDER STATUS
========================= */

app.patch("/api/admin/orders/:id", (req, res) => {
  try {
    const { status } = req.body;

    const allowed = [
      "pending",
      "paid",
      "processing",
      "shipped",
      "delivered",
      "cancelled"
    ];

    if (!allowed.includes(status)) {
      return res.status(400).json({
        success: false,
        message: "Invalid order status"
      });
    }

    const result = db
      .prepare(`
        UPDATE orders
        SET status = ?
        WHERE id = ?
      `)
      .run(status, req.params.id);

    if (!result.changes) {
      return res.status(404).json({
        success: false,
        message: "Order not found"
      });
    }

    res.json({
      success: true,
      message: "Order status updated"
    });

  } catch (error) {
    console.error("UPDATE ORDER ERROR:", error);

    res.status(500).json({
      success: false,
      message: "Could not update order"
    });
  }
});

/* =========================
   SPA FALLBACK
========================= */

app.get("/{*splat}", (req, res) => {
  res.sendFile(path.join(__dirname, "index.html"));
});

/* =========================
   START SERVER
========================= */

app.listen(PORT, "0.0.0.0", () => {
  console.log(
    `Shiv Supplements server running on port ${PORT}`
  );
});
