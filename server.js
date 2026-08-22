const express=require("express");
const session=require("express-session");
const bcrypt=require("bcryptjs");
const Database=require("better-sqlite3");
const Razorpay=require("razorpay");
const crypto=require("crypto");
const path=require("path");
const app=express();
const db=new Database(process.env.DB_PATH||"shiv_supplements.db");

db.exec(`
CREATE TABLE IF NOT EXISTS users(
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 name TEXT NOT NULL,
 phone TEXT NOT NULL,
 email TEXT UNIQUE NOT NULL,
 password_hash TEXT NOT NULL,
 created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS orders(
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 user_id INTEGER NOT NULL,
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
);`);

app.use(express.json({limit:"1mb"}));
app.use(express.urlencoded({extended:true}));
app.set("trust proxy", 1);
app.use(session({
 secret:process.env.SESSION_SECRET||"CHANGE_THIS_SECRET",
 resave:false,saveUninitialized:false,
 cookie:{httpOnly:true,sameSite:"lax",secure:process.env.NODE_ENV==="production",maxAge:7*24*60*60*1000}
}));
app.use(express.static(path.join(__dirname,"public")));
app.use(express.static(path.join(__dirname, "public")));

// ================= MSG91 OTP =================

const MSG91_AUTHKEY = process.env.MSG91_AUTHKEY;
const MSG91_TEMPLATE_ID = process.env.MSG91_TEMPLATE_ID;

app.post("/api/send-otp", async (req, res) => {
  try {
    const { mobile } = req.body;

    if (!mobile) {
      return res.status(400).json({
        success: false,
        message: "Mobile number is required"
      });
    }

    const phone = String(mobile).replace(/\D/g, "");

    const response = await fetch("https://control.msg91.com/api/v5/otp", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "authkey": MSG91_AUTHKEY
      },
      body: JSON.stringify({
        template_id: MSG91_TEMPLATE_ID,
        mobile: phone
      })
    });

    const data = await response.json();

    console.log("MSG91:", data);

    if (data.type === "success") {
      return res.json({
        success: true,
        message: "OTP sent successfully"
      });
    }

    res.status(400).json({
      success: false,
      message: data.message || "Failed to send OTP"
    });

  } catch (error) {
    console.error("MSG91 OTP error:", error);

    res.status(500).json({
      success: false,
      message: "OTP service error"
    });
  }
});

app.post("/api/verify-otp", async (req, res) => {
  try {
    const { mobile, otp } = req.body;

    if (!mobile || !otp) {
      return res.status(400).json({
        success: false,
        message: "Mobile and OTP are required"
      });
    }

    const phone = String(mobile).replace(/\D/g, "");

    const response = await fetch(
      `https://control.msg91.com/api/v5/otp/verify?otp=${encodeURIComponent(otp)}&mobile=${encodeURIComponent(phone)}`,
      {
        method: "GET",
        headers: {
          "authkey": MSG91_AUTHKEY
        }
      }
    );

    const data = await response.json();

    console.log("MSG91 Verify:", data);

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
    console.error("MSG91 verification error:", error);

    res.status(500).json({
      success: false,
      message: "OTP verification error"
    });
  }
});

// ================= END MSG91 OTP =================
const safe=u=>u&&({id:u.id,name:u.name,phone:u.phone,email:u.email});
const emailOk=e=>/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e||"");
const phoneOk=p=>/^\+?[0-9]{10,13}$/.test((p||"").replace(/[\s-]/g,""));

app.get("/api/me",(req,res)=>res.json({user:safe(req.session.user)}));

app.post("/api/register",async(req,res)=>{
 const {name,phone,email,password}=req.body;
 if(!name||!phone||!email||!password||password.length<6) return res.status(400).json({error:"Please complete all fields. Password must be at least 6 characters."});
 if(!phoneOk(phone)) return res.status(400).json({error:"Enter a valid mobile number."});
 if(!emailOk(email)) return res.status(400).json({error:"Enter a valid email address."});
 try{
  const hash=await bcrypt.hash(password,12);
  const r=db.prepare("INSERT INTO users(name,phone,email,password_hash) VALUES(?,?,?,?)").run(name.trim(),phone.replace(/[\s-]/g,""),email.toLowerCase().trim(),hash);
  const u=db.prepare("SELECT id,name,phone,email FROM users WHERE id=?").get(r.lastInsertRowid);
  req.session.user=u;res.json({user:safe(u)});
 }catch(e){res.status(400).json({error:"That email is already registered."});}
});

app.post("/api/login",async(req,res)=>{
 const {email,password}=req.body;
 const u=db.prepare("SELECT * FROM users WHERE email=?").get((email||"").toLowerCase().trim());
 if(!u||!(await bcrypt.compare(password||"",u.password_hash))) return res.status(401).json({error:"Incorrect email or password."});
 req.session.user={id:u.id,name:u.name,phone:u.phone,email:u.email};res.json({user:safe(req.session.user)});
});

app.post("/api/logout",(req,res)=>req.session.destroy(()=>res.json({ok:true})));

app.get("/api/orders",(req,res)=>{
 if(!req.session.user)return res.status(401).json({error:"Login required"});
 const rows=db.prepare("SELECT id,items_json,amount_paise,status,created_at FROM orders WHERE user_id=? ORDER BY id DESC").all(req.session.user.id);
 res.json({orders:rows});
});

app.post("/api/create-order",async(req,res)=>{
 if(!req.session.user)return res.status(401).json({error:"Please login before checkout."});
 const {name,phone,email,address,items,total}=req.body;
 if(!name||!phone||!email||!address||!Array.isArray(items)||!items.length||!Number.isFinite(total)||total<=0)return res.status(400).json({error:"Please complete your order details."});
 if(!process.env.RAZORPAY_KEY_ID||!process.env.RAZORPAY_KEY_SECRET)return res.status(503).json({error:"Razorpay is not configured yet. Add your live/test keys on the server."});
 try{
  const rz=new Razorpay({key_id:process.env.RAZORPAY_KEY_ID,key_secret:process.env.RAZORPAY_KEY_SECRET});
  const order=await rz.orders.create({amount:Math.round(total*100),currency:"INR",receipt:"SS"+Date.now()});
  const r=db.prepare(`INSERT INTO orders(user_id,name,phone,email,address,items_json,amount_paise,razorpay_order_id) VALUES(?,?,?,?,?,?,?,?)`)
   .run(req.session.user.id,name,phone,email,address,JSON.stringify(items),Math.round(total*100),order.id);
  res.json({localOrderId:r.lastInsertRowid,razorpayOrderId:order.id,keyId:process.env.RAZORPAY_KEY_ID});
 }catch(e){console.error(e);res.status(500).json({error:"Could not start payment."});}
});

app.post("/api/verify-payment",(req,res)=>{
 if(!req.session.user)return res.status(401).json({error:"Login required"});
 const {localOrderId,razorpayPaymentId,razorpayOrderId,razorpaySignature}=req.body;
 const row=db.prepare("SELECT * FROM orders WHERE id=? AND user_id=?").get(localOrderId,req.session.user.id);
 if(!row)return res.status(404).json({error:"Order not found."});
 const expected=crypto.createHmac("sha256",process.env.RAZORPAY_KEY_SECRET).update(row.razorpay_order_id+"|"+razorpayPaymentId).digest("hex");
 if(expected!==razorpaySignature||row.razorpay_order_id!==razorpayOrderId)return res.status(400).json({error:"Payment verification failed."});
 db.prepare("UPDATE orders SET status='paid',razorpay_payment_id=? WHERE id=?").run(razorpayPaymentId,row.id);
 res.json({ok:true});
});

app.get("/", (req, res) => res.sendFile(path.join(__dirname, "index.html")));
app.listen(process.env.PORT||3000,()=>console.log("Shiv Supplements online store running"));
