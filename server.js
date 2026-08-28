require('dotenv').config();

const express = require('express');
const path = require('path');
const crypto = require('crypto');
const Database = require('better-sqlite3');
const session = require('express-session');

const app = express();
const PORT = Number(process.env.PORT) || 10000;
const ROOT = __dirname;

const db = new Database(process.env.DB_PATH || path.join(ROOT, 'shiv_supplements.db'));
db.pragma('journal_mode = WAL');

// ---------------- DATABASE ----------------
db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  phone TEXT UNIQUE NOT NULL,
  email TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS products (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  brand TEXT NOT NULL,
  name TEXT NOT NULL,
  category TEXT NOT NULL,
  flavor TEXT DEFAULT '',
  size TEXT DEFAULT '',
  mrp REAL NOT NULL DEFAULT 0,
  price REAL NOT NULL DEFAULT 0,
  stock INTEGER NOT NULL DEFAULT 0,
  image TEXT DEFAULT '',
  description TEXT DEFAULT '',
  active INTEGER NOT NULL DEFAULT 1,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT DEFAULT CURRENT_TIMESTAMP
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

// Safe migrations for older versions.
const cols = db.prepare('PRAGMA table_info(orders)').all();
const has = (n) => cols.some(c => c.name === n);
if (!has('payment_method')) db.exec("ALTER TABLE orders ADD COLUMN payment_method TEXT DEFAULT 'UPI'");
if (!has('payment_ref')) db.exec("ALTER TABLE orders ADD COLUMN payment_ref TEXT");
if (!has('user_id')) db.exec("ALTER TABLE orders ADD COLUMN user_id INTEGER");

// Seed only if product table is empty.
if (db.prepare('SELECT COUNT(*) AS c FROM products').get().c === 0) {
  const seed = [
    ['MuscleBlaze','Biozyme Whey','Whey Protein','Chocolate','1 kg',3999,2999,10,'','Premium whey protein.'],
    ['Avvatar','Whey Protein','Whey Protein','Malai Kulfi','1 kg',3999,3199,10,'','High-quality whey protein.'],
    ['Optimum Nutrition','Gold Standard Whey','Whey Protein','Double Rich Chocolate','1 lb',2499,2199,10,'','Popular whey protein.'],
    ['MuscleBlaze','Creatine Monohydrate','Creatine','Unflavoured','250 g',999,799,15,'','Creatine monohydrate.'],
    ['Avvatar','Mass Gainer','Mass Gainer','Chocolate','3 kg',3499,2899,8,'','Mass gainer for calorie surplus.'],
    ['MuscleBlaze','Pre Workout','Pre-Workout','Fruit Punch','100 g',1499,1199,8,'','Pre-workout supplement.']
  ];
  const ins = db.prepare(`INSERT INTO products
    (brand,name,category,flavor,size,mrp,price,stock,image,description)
    VALUES (?,?,?,?,?,?,?,?,?,?)`);
  const tx = db.transaction(() => seed.forEach(p => ins.run(...p)));
  tx();
}

// ---------------- EXPRESS ----------------
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true }));
app.set('trust proxy', 1);
app.use(session({
  secret: process.env.SESSION_SECRET || 'shiv-supplements-change-this-secret',
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: 'lax',
    secure: process.env.NODE_ENV === 'production',
    maxAge: 7 * 24 * 60 * 60 * 1000
  }
}));

function hashPassword(p) { return crypto.createHash('sha256').update(String(p)).digest('hex'); }
function normalizePhone(p) { return String(p || '').replace(/\D/g, '').slice(-10); }
function validPhone(p) { return /^[6-9]\d{9}$/.test(String(p)); }
function validEmail(e) { return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(String(e || '')); }
function safeUser(u) { return u ? { id:u.id, name:u.name, phone:u.phone, email:u.email } : null; }
function requireLogin(req,res,next) {
  if (!req.session.user) return res.status(401).json({success:false,message:'Please login first'});
  next();
}
function requireAdmin(req,res,next) {
  if (!req.session.admin) return res.status(401).json({success:false,message:'Admin login required'});
  next();
}
function cleanProduct(body) {
  const p = {
    brand: String(body.brand || '').trim().slice(0,100),
    name: String(body.name || '').trim().slice(0,200),
    category: String(body.category || '').trim().slice(0,100),
    flavor: String(body.flavor || '').trim().slice(0,100),
    size: String(body.size || '').trim().slice(0,100),
    mrp: Number(body.mrp),
    price: Number(body.price),
    stock: Math.max(0, Math.floor(Number(body.stock || 0))),
    image: String(body.image || '').trim().slice(0,1000),
    description: String(body.description || '').trim().slice(0,500)
  };
  if (!p.brand || !p.name || !p.category) throw Object.assign(new Error('Brand, product name and category are required'),{status:400});
  if (!Number.isFinite(p.mrp) || p.mrp < 0 || !Number.isFinite(p.price) || p.price < 0) throw Object.assign(new Error('Enter valid MRP and selling price'),{status:400});
  if (p.mrp > 0 && p.price > p.mrp) throw Object.assign(new Error('Selling price cannot be greater than MRP'),{status:400});
  return p;
}
function serializeProduct(p) {
  const mrp = Number(p.mrp || 0), price = Number(p.price || 0);
  return {...p, mrp, price, stock:Number(p.stock||0), active:Boolean(p.active), discount:mrp ? Math.max(0,Math.round((1-price/mrp)*100)) : 0};
}
function parseOrderItems(items) {
  if (!Array.isArray(items) || !items.length) throw Object.assign(new Error('Order items are required'),{status:400});
  return items.map(x => {
    const id = Number(x.id), qty = Math.max(1,Math.floor(Number(x.qty || x.quantity || 1)));
    if (!Number.isInteger(id) || !Number.isInteger(qty)) throw Object.assign(new Error('Invalid product or quantity'),{status:400});
    const p = db.prepare('SELECT id,brand,name,category,flavor,size,price,stock,active FROM products WHERE id=?').get(id);
    if (!p || !p.active) throw Object.assign(new Error('A selected product is no longer available'),{status:400});
    if (p.stock < qty) throw Object.assign(new Error(`${p.name} has only ${p.stock} item(s) in stock`),{status:400});
    return {id:p.id,brand:p.brand,name:p.name,category:p.category,flavor:p.flavor||'',size:p.size||'',price:Number(p.price),qty};
  });
}
function createOrder(req,body) {
  const name=String(body.name||'').trim(), phone=normalizePhone(body.phone), email=String(body.email||'').trim().toLowerCase(), address=String(body.address||'').trim();
  if (!name || !phone || !email || !address) throw Object.assign(new Error('All delivery details are required'),{status:400});
  if (!validPhone(phone)) throw Object.assign(new Error('Enter a valid 10-digit mobile number'),{status:400});
  if (!validEmail(email)) throw Object.assign(new Error('Enter a valid email address'),{status:400});
  const items=parseOrderItems(body.items);
  const amount=items.reduce((s,i)=>s+i.price*i.qty,0);
  if (amount<=0) throw Object.assign(new Error('Invalid order amount'),{status:400});
  const r=db.prepare(`INSERT INTO orders(user_id,name,phone,email,address,items_json,amount_paise,status,payment_method)
    VALUES(?,?,?,?,?,?,?,'pending','UPI')`).run(req.session.user.id,name,phone,email,address,JSON.stringify(items),Math.round(amount*100));
  return {id:Number(r.lastInsertRowid),amount,currency:'INR',status:'pending',paymentMethod:'UPI'};
}

// ---------------- PAGES / STATIC ----------------
app.get('/', (req,res) => res.sendFile(path.join(ROOT,'index.html')));
app.get('/admin', (req,res) => res.sendFile(path.join(ROOT,'admin.html')));
app.get('/admin.html', (req,res) => res.sendFile(path.join(ROOT,'admin.html')));
app.use((req,res,next)=> req.path === '/server.js' ? res.status(404).send('Not found') : next());
app.use(express.static(ROOT, { index:false, dotfiles:'ignore' }));

// ---------------- PUBLIC / CUSTOMER ----------------
app.get('/api/health',(req,res)=>res.json({success:true,message:'Shiv Supplements server is running'}));
app.get('/api/store-settings',(req,res)=>res.json({success:true,storeName:'Shiv Supplements',upiId:process.env.UPI_ID||'',qrImage:process.env.QR_IMAGE||'qr.png'}));
app.get('/api/me',(req,res)=>res.json({success:true,user:req.session.user||null}));

app.post('/api/register',(req,res)=>{
  try {
    const name=String(req.body.name||'').trim(), phone=normalizePhone(req.body.phone), email=String(req.body.email||'').trim().toLowerCase(), password=String(req.body.password||'');
    if(!name||!phone||!email||!password) return res.status(400).json({success:false,message:'Name, phone, email and password are required'});
    if(!validPhone(phone)) return res.status(400).json({success:false,message:'Enter a valid 10-digit mobile number'});
    if(!validEmail(email)) return res.status(400).json({success:false,message:'Enter a valid email address'});
    if(password.length<6) return res.status(400).json({success:false,message:'Password must contain at least 6 characters'});
    const exists=db.prepare('SELECT id FROM users WHERE phone=? OR email=?').get(phone,email);
    if(exists) return res.status(409).json({success:false,message:'Phone number or email is already registered'});
    const r=db.prepare('INSERT INTO users(name,phone,email,password_hash) VALUES(?,?,?,?)').run(name,phone,email,hashPassword(password));
    const user=db.prepare('SELECT id,name,phone,email FROM users WHERE id=?').get(r.lastInsertRowid);
    req.session.user=user;
    res.json({success:true,message:'Registration successful',user:safeUser(user)});
  } catch(e){ console.error(e); res.status(500).json({success:false,message:'Registration failed'}); }
});

app.post('/api/login',(req,res)=>{
  try{
    const identifier=String(req.body.identifier||req.body.email||req.body.phone||'').trim();
    const password=String(req.body.password||'');
    if(!identifier||!password) return res.status(400).json({success:false,message:'Email/mobile and password are required'});
    const user=db.prepare('SELECT * FROM users WHERE phone=? OR email=?').get(normalizePhone(identifier),identifier.toLowerCase());
    if(!user||hashPassword(password)!==user.password_hash) return res.status(401).json({success:false,message:'Invalid login details'});
    req.session.user=safeUser(user);
    res.json({success:true,message:'Login successful',user:req.session.user});
  }catch(e){console.error(e);res.status(500).json({success:false,message:'Login failed'});}
});
app.post('/api/logout',(req,res)=>req.session.destroy(()=>res.json({success:true,message:'Logged out'})));

app.get('/api/products',(req,res)=>{
  try{
    const products=db.prepare('SELECT * FROM products WHERE active=1 ORDER BY brand COLLATE NOCASE,name COLLATE NOCASE,id DESC').all().map(serializeProduct);
    res.json({success:true,products});
  }catch(e){console.error(e);res.status(500).json({success:false,message:'Could not load products'});}
});

app.post('/api/create-order',requireLogin,(req,res)=>{
  try{ const order=createOrder(req,req.body); res.json({success:true,message:'Order created. Pay by UPI and submit your UTR.',order}); }
  catch(e){console.error(e);res.status(e.status||500).json({success:false,message:e.message||'Could not create order'});}
});

app.post('/api/manual-order',requireLogin,(req,res)=>{
  try{
    const orderId=Number(req.body.orderId||req.body.localOrderId), utr=String(req.body.utr||req.body.paymentRef||'').trim().slice(0,100);
    if(!Number.isInteger(orderId)||orderId<=0||utr.length<6) return res.status(400).json({success:false,message:'Order ID and UTR are required'});
    const order=db.prepare('SELECT * FROM orders WHERE id=? AND user_id=?').get(orderId,req.session.user.id);
    if(!order) return res.status(404).json({success:false,message:'Order not found'});
    if(order.status!=='pending') return res.status(400).json({success:false,message:'This order is no longer pending'});
    db.prepare('UPDATE orders SET payment_ref=?,payment_method="UPI" WHERE id=?').run(utr,orderId);
    res.json({success:true,message:'UTR submitted. Your payment will be verified by the admin.',order:{id:orderId,status:'pending',paymentRef:utr}});
  }catch(e){console.error(e);res.status(500).json({success:false,message:'Could not submit payment details'});}
});

app.get('/api/orders',requireLogin,(req,res)=>{
  try{
    const orders=db.prepare('SELECT id,name,phone,email,address,items_json,amount_paise,status,payment_method,payment_ref,created_at FROM orders WHERE user_id=? ORDER BY id DESC').all(req.session.user.id);
    res.json({success:true,orders:orders.map(o=>({...o,amount:o.amount_paise/100,items:JSON.parse(o.items_json)}))});
  }catch(e){console.error(e);res.status(500).json({success:false,message:'Could not load orders'});}
});

// ---------------- ADMIN ----------------
app.post('/api/admin/login',(req,res)=>{
  const username=String(req.body.username||''), password=String(req.body.password||'');
  const expectedUser=process.env.ADMIN_USERNAME||'admin';
  const expectedPass=process.env.ADMIN_PASSWORD||'ChangeMe123!';
  if(username!==expectedUser||password!==expectedPass) return res.status(401).json({success:false,message:'Invalid admin credentials'});
  req.session.admin=true;
  res.json({success:true,message:'Admin login successful'});
});
app.post('/api/admin/logout',(req,res)=>{delete req.session.admin;res.json({success:true,message:'Logged out'});});
app.get('/api/admin/me',(req,res)=>res.json({success:true,loggedIn:!!req.session.admin}));

app.use('/api/admin',requireAdmin);

app.get('/api/admin/products',(req,res)=>{
  try{res.json({success:true,products:db.prepare('SELECT * FROM products ORDER BY brand COLLATE NOCASE,name COLLATE NOCASE,id DESC').all().map(serializeProduct)});}
  catch(e){console.error(e);res.status(500).json({success:false,message:'Could not load products'});}
});
app.post('/api/admin/products',(req,res)=>{
  try{const p=cleanProduct(req.body);const r=db.prepare(`INSERT INTO products(brand,name,category,flavor,size,mrp,price,stock,image,description,active,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,1,CURRENT_TIMESTAMP)`).run(p.brand,p.name,p.category,p.flavor,p.size,p.mrp,p.price,p.stock,p.image,p.description);res.json({success:true,message:'Product added',product:serializeProduct(db.prepare('SELECT * FROM products WHERE id=?').get(r.lastInsertRowid))});}
  catch(e){console.error(e);res.status(e.status||500).json({success:false,message:e.message||'Could not add product'});}
});
app.patch('/api/admin/products/:id',(req,res)=>{
  try{const id=Number(req.params.id), old=db.prepare('SELECT * FROM products WHERE id=?').get(id);if(!old)return res.status(404).json({success:false,message:'Product not found'});const p=cleanProduct({...old,...req.body});const active=req.body.active===undefined?old.active:(req.body.active?1:0);db.prepare(`UPDATE products SET brand=?,name=?,category=?,flavor=?,size=?,mrp=?,price=?,stock=?,image=?,description=?,active=?,updated_at=CURRENT_TIMESTAMP WHERE id=?`).run(p.brand,p.name,p.category,p.flavor,p.size,p.mrp,p.price,p.stock,p.image,p.description,active,id);res.json({success:true,message:'Product updated',product:serializeProduct(db.prepare('SELECT * FROM products WHERE id=?').get(id))});}
  catch(e){console.error(e);res.status(e.status||500).json({success:false,message:e.message||'Could not update product'});}
});
app.delete('/api/admin/products/:id',(req,res)=>{
  try{const id=Number(req.params.id);const r=db.prepare('DELETE FROM products WHERE id=?').run(id);if(!r.changes)return res.status(404).json({success:false,message:'Product not found'});res.json({success:true,message:'Product deleted'});}
  catch(e){console.error(e);res.status(500).json({success:false,message:'Could not delete product'});}
});

app.get('/api/admin/orders',(req,res)=>{
  try{const orders=db.prepare('SELECT * FROM orders ORDER BY id DESC').all();res.json({success:true,orders:orders.map(o=>({...o,amount:o.amount_paise/100,items:JSON.parse(o.items_json)}))});}
  catch(e){console.error(e);res.status(500).json({success:false,message:'Could not load orders'});}
});

// Payment approval is the ONLY way to move pending -> paid, so stock is decremented once.
app.patch('/api/admin/orders/:id/approve-payment',(req,res)=>{
  try{
    const id=Number(req.params.id), order=db.prepare('SELECT * FROM orders WHERE id=?').get(id);
    if(!order)return res.status(404).json({success:false,message:'Order not found'});
    if(order.status!=='pending')return res.status(400).json({success:false,message:'Only pending orders can be approved'});
    // Direct UPI flow: admin manually verifies the payment in the UPI/PhonePe app.
    // No UTR/payment reference is required.
    const items=JSON.parse(order.items_json);
    const tx=db.transaction(()=>{
      for(const item of items){const p=db.prepare('SELECT stock FROM products WHERE id=?').get(item.id);if(!p||p.stock<item.qty)throw new Error(`${item.name} does not have enough stock`);}
      for(const item of items)db.prepare('UPDATE products SET stock=stock-?,updated_at=CURRENT_TIMESTAMP WHERE id=?').run(item.qty,item.id);
      db.prepare("UPDATE orders SET status='paid' WHERE id=?").run(id);
    });
    tx();
    res.json({success:true,message:'Payment approved successfully'});
  }catch(e){console.error(e);res.status(500).json({success:false,message:e.message||'Could not approve payment'});}
});

app.patch('/api/admin/orders/:id',(req,res)=>{
  try{
    const id=Number(req.params.id), status=String(req.body.status||''), allowed=['processing','shipped','delivered','cancelled'];
    if(!allowed.includes(status))return res.status(400).json({success:false,message:'Invalid status transition'});
    const order=db.prepare('SELECT status FROM orders WHERE id=?').get(id);if(!order)return res.status(404).json({success:false,message:'Order not found'});
    if(status==='processing'&&order.status!=='paid')return res.status(400).json({success:false,message:'Payment must be approved first'});
    if(status==='shipped'&& !['paid','processing'].includes(order.status))return res.status(400).json({success:false,message:'Order is not ready to ship'});
    if(status==='delivered'&&order.status!=='shipped')return res.status(400).json({success:false,message:'Order must be shipped first'});
    db.prepare('UPDATE orders SET status=? WHERE id=?').run(status,id);
    res.json({success:true,message:'Order status updated'});
  }catch(e){console.error(e);res.status(500).json({success:false,message:'Could not update order'});}
});

app.use((err,req,res,next)=>{console.error('UNHANDLED',err);res.status(500).json({success:false,message:'Server error'});});

app.listen(PORT,'0.0.0.0',()=>console.log(`Shiv Supplements server running on port ${PORT}`));
