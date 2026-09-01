require('dotenv').config();

const express = require('express');
const path = require('path');
const crypto = require('crypto');
const { Pool } = require('pg');
const session = require('express-session');
const pgSession = require('connect-pg-simple')(session);

const app = express();
const PORT = Number(process.env.PORT) || 10000;
const ROOT = __dirname;

// IMPORTANT: Render PostgreSQL is the permanent database.
// Set DATABASE_URL in Render (it is normally provided by the Render PostgreSQL service).
if (!process.env.DATABASE_URL) {
  console.error('DATABASE_URL is missing. Add the Render PostgreSQL Internal Database URL to this Web Service.');
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL ? { rejectUnauthorized: false } : false,
  max: 10,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 10000
});

pool.on('error', (err) => console.error('PostgreSQL pool error:', err));

async function db(sql, params = []) {
  return pool.query(sql, params);
}

async function initDatabase() {
  await db(`
    CREATE TABLE IF NOT EXISTS users (
      id BIGSERIAL PRIMARY KEY,
      name TEXT NOT NULL,
      phone TEXT UNIQUE NOT NULL,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS products (
      id BIGSERIAL PRIMARY KEY,
      brand TEXT NOT NULL,
      name TEXT NOT NULL,
      category TEXT NOT NULL,
      flavor TEXT DEFAULT '',
      size TEXT DEFAULT '',
      mrp DOUBLE PRECISION NOT NULL DEFAULT 0,
      price DOUBLE PRECISION NOT NULL DEFAULT 0,
      stock INTEGER NOT NULL DEFAULT 0,
      image TEXT DEFAULT '',
      description TEXT DEFAULT '',
      active BOOLEAN NOT NULL DEFAULT TRUE,
      created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
      updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS orders (
      id BIGSERIAL PRIMARY KEY,
      user_id BIGINT,
      name TEXT NOT NULL,
      phone TEXT NOT NULL,
      email TEXT NOT NULL,
      address TEXT NOT NULL,
      items_json TEXT NOT NULL,
      amount_paise BIGINT NOT NULL,
      status TEXT DEFAULT 'pending',
      payment_method TEXT DEFAULT 'UPI',
      payment_ref TEXT,
      created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
      coupon_code TEXT,
      discount_paise BIGINT DEFAULT 0,
      subtotal_paise BIGINT DEFAULT 0
    );

    ALTER TABLE orders ADD COLUMN IF NOT EXISTS payment_method TEXT DEFAULT 'UPI';
    ALTER TABLE orders ADD COLUMN IF NOT EXISTS payment_ref TEXT;
    ALTER TABLE orders ADD COLUMN IF NOT EXISTS user_id BIGINT;
    ALTER TABLE orders ADD COLUMN IF NOT EXISTS coupon_code TEXT;
    ALTER TABLE orders ADD COLUMN IF NOT EXISTS discount_paise BIGINT DEFAULT 0;
    ALTER TABLE orders ADD COLUMN IF NOT EXISTS subtotal_paise BIGINT DEFAULT 0;
  `);

  // Seed only when the permanent products table is genuinely empty.
  const count = await db('SELECT COUNT(*)::int AS c FROM products');
  if (Number(count.rows[0].c) === 0) {
    const seed = [
      ['MuscleBlaze','Biozyme Whey','Whey Protein','Chocolate','1 kg',3999,2999,10,'','Premium whey protein.'],
      ['Avvatar','Whey Protein','Whey Protein','Malai Kulfi','1 kg',3999,3199,10,'','High-quality whey protein.'],
      ['Optimum Nutrition','Gold Standard Whey','Whey Protein','Double Rich Chocolate','1 lb',2499,2199,10,'','Popular whey protein.'],
      ['MuscleBlaze','Creatine Monohydrate','Creatine','Unflavoured','250 g',999,799,15,'','Creatine monohydrate.'],
      ['Avvatar','Mass Gainer','Mass Gainer','Chocolate','3 kg',3499,2899,8,'','Mass gainer for calorie surplus.'],
      ['MuscleBlaze','Pre Workout','Pre-Workout','Fruit Punch','100 g',1499,1199,8,'','Pre-workout supplement.']
    ];
    for (const p of seed) {
      await db(`INSERT INTO products
        (brand,name,category,flavor,size,mrp,price,stock,image,description)
        VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, p);
    }
    console.log('Seeded default products because the permanent PostgreSQL products table was empty.');
  }

  console.log('PostgreSQL database ready.');
}

// ---------------- EXPRESS ----------------
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true }));
app.set('trust proxy', 1);
app.use(session({
  store: process.env.DATABASE_URL ? new pgSession({
    pool,
    tableName: 'user_sessions',
    createTableIfMissing: true
  }) : undefined,
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
function safeUser(u) { return u ? { id:Number(u.id), name:u.name, phone:u.phone, email:u.email } : null; }
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
  return {...p, id:Number(p.id), mrp, price, stock:Number(p.stock||0), active:Boolean(p.active), discount:mrp ? Math.max(0,Math.round((1-price/mrp)*100)) : 0};
}

async function parseOrderItems(items) {
  if (!Array.isArray(items) || !items.length) throw Object.assign(new Error('Order items are required'),{status:400});
  const out = [];
  for (const x of items) {
    const id = Number(x.id), qty = Math.max(1,Math.floor(Number(x.qty || x.quantity || 1)));
    if (!Number.isInteger(id) || !Number.isInteger(qty)) throw Object.assign(new Error('Invalid product or quantity'),{status:400});
    const r = await db('SELECT id,brand,name,category,flavor,size,price,stock,active FROM products WHERE id=$1',[id]);
    const p = r.rows[0];
    if (!p || !p.active) throw Object.assign(new Error('A selected product is no longer available'),{status:400});
    if (Number(p.stock) < qty) throw Object.assign(new Error(`${p.name} has only ${p.stock} item(s) in stock`),{status:400});
    out.push({id:Number(p.id),brand:p.brand,name:p.name,category:p.category,flavor:p.flavor||'',size:p.size||'',price:Number(p.price),qty});
  }
  return out;
}

async function validateCoupon(req, code) {
  const normalized=String(code||'').trim().toUpperCase();
  if(!normalized) return {valid:false,code:'',discount:0,message:''};
  if(normalized!=='WELCOME10' && normalized!=='1STORDER10') return {valid:false,code:normalized,discount:0,message:'Invalid coupon code'};
  const userId=req.session.user?.id;
  const r=await db('SELECT COUNT(*)::int AS c FROM orders WHERE user_id=$1',[userId]);
  const orderCount=Number(r.rows[0].c||0);
  if(normalized==='1STORDER10' && orderCount>0) return {valid:false,code:normalized,discount:0,message:'1STORDER10 is valid only on your first order'};
  return {valid:true,code:normalized,discount:0.10,message:'10% discount applied'};
}

async function createOrder(req,body) {
  const name=String(body.name||'').trim(), phone=normalizePhone(body.phone), email=String(body.email||'').trim().toLowerCase(), address=String(body.address||'').trim();
  const paymentMethod=String(body.paymentMethod||'UPI').trim().toUpperCase();
  if (!['UPI','COD'].includes(paymentMethod)) throw Object.assign(new Error('Invalid payment method'),{status:400});
  if (!name || !phone || !email || !address) throw Object.assign(new Error('All delivery details are required'),{status:400});
  if (!validPhone(phone)) throw Object.assign(new Error('Enter a valid 10-digit mobile number'),{status:400});
  if (!validEmail(email)) throw Object.assign(new Error('Enter a valid email address'),{status:400});
  const items=await parseOrderItems(body.items);
  const subtotal=items.reduce((s,i)=>s+i.price*i.qty,0);
  if (subtotal<=0) throw Object.assign(new Error('Invalid order amount'),{status:400});
  const coupon=await validateCoupon(req,body.couponCode);
  if(String(body.couponCode||'').trim() && !coupon.valid) throw Object.assign(new Error(coupon.message),{status:400});
  const discount=Math.round(subtotal*(coupon.valid?coupon.discount:0));
  const amount=Math.max(0,subtotal-discount);
  const r=await db(`INSERT INTO orders(user_id,name,phone,email,address,items_json,amount_paise,status,payment_method,coupon_code,discount_paise,subtotal_paise)
    VALUES($1,$2,$3,$4,$5,$6,$7,'pending',$8,$9,$10,$11) RETURNING id`,
    [req.session.user.id,name,phone,email,address,JSON.stringify(items),Math.round(amount*100),paymentMethod,coupon.valid?coupon.code:null,Math.round(discount*100),Math.round(subtotal*100)]);
  return {id:Number(r.rows[0].id),amount,currency:'INR',status:'pending',paymentMethod,subtotal,discount,couponCode:coupon.valid?coupon.code:null};
}

// ---------------- PAGES / STATIC ----------------
app.get('/', (req,res) => res.sendFile(path.join(ROOT,'index.html')));
app.get('/admin', (req,res) => res.sendFile(path.join(ROOT,'admin.html')));
app.get('/admin.html', (req,res) => res.sendFile(path.join(ROOT,'admin.html')));
app.use((req,res,next)=> req.path === '/server.js' ? res.status(404).send('Not found') : next());
app.use(express.static(ROOT, { index:false, dotfiles:'ignore' }));

// ---------------- PUBLIC / CUSTOMER ----------------
app.get('/api/health',async(req,res)=>res.json({success:true,message:'Shiv Supplements server is running',database:'postgresql'}));
app.get('/api/store-settings',(req,res)=>res.json({success:true,storeName:'Shiv Supplements',upiId:process.env.UPI_ID||'',qrImage:process.env.QR_IMAGE||'qr.png'}));
app.get('/api/me',(req,res)=>res.json({success:true,user:req.session.user||null}));

app.post('/api/register',async(req,res)=>{
  try {
    const name=String(req.body.name||'').trim(), phone=normalizePhone(req.body.phone), email=String(req.body.email||'').trim().toLowerCase(), password=String(req.body.password||'');
    if(!name||!phone||!email||!password) return res.status(400).json({success:false,message:'Name, phone, email and password are required'});
    if(!validPhone(phone)) return res.status(400).json({success:false,message:'Enter a valid 10-digit mobile number'});
    if(!validEmail(email)) return res.status(400).json({success:false,message:'Enter a valid email address'});
    if(password.length<6) return res.status(400).json({success:false,message:'Password must contain at least 6 characters'});
    const exists=await db('SELECT id FROM users WHERE phone=$1 OR email=$2',[phone,email]);
    if(exists.rows[0]) return res.status(409).json({success:false,message:'Phone number or email is already registered'});
    const r=await db('INSERT INTO users(name,phone,email,password_hash) VALUES($1,$2,$3,$4) RETURNING id,name,phone,email',[name,phone,email,hashPassword(password)]);
    const user=r.rows[0];
    req.session.user=user;
    res.json({success:true,message:'Registration successful',user:safeUser(user)});
  } catch(e){ console.error(e); res.status(500).json({success:false,message:'Registration failed'}); }
});

app.post('/api/login',async(req,res)=>{
  try{
    const identifier=String(req.body.identifier||req.body.email||req.body.phone||'').trim();
    const password=String(req.body.password||'');
    if(!identifier||!password) return res.status(400).json({success:false,message:'Email/mobile and password are required'});
    const r=await db('SELECT * FROM users WHERE phone=$1 OR email=$2',[normalizePhone(identifier),identifier.toLowerCase()]);
    const user=r.rows[0];
    if(!user||hashPassword(password)!==user.password_hash) return res.status(401).json({success:false,message:'Invalid login details'});
    req.session.user=safeUser(user);
    res.json({success:true,message:'Login successful',user:req.session.user});
  }catch(e){console.error(e);res.status(500).json({success:false,message:'Login failed'});}
});
app.post('/api/logout',(req,res)=>req.session.destroy(()=>res.json({success:true,message:'Logged out'})));

app.get('/api/products',async(req,res)=>{
  try{
    const r=await db('SELECT * FROM products WHERE active=TRUE ORDER BY brand COLLATE "C",name COLLATE "C",id DESC');
    res.json({success:true,products:r.rows.map(serializeProduct)});
  }catch(e){console.error(e);res.status(500).json({success:false,message:'Could not load products'});}
});

app.post('/api/coupons/validate',requireLogin,async(req,res)=>{
  try {
    const code=String(req.body.code||'').trim().toUpperCase();
    const subtotal=Math.max(0,Number(req.body.subtotal||0));
    const result=await validateCoupon(req,code);
    if(!result.valid) return res.status(400).json({success:false,message:result.message||'Invalid coupon'});
    const discount=Math.round(subtotal*result.discount);
    res.json({success:true,code:result.code,discountPercent:10,discount,finalAmount:Math.max(0,subtotal-discount),message:'Coupon applied successfully'});
  } catch(e) { res.status(500).json({success:false,message:'Could not validate coupon'}); }
});

app.post('/api/create-order',requireLogin,async(req,res)=>{
  try{ const order=await createOrder(req,req.body); res.json({success:true,message:order.paymentMethod==='COD'?'Order placed with Cash on Delivery.':'Order created. Pay by UPI.',order}); }
  catch(e){console.error(e);res.status(e.status||500).json({success:false,message:e.message||'Could not create order'});}
});

app.post('/api/manual-order',requireLogin,async(req,res)=>{
  try{
    const orderId=Number(req.body.orderId||req.body.localOrderId||req.body.id);
    if(!Number.isInteger(orderId)||orderId<=0) return res.status(400).json({success:false,message:'Order ID is required'});
    const r=await db('SELECT id,status,payment_method FROM orders WHERE id=$1 AND user_id=$2',[orderId,req.session.user.id]);
    const order=r.rows[0];
    if(!order) return res.status(404).json({success:false,message:'Order not found'});
    if(order.status!=='pending') return res.status(400).json({success:false,message:'This order is no longer pending'});
    res.json({success:true,message:'Payment recorded as pending verification. Admin will verify the UPI payment.',order:{id:Number(order.id),status:order.status,paymentMethod:order.payment_method||'UPI'}});
  }catch(e){console.error(e);res.status(500).json({success:false,message:'Could not update payment status'});}
});

app.get('/api/orders',requireLogin,async(req,res)=>{
  try{
    const r=await db('SELECT id,name,phone,email,address,items_json,amount_paise,status,payment_method,payment_ref,coupon_code,discount_paise,subtotal_paise,created_at FROM orders WHERE user_id=$1 ORDER BY id DESC',[req.session.user.id]);
    res.json({success:true,orders:r.rows.map(o=>({...o,id:Number(o.id),amount:Number(o.amount_paise)/100,items:JSON.parse(o.items_json)}))});
  }catch(e){console.error(e);res.status(500).json({success:false,message:'Could not load orders'});}
});

// ---------------- ADMIN ----------------
app.post('/api/admin/login',async(req,res)=>{
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

app.get('/api/admin/products',async(req,res)=>{
  try{const r=await db('SELECT * FROM products ORDER BY brand COLLATE "C",name COLLATE "C",id DESC');res.json({success:true,products:r.rows.map(serializeProduct)});}
  catch(e){console.error(e);res.status(500).json({success:false,message:'Could not load products'});}
});
app.post('/api/admin/products',async(req,res)=>{
  try{
    const p=cleanProduct(req.body);
    const r=await db(`INSERT INTO products(brand,name,category,flavor,size,mrp,price,stock,image,description,active,updated_at)
      VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,TRUE,CURRENT_TIMESTAMP) RETURNING *`,
      [p.brand,p.name,p.category,p.flavor,p.size,p.mrp,p.price,p.stock,p.image,p.description]);
    res.json({success:true,message:'Product added',product:serializeProduct(r.rows[0])});
  }catch(e){console.error(e);res.status(e.status||500).json({success:false,message:e.message||'Could not add product'});}
});
app.patch('/api/admin/products/:id',async(req,res)=>{
  try{
    const id=Number(req.params.id);
    const oldR=await db('SELECT * FROM products WHERE id=$1',[id]);
    const old=oldR.rows[0];
    if(!old)return res.status(404).json({success:false,message:'Product not found'});
    const p=cleanProduct({...old,...req.body});
    const active=req.body.active===undefined?Boolean(old.active):(req.body.active?true:false);
    const r=await db(`UPDATE products SET brand=$1,name=$2,category=$3,flavor=$4,size=$5,mrp=$6,price=$7,stock=$8,image=$9,description=$10,active=$11,updated_at=CURRENT_TIMESTAMP WHERE id=$12 RETURNING *`,
      [p.brand,p.name,p.category,p.flavor,p.size,p.mrp,p.price,p.stock,p.image,p.description,active,id]);
    res.json({success:true,message:'Product updated',product:serializeProduct(r.rows[0])});
  }catch(e){console.error(e);res.status(e.status||500).json({success:false,message:e.message||'Could not update product'});}
});
app.delete('/api/admin/products/:id',async(req,res)=>{
  try{
    const id=Number(req.params.id);
    const r=await db('DELETE FROM products WHERE id=$1',[id]);
    if(!r.rowCount)return res.status(404).json({success:false,message:'Product not found'});
    res.json({success:true,message:'Product deleted'});
  }catch(e){console.error(e);res.status(500).json({success:false,message:'Could not delete product'});}
});

app.get('/api/admin/orders',async(req,res)=>{
  try{const r=await db('SELECT * FROM orders ORDER BY id DESC');res.json({success:true,orders:r.rows.map(o=>({...o,id:Number(o.id),amount:Number(o.amount_paise)/100,items:JSON.parse(o.items_json)}))});}
  catch(e){console.error(e);res.status(500).json({success:false,message:'Could not load orders'});}
});

// Payment approval is the ONLY way to move pending -> paid, so stock is decremented once.
app.patch('/api/admin/orders/:id/approve-payment',async(req,res)=>{
  const client=await pool.connect();
  try{
    const id=Number(req.params.id);
    const orderR=await client.query('SELECT * FROM orders WHERE id=$1 FOR UPDATE',[id]);
    const order=orderR.rows[0];
    if(!order)return res.status(404).json({success:false,message:'Order not found'});
    if(order.status!=='pending')return res.status(400).json({success:false,message:'Only pending orders can be approved'});
    const items=JSON.parse(order.items_json);
    await client.query('BEGIN');
    for(const item of items){
      const p=(await client.query('SELECT stock FROM products WHERE id=$1 FOR UPDATE',[item.id])).rows[0];
      if(!p||Number(p.stock)<item.qty)throw new Error(`${item.name} does not have enough stock`);
    }
    for(const item of items)await client.query('UPDATE products SET stock=stock-$1,updated_at=CURRENT_TIMESTAMP WHERE id=$2',[item.qty,item.id]);
    await client.query("UPDATE orders SET status='paid' WHERE id=$1",[id]);
    await client.query('COMMIT');
    res.json({success:true,message:'Payment approved successfully'});
  }catch(e){
    try{await client.query('ROLLBACK');}catch{}
    console.error(e);res.status(500).json({success:false,message:e.message||'Could not approve payment'});
  }finally{client.release();}
});

app.patch('/api/admin/orders/:id',async(req,res)=>{
  try{
    const id=Number(req.params.id), status=String(req.body.status||''), allowed=['processing','shipped','delivered','cancelled'];
    if(!allowed.includes(status))return res.status(400).json({success:false,message:'Invalid status transition'});
    const r=await db('SELECT status FROM orders WHERE id=$1',[id]);
    const order=r.rows[0];
    if(!order)return res.status(404).json({success:false,message:'Order not found'});
    if(status==='processing'&&order.status!=='paid')return res.status(400).json({success:false,message:'Payment must be approved first'});
    if(status==='shipped'&& !['paid','processing'].includes(order.status))return res.status(400).json({success:false,message:'Order is not ready to ship'});
    if(status==='delivered'&&order.status!=='shipped')return res.status(400).json({success:false,message:'Order must be shipped first'});
    await db('UPDATE orders SET status=$1 WHERE id=$2',[status,id]);
    res.json({success:true,message:'Order status updated'});
  }catch(e){console.error(e);res.status(500).json({success:false,message:'Could not update order'});}
});

app.use((err,req,res,next)=>{console.error('UNHANDLED',err);res.status(500).json({success:false,message:'Server error'});});

initDatabase().then(()=>{
  app.listen(PORT,'0.0.0.0',()=>console.log(`Shiv Supplements server running on port ${PORT} using PostgreSQL`));
}).catch(err=>{
  console.error('DATABASE STARTUP FAILED:', err);
  process.exit(1);
});
