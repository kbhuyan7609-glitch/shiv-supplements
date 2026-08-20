# Shiv Supplements — Professional Online Store

This is a professional custom storefront inspired by common supplement e-commerce patterns (category navigation, product cards, offers, account, cart and checkout). It does NOT copy another company's exact design, text, images or branding.

Included:
- Your uploaded Shiv Supplements logo
- Professional responsive homepage
- Shop-by-category section
- Product catalog cards
- Cart with quantity controls
- Customer Login
- Customer Registration with NAME + MOBILE + EMAIL + PASSWORD
- Server-side password hashing
- Checkout with delivery address
- Razorpay Standard Checkout integration hooks
- Server-side Razorpay order creation
- Server-side HMAC payment verification
- Order storage in SQLite
- WhatsApp support button
- Instagram link

## Razorpay setup
Razorpay's official flow requires creating the order on your server, opening Checkout with the returned order_id, and verifying the returned signature server-side before fulfilling an order. Do not expose RAZORPAY_KEY_SECRET in frontend code.

1. Create/verify your Razorpay merchant account and complete KYC.
2. Copy `.env.example` to `.env`.
3. Add RAZORPAY_KEY_ID and RAZORPAY_KEY_SECRET.
4. Test with Test Mode keys.
5. For real payments, switch to Live Mode keys and deploy over HTTPS.
6. Configure capture/webhooks for production order reliability.

## Run locally
Node.js 20+ recommended:
npm install
npm start
Then open http://localhost:3000

## Add your actual products
Edit the `products` array in `public/index.html`.
For a real catalog, replace the sample prices/details and add actual product images, sizes/flavours, MRP, sale price and stock.

## Hosting
This is a Node.js application, not a plain HTML file, because login and secure Razorpay order creation require a server. Use a Node-compatible host with persistent database storage for production.
