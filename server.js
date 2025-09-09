// server.js — NVRBRTH backend (Stripe Checkout + Adaptive Pricing ready)
// ---------------------------------------------------------------
// ENV REQUIRED: STRIPE_SECRET_KEY, ADMIN_KEY
// ENV OPTIONAL: PORT, FROM_EMAIL, RESEND_API_KEY,
//               FREE_SHIPPING_GBP (e.g. "6000" for £60 threshold),
//               META_PIXEL_ID, META_ACCESS_TOKEN,
//               TIKTOK_PIXEL_ID, TIKTOK_ACCESS_TOKEN,
//               STRIPE_WEBHOOK_SECRET
// ---------------------------------------------------------------

// Load .env locally; on Render env vars are injected automatically
require("dotenv").config();

const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const stripe = require("stripe")(process.env.STRIPE_SECRET_KEY);

// Optional deps (don’t crash if not installed)
let rateLimit = null;
try { rateLimit = require("express-rate-limit"); } catch {}
let resend = null;
try {
  const { Resend } = require("@resend/node");
  if (process.env.RESEND_API_KEY) resend = new Resend(process.env.RESEND_API_KEY);
} catch {}

// ---------- Config ----------
const PORT = process.env.PORT || 8787;
const FROM_EMAIL = process.env.FROM_EMAIL || "orders@nvrbrth.store";
const ORDERS_FILE = path.join(process.cwd(), "orders.jsonl");
const INVENTORY_FILE = path.join(process.cwd(), "inventory.json"); // { "lookup_key": { "stock": 50 } }
const FREE_SHIPPING_GBP = Number(process.env.FREE_SHIPPING_GBP || "0"); // minor units (e.g., 6000 = £60)

// ---------- App ----------
const app = express();

// Webhook needs raw body
app.post("/webhooks/stripe", express.raw({ type: "application/json" }), handleStripeWebhook);

// JSON elsewhere
app.use(express.json({ limit: "1mb" }));
app.use(helmet({ crossOriginResourcePolicy: { policy: "cross-origin" } }));
if (rateLimit) {
  app.use(rateLimit({ windowMs: 60_000, max: 120 })); // 120 req/min per IP
}
app.use(
  cors({
    origin: [/^http:\/\/localhost:\d+$/, /^https:\/\/([a-z0-9-]+\.)?nvrbrth\.store$/i],
    credentials: true,
  })
);

// ---------- Tiny JSONL “DB” ----------
async function fileAppend(obj) {
  await fs.promises.appendFile(ORDERS_FILE, JSON.stringify(obj) + "\n", "utf8");
}
async function fileReadAll() {
  try {
    const txt = await fs.promises.readFile(ORDERS_FILE, "utf8");
    return txt.split("\n").filter(Boolean).map((l) => JSON.parse(l));
  } catch (e) {
    if (e.code === "ENOENT") return [];
    throw e;
  }
}
async function dbGetOrderBySessionId(sessionId) {
  const all = await fileReadAll();
  return [...all].reverse().find((o) => o.stripe_session_id === sessionId) || null;
}
async function dbGetOrderById(orderId) {
  const all = await fileReadAll();
  return [...all].reverse().find((o) => o.id === orderId) || null;
}
async function dbWriteSnapshot(orderObj) {
  await fileAppend({ ...orderObj, snapshot_at: new Date().toISOString() });
}

// ---------- Inventory (optional) ----------
async function invLoad() {
  try {
    const raw = await fs.promises.readFile(INVENTORY_FILE, "utf8");
    return JSON.parse(raw);
  } catch (e) {
    if (e.code === "ENOENT") return null; // inventory disabled
    throw e;
  }
}
async function invSave(inv) {
  await fs.promises.writeFile(INVENTORY_FILE, JSON.stringify(inv, null, 2), "utf8");
}
async function invCheckAndMaybeReserve(cartMap /* {lookup_key: qty} */) {
  const inv = await invLoad();
  if (!inv) return { ok: true, reserved: null }; // no inventory file => skip
  for (const [lk, qty] of Object.entries(cartMap)) {
    const row = inv[lk];
    if (!row || typeof row.stock !== "number") {
      return { ok: false, error: `No inventory for ${lk}` };
    }
    if (row.stock < qty) {
      return { ok: false, error: `Insufficient stock for ${lk} (have ${row.stock}, need ${qty})` };
    }
  }
  return { ok: true, reserved: null };
}
async function invDecrement(lineItems /* [{lookup_key, quantity}] */) {
  const inv = await invLoad();
  if (!inv) return;
  for (const li of lineItems) {
    const row = inv[li.lookup_key];
    if (row && typeof row.stock === "number") {
      row.stock = Math.max(0, row.stock - (li.quantity || 1));
    }
  }
  await invSave(inv);
}
async function invIncrement(lineItems) {
  const inv = await invLoad();
  if (!inv) return;
  for (const li of lineItems) {
    const row = inv[li.lookup_key];
    if (row && typeof row.stock === "number") {
      row.stock += (li.quantity || 1);
    }
  }
  await invSave(inv);
}

// ---------- Prices cache ----------
let PRICE_CACHE = null;
let PRICE_CACHE_AT = 0;
const PRICE_TTL_MS = 5 * 60 * 1000;

async function refreshPrices() {
  const prices = [];
  let starting_after = null;
  do {
    const resp = await stripe.prices.list({
      active: true,
      limit: 100,
      starting_after,
      expand: ["data.product"],
    });
    prices.push(...resp.data.filter((p) => !!p.lookup_key));
    starting_after = resp.has_more ? resp.data[resp.data.length - 1].id : null;
  } while (starting_after);
  const map = {};
  for (const p of prices) {
    const key = p.lookup_key;
    if (!map[key] || p.created > map[key].created) map[key] = p;
  }
  PRICE_CACHE = map;
  PRICE_CACHE_AT = Date.now();
  return map;
}
async function getPrices() {
  if (!PRICE_CACHE || Date.now() - PRICE_CACHE_AT > PRICE_TTL_MS) await refreshPrices();
  return PRICE_CACHE;
}

// ---------- Helpers ----------
function requireAdmin(req, res, next) {
  const got = (req.headers["x-admin-key"] || "").toString();
  if (!got || got !== process.env.ADMIN_KEY) return res.status(401).json({ error: "Unauthorized" });
  next();
}
function asCurrency(amount, currency) {
  try {
    return new Intl.NumberFormat("en-GB", {
      style: "currency",
      currency: (currency || "GBP").toUpperCase(),
    }).format((amount || 0) / 100);
  } catch {
    return `${(amount || 0) / 100} ${currency || "GBP"}`;
  }
}
function hashIdem(obj) {
  return crypto.createHash("sha256").update(JSON.stringify(obj)).digest("hex");
}
function renderOrderEmail({ id, created_at, items, note, pricing, presentment, shipped }) {
  const lines = items
    .map(
      (li) =>
        `<tr><td style="padding:6px 0">${li.name}${li.size ? ` — <strong>${li.size}</strong>` : ""} × ${li.quantity}</td><td style="text-align:right">${asCurrency(li.unit_amount, pricing.currency)}</td></tr>`
    )
    .join("");

  const totalsHtml = `
  <tr><td style="padding:6px 0">Subtotal</td><td style="text-align:right">${asCurrency(pricing.subtotal, pricing.currency)}</td></tr>
  ${pricing.shipping_amount ? `<tr><td>Shipping</td><td style="text-align:right">${asCurrency(pricing.shipping_amount, pricing.currency)}</td></tr>` : ""}
  ${pricing.tax_amount ? `<tr><td>Tax</td><td style="text-align:right">${asCurrency(pricing.tax_amount, pricing.currency)}</td></tr>` : ""}
  <tr><td><strong>Total</strong></td><td style="text-align:right"><strong>${asCurrency(pricing.total, pricing.currency)}</strong></td></tr>`;

  const presentmentHtml = presentment
    ? `<p style="margin-top:12px;color:#444">Charged in ${presentment.currency.toUpperCase()}: <strong>${asCurrency(presentment.amount, presentment.currency)}</strong>.</p>`
    : "";

  const shipHtml = shipped
    ? `<p style="margin-top:12px"><strong>Shipped:</strong> ${new Date(shipped.when).toLocaleString()} — ${shipped.carrier || "Carrier"} ${shipped.tracking ? `• Tracking: <a href="${shipped.tracking_url || "#"}">${shipped.tracking}</a>` : ""}</p>`
    : "";

  const noteHtml = note ? `<p style="margin-top:12px"><em>Note:</em> ${String(note).slice(0, 500)}</p>` : "";

  return `
  <div style="font-family:system-ui,-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;max-width:560px">
    <h2 style="margin:0 0 12px">NVRBRTH — Order ${id}</h2>
    <p style="margin:0 12px 12px 0;color:#666">Placed ${new Date(created_at).toLocaleString()}</p>
    <table style="width:100%;border-collapse:collapse">${lines}${totalsHtml}</table>
    ${presentmentHtml}${shipHtml}${noteHtml}
    <p style="margin-top:20px">We’ll email shipping updates. — NVRBRTH</p>
  </div>`;
}

async function sendEmail(to, subject, html) {
  if (!resend) return;
  try {
    await resend.emails.send({ from: `NVRBRTH <${FROM_EMAIL}>`, to, subject, html });
  } catch (e) {
    console.error("Resend error:", e?.message || e);
  }
}

// ---- Pixels (server-side) — optional stubs ----
async function fireMetaCAPI({ event_name, event_time, email, value_minor, currency, event_id }) {
  const PIXEL_ID = process.env.META_PIXEL_ID;
  const ACCESS_TOKEN = process.env.META_ACCESS_TOKEN;
  if (!PIXEL_ID || !ACCESS_TOKEN) return;
  try {
    const url = `https://graph.facebook.com/v20.0/${PIXEL_ID}/events?access_token=${ACCESS_TOKEN}`;
    const payload = {
      data: [
        {
          event_name,
          event_time,
          event_id,
          action_source: "website",
          user_data: email ? { em: [crypto.createHash("sha256").update(email.trim().toLowerCase()).digest("hex")] } : {},
          custom_data: { currency: (currency || "GBP").toUpperCase(), value: (value_minor || 0) / 100 },
        },
      ],
    };
    await fetch(url, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(payload) });
  } catch (e) {
    console.error("Meta CAPI error", e?.message || e);
  }
}
async function fireTikTokCAPI({ event_name, event_time, email, value_minor, currency, event_id }) {
  const PIXEL_ID = process.env.TIKTOK_PIXEL_ID;
  const ACCESS_TOKEN = process.env.TIKTOK_ACCESS_TOKEN;
  if (!PIXEL_ID || !ACCESS_TOKEN) return;
  try {
    const url = "https://business-api.tiktok.com/open_api/v1.3/pixel/track/";
    const payload = {
      pixel_code: PIXEL_ID,
      event: event_name,
      timestamp: event_time,
      context: {
        ad: {},
        page: {},
        user: email ? { email: [crypto.createHash("sha256").update(email.trim().toLowerCase()).digest("hex")] } : {},
      },
      properties: { value: (value_minor || 0) / 100, currency: (currency || "GBP").toUpperCase() },
      event_id,
    };
    await fetch(url, {
      method: "POST",
      headers: { "content-type": "application/json", "access-token": ACCESS_TOKEN },
      body: JSON.stringify(payload),
    });
  } catch (e) {
    console.error("TikTok CAPI error", e?.message || e);
  }
}

// ---------- API ----------
app.get("/api/health", (_req, res) => res.json({ ok: true, updated_at: new Date().toISOString() }));

// Prices for frontend
app.get("/api/prices", async (_req, res) => {
  const map = await getPrices();
  const out = Object.fromEntries(
    Object.entries(map).map(([lookup_key, p]) => [
      lookup_key,
      {
        id: p.id,
        lookup_key,
        currency: p.currency,
        unit_amount: p.unit_amount,
        product: { id: p.product?.id, name: p.product?.name, metadata: p.product?.metadata || {} },
        metadata: p.metadata || {},
      },
    ])
  );
  res.json({ prices: out, updated_at: PRICE_CACHE_AT });
});

// Admin: force-refresh price cache
app.post("/api/prices/refresh", requireAdmin, async (_req, res) => {
  await refreshPrices();
  res.json({ ok: true, count: Object.keys(PRICE_CACHE || {}).length });
});

// --- Create checkout session ---
// Accepts EITHER:
// 1) { cart: [{ lookupKey, quantity, size? }], email?, note? }
// 2) { customer_email, shipping, line_items: [{ lookup_key, size, quantity }] }
app.post("/api/checkout", async (req, res) => {
  try {
    const body = req.body || {};

    // Normalize incoming payload to { email, note, items:[{lookup_key, size?, quantity}] }
    let email = body.email || body.customer_email || null;
    let note = body.note || null;
    let items = [];

    if (Array.isArray(body.line_items) && body.line_items.length) {
      // new checkout.html payload
      items = body.line_items.map((li) => ({
        lookup_key: li.lookup_key,
        size: li.size || null,
        quantity: Math.max(1, parseInt(li.quantity || 1, 10)),
      }));
    } else if (Array.isArray(body.cart) && body.cart.length) {
      // old payload
      items = body.cart.map((ci) => ({
        lookup_key: ci.lookupKey,
        size: ci.size || null,
        quantity: Math.max(1, parseInt(ci.quantity || 1, 10)),
      }));
    }

    if (!items.length) return res.status(400).json({ error: "Cart required" });

    const prices = await getPrices();

    // Build Stripe line_items + inventory check map + estimate subtotal (GBP minor)
    const cartMap = {};
    let estimatedSubtotal = 0;
    const stripeLineItems = items.map((ci) => {
      const p = prices[ci.lookup_key];
      if (!p) throw new Error(`Unknown price lookup_key: ${ci.lookup_key}`);
      cartMap[ci.lookup_key] = (cartMap[ci.lookup_key] || 0) + ci.quantity;
      estimatedSubtotal += (p.unit_amount || 0) * ci.quantity;
      return { price: p.id, quantity: ci.quantity };
    });

    // Optional inventory check
    const inv = await invCheckAndMaybeReserve(cartMap);
    if (!inv.ok) return res.status(400).json({ error: inv.error });

    // Shipping options (Adaptive Pricing will present in local currency)
    let shippingAmount = 399; // default £3.99
    if (FREE_SHIPPING_GBP > 0 && estimatedSubtotal >= FREE_SHIPPING_GBP) shippingAmount = 0;
    const shipping_options = [
      {
        shipping_rate_data: {
          display_name: shippingAmount === 0 ? "Free Shipping" : "Standard",
          delivery_estimate: { minimum: { unit: "business_day", value: 3 }, maximum: { unit: "business_day", value: 7 } },
          type: "fixed_amount",
          fixed_amount: { amount: shippingAmount, currency: "gbp" },
        },
      },
    ];

    // New order id + idem key
    const orderId = crypto.randomBytes(6).toString("hex");
    const created_at = new Date().toISOString();
    const idemKey = hashIdem({ items, email: email || "", note: note || "" });

    const sessionParams = {
      mode: "payment",
      line_items: stripeLineItems,
      allow_promotion_codes: true,
      shipping_address_collection: {
        allowed_countries: ["GB", "IE", "US", "CA", "AU", "NZ", "DE", "FR", "ES", "IT", "NL", "BE", "SE", "NO", "DK"],
      },
      shipping_options,
      success_url: "https://nvrbrth.store/thank-you?session_id={CHECKOUT_SESSION_ID}",
      cancel_url: "https://nvrbrth.store/basket",
      customer_email: email || undefined,
      automatic_payment_methods: { enabled: true },
      phone_number_collection: { enabled: true },
      client_reference_id: orderId,
      metadata: { order_id: orderId, note: note ? String(note).slice(0, 500) : "" },
    };

    const session = await stripe.checkout.sessions.create(sessionParams, { idempotencyKey: idemKey });

    // Persist pending order snapshot (verbose items)
    const itemsVerbose = items.map((ci) => {
      const p = prices[ci.lookup_key];
      return {
        lookup_key: ci.lookup_key,
        name: p.product?.name || ci.lookup_key,
        size: ci.size || null,
        quantity: ci.quantity,
        unit_amount: p.unit_amount,
      };
    });
    await dbWriteSnapshot({
      id: orderId,
      created_at,
      status: "pending",
      email: email || null,
      note: note || null,
      stripe_session_id: session.id,
      items: itemsVerbose,
      pricing: { currency: "gbp", subtotal: null, shipping_amount: null, tax_amount: null, total: null },
    });

    res.json({ url: session.url, id: session.id });
  } catch (e) {
    console.error("Checkout error:", e?.message || e);
    res.status(400).json({ error: e?.message || "Checkout failed" });
  }
});

// Thank-you page helper
app.get("/api/order/by-session/:sessionId", async (req, res) => {
  try {
    const order = await dbGetOrderBySessionId(req.params.sessionId);
    if (!order) return res.status(404).json({ error: "Not found" });
    res.json(order);
  } catch (e) {
    res.status(500).json({ error: "Lookup failed" });
  }
});

// ---------- Admin ops ----------
app.get("/api/orders", requireAdmin, async (_req, res) => {
  try {
    const all = await fileReadAll();
    res.json(all.sort((a, b) => (b.created_at || "").localeCompare(a.created_at || "")));
  } catch (e) {
    res.status(500).json({ error: "Failed to list orders" });
  }
});

app.get("/api/orders.csv", requireAdmin, async (_req, res) => {
  try {
    const all = await fileReadAll();
    const cols = ["id","status","created_at","paid_at","email","total_minor","currency","stripe_session_id"];
    const header = cols.join(",") + "\n";
    const rows = all.map(o =>
      [
        o.id,
        o.status || "",
        o.created_at || "",
        o.paid_at || "",
        (o.email || "").replace(/,/g, " "),
        o.pricing?.total ?? "",
        (o.pricing?.currency || "gbp").toUpperCase(),
        o.stripe_session_id || ""
      ].join(",")
    ).join("\n");
    res.setHeader("content-type","text/csv");
    res.send(header + rows + "\n");
  } catch (e) {
    res.status(500).json({ error: "Export failed" });
  }
});

// Mark shipped + send email
// body: { carrier?, tracking?, tracking_url? }
app.post("/api/orders/:id/ship", requireAdmin, async (req, res) => {
  try {
    const order = await dbGetOrderById(req.params.id);
    if (!order) return res.status(404).json({ error: "Not found" });
    const shipped = {
      when: new Date().toISOString(),
      carrier: req.body?.carrier || null,
      tracking: req.body?.tracking || null,
      tracking_url: req.body?.tracking_url || null,
    };
    const updated = { ...order, status: "shipped", shipped };
    await dbWriteSnapshot(updated);
    // Email customer
    const toEmail = order.email || order.stripe_details?.customer_details?.email || null;
    if (toEmail && resend) {
      const html = renderOrderEmail({
        id: order.id,
        created_at: order.created_at,
        items: order.items,
        note: order.note,
        pricing: order.pricing || { currency: "gbp", subtotal: 0, shipping_amount: 0, tax_amount: 0, total: 0 },
        presentment: null,
        shipped,
      });
      await sendEmail(toEmail, `NVRBRTH — Order ${order.id} shipped`, html);
    }
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: "Ship update failed" });
  }
});

// Resend confirmation
app.post("/api/orders/:id/resend", requireAdmin, async (req, res) => {
  try {
    const order = await dbGetOrderById(req.params.id);
    if (!order) return res.status(404).json({ error: "Not found" });
    const toEmail = order.email || order.stripe_details?.customer_details?.email || null;
    if (!toEmail || !resend) return res.status(400).json({ error: "No email available or Resend not configured" });
    const html = renderOrderEmail({
      id: order.id,
      created_at: order.created_at,
      items: order.items,
      note: order.note,
      pricing: order.pricing || { currency: "gbp", subtotal: 0, shipping_amount: 0, tax_amount: 0, total: 0 },
      presentment: order.stripe_details?.presentment_details
        ? {
            currency: order.stripe_details.presentment_details.presentment_currency,
            amount: order.stripe_details.presentment_details.presentment_amount,
          }
        : null,
    });
    await sendEmail(toEmail, `NVRBRTH — Order ${order.id} confirmed`, html);
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: "Resend failed" });
  }
});

// GDPR-ish redact
app.delete("/api/orders/:id", requireAdmin, async (req, res) => {
  try {
    const order = await dbGetOrderById(req.params.id);
    if (!order) return res.status(404).json({ error: "Not found" });
    const redacted = { ...order, email: null, stripe_details: null, redacted_at: new Date().toISOString() };
    await dbWriteSnapshot(redacted);
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: "Redact failed" });
  }
});

// ---------- Stripe webhook ----------
async function handleStripeWebhook(req, res) {
  let event;
  const sig = req.headers["stripe-signature"];
  try {
    if (process.env.STRIPE_WEBHOOK_SECRET) {
      event = stripe.webhooks.constructEvent(req.body, sig, process.env.STRIPE_WEBHOOK_SECRET);
    } else {
      const payload = req.body?.toString("utf8") || "{}";
      event = JSON.parse(payload);
    }
  } catch (err) {
    console.error("Webhook signature/parse error:", err?.message || err);
    return res.status(400).send(`Webhook Error: ${err.message}`);
  }

  try {
    switch (event.type) {
      case "checkout.session.completed": {
        const session = event.data.object;
        const full = await stripe.checkout.sessions.retrieve(session.id, {
          expand: ["customer_details", "shipping_details", "line_items.data.price.product", "total_details"],
        });

        const subtotal = full.amount_subtotal || 0;
        const total = full.amount_total || 0;
        const shipping_amount = (full.shipping_cost && full.shipping_cost.amount_total) || 0;
        const tax_amount = (full.total_details && full.total_details.amount_tax) || 0;

        const presentment =
          full.presentment_details && full.presentment_details.presentment_currency
            ? {
                currency: full.presentment_details.presentment_currency,
                amount: full.presentment_details.presentment_amount,
              }
            : null;

        const order = (await dbGetOrderBySessionId(session.id)) || {
          id: full.client_reference_id || crypto.randomBytes(6).toString("hex"),
          created_at: new Date().toISOString(),
        };

        // Items from Stripe (authoritative)
        let items = [];
        if (full.line_items?.data?.length) {
          items = full.line_items.data.map((li) => ({
            lookup_key: li.price?.lookup_key || null,
            name: li.price?.product?.name || li.description || "Item",
            size: null,
            quantity: li.quantity || 1,
            unit_amount: li.price?.unit_amount ?? li.amount_total ?? 0,
          }));
        }

        const updated = {
          ...order,
          stripe_session_id: session.id,
          status: "paid",
          paid_at: new Date().toISOString(),
          email: full.customer_details?.email || order.email || null,
          items: items.length ? items : order.items || [],
          pricing: { currency: full.currency || "gbp", subtotal, shipping_amount, tax_amount, total },
          stripe_details: {
            customer_details: full.customer_details || null,
            shipping_details: full.shipping_details || null,
            presentment_details: full.presentment_details || null,
          },
        };
        await dbWriteSnapshot(updated);

        // Inventory decrement (best-effort)
        if (items.length) await invDecrement(items);

        // Fire pixels (best-effort)
        const event_id = session.id;
        await Promise.all([
          fireMetaCAPI({
            event_name: "Purchase",
            event_time: Math.floor(Date.now() / 1000),
            email: updated.email,
            value_minor: total,
            currency: updated.pricing.currency,
            event_id,
          }),
          fireTikTokCAPI({
            event_name: "CompletePayment",
            event_time: Math.floor(Date.now() / 1000),
            email: updated.email,
            value_minor: total,
            currency: updated.pricing.currency,
            event_id,
          }),
        ]);

        // Email confirmation
        if (updated.email && resend) {
          const html = renderOrderEmail({
            id: updated.id,
            created_at: updated.created_at,
            items: updated.items,
            note: updated.note,
            pricing: updated.pricing,
            presentment,
          });
          await sendEmail(updated.email, `NVRBRTH — Order ${updated.id} confirmed`, html);
        }

        break;
      }

      case "checkout.session.expired": {
        // Optionally send “you left this behind” if we have email + cart snapshot
        const session = event.data.object;
        const order = await dbGetOrderBySessionId(session.id);
        if (order && order.email && resend) {
          const token = crypto.randomBytes(12).toString("hex");
          await dbWriteSnapshot({ ...order, recovery_token: token, recovery_created_at: new Date().toISOString() });
          const html = `
            <div style="font-family:system-ui">You left something behind at NVRBRTH.
            <p><a href="https://nvrbrth.store/recover?token=${token}">Resume your order</a></p></div>`;
          await sendEmail(order.email, "Still want this? Complete your NVRBRTH order", html);
        }
        break;
      }

      case "charge.refunded":
      case "refund.succeeded": {
        // Mark refunded & (optionally) restock
        const charge = event.data.object;
        const paymentIntentId = charge.payment_intent || charge.payment || null;
        if (paymentIntentId) {
          const all = await fileReadAll();
          const latestPaid = [...all].reverse().find((o) => o.status === "paid" && o.pricing?.total);
          if (latestPaid) {
            const updated = { ...latestPaid, status: "refunded", refunded_at: new Date().toISOString() };
            await dbWriteSnapshot(updated);
            if (latestPaid.items?.length) await invIncrement(latestPaid.items);
          }
        }
        break;
      }

      case "charge.dispute.created": {
        const all = await fileReadAll();
        const latestPaid = [...all].reverse().find((o) => o.status === "paid");
        if (latestPaid) {
          await dbWriteSnapshot({ ...latestPaid, status: "disputed", disputed_at: new Date().toISOString() });
        }
        break;
      }

      default:
        // no-op
        break;
    }

    res.json({ received: true });
  } catch (e) {
    console.error("Webhook handler error:", e?.message || e);
    res.status(500).json({ error: "Webhook processing failed" });
  }
}

// ---------- Boot ----------
app.listen(PORT, () => console.log(`🚀 NVRBRTH backend ready on ${PORT}`));
