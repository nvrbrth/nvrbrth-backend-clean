const express = require('express');
const cors = require('cors');
const fs = require('fs');
const bodyParser = require('body-parser');
const stripe = require('stripe')('sk_test_51Rn2f1RvW9dwX7RvfVL9VcVJpy1WSUwON0xdKhNMRUTZrekQP7U2OfrtxEwC4wY1Fq9u8tZAnoeLcBKP1Eab2sbe00lb73vJGT');

const app = express();
const PORT = process.env.PORT || 5000;

app.use(cors());
app.use(bodyParser.json());

// ✅ Test route
app.get('/', (req, res) => {
  res.send('✅ NVRBRTH backend is alive and kicking');
});

// ✅ Checkout route (saves order info)
app.post('/api/checkout', (req, res) => {
  const orderData = req.body;

  if (!orderData) {
    console.error('❌ No order data received.');
    return res.status(400).json({ success: false, message: 'No data' });
  }

  try {
    fs.appendFileSync('orders.json', JSON.stringify(orderData) + '\n');
    console.log('✅ Order saved:', orderData);
    res.status(200).json({ success: true });
  } catch (err) {
    console.error('❌ Failed to save order:', err);
    res.status(500).json({ success: false, message: 'Failed to save order' });
  }
});

// ✅ Stripe Checkout session route
app.post('/api/create-checkout-session', async (req, res) => {
  try {
    const session = await stripe.checkout.sessions.create({
      payment_method_types: ['card'],
      line_items: [
        {
          price_data: {
            currency: 'gbp',
            product_data: {
              name: 'HOST_001 Tee',
            },
            unit_amount: 3500, // £35.00
          },
          quantity: 1,
        },
      ],
      mode: 'payment',
      success_url: 'https://nvrbrth.store/thankyou.html',
      cancel_url: 'https://nvrbrth.store/checkout.html',
    });

    res.json({ url: session.url });
  } catch (error) {
    console.error('❌ Stripe error:', error);
    res.status(500).json({ error: 'Stripe session creation failed' });
  }
});

// 🚀 Start the server
app.listen(PORT, () => {
  console.log(`🚀 Server running at http://localhost:${PORT}`);
});
