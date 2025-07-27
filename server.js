const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const fs = require('fs');
const stripe = require('stripe')('sk_test_51Rn2f1RvW9dwX7RvfVL9VcVJpy1WSUwON0xdKhNMRUTZrekQP7U2OfrtxEwC4wY1Fq9u8tZAnoeLcBKP1Eab2sbe00lb73vJGT'); // 

const app = express();
const PORT = 5000;

app.use(cors());
app.use(bodyParser.json());

// 🔥 Save order endpoint
app.post('/api/checkout', (req, res) => {
  const orderData = req.body;

  try {
    // Append each order as a line of JSON
    fs.appendFileSync('orders.json', JSON.stringify(orderData) + '\n');
    console.log('✅ Order received:', orderData);
    res.json({ success: true, message: 'Order saved successfully.' });
  } catch (error) {
    console.error('❌ Error saving order:', error);
    res.status(500).json({ success: false, message: 'Failed to save order.' });
  }
});

// ✅ New: Stripe Checkout session creation
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
      cancel_url: 'https://nvrbrth.store/products.html',
    });

    res.json({ url: session.url });
  } catch (error) {
    console.error('Stripe error:', error);
    res.status(500).json({ error: 'Stripe session creation failed' });
  }
});

// ✅ Root route for testing server is alive
app.get('/', (req, res) => {
  res.send('✅ NVRBRTH backend is alive and kicking');
});

// 🔌 Start server
app.listen(PORT, () => {
  console.log(`🚀 NVRBRTH backend running at http://localhost:${PORT}`);
});
