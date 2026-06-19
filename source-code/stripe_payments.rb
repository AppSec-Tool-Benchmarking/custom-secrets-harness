# stripe_payments.rb
#
# TEST HARNESS: This file intentionally contains hardcoded Stripe credentials
# for secrets detection tool benchmarking. All keys are FAKE.
# See secrets-manifest.csv for ground truth.

require 'stripe'
require 'sendgrid-ruby'
require 'twilio-ruby'

# --- MANIFEST ID 24 ---
# Stripe Secret Key — LIVE (format: sk_live_[A-Za-z0-9]{99})
STRIPE_SECRET_KEY_LIVE = "sk_live_51FakeStripeSecretKeyLiveABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnop"

# --- MANIFEST ID 25 ---
# Stripe Secret Key — TEST (format: sk_test_[A-Za-z0-9]{99})
STRIPE_SECRET_KEY_TEST = "sk_test_51FakeStripeSecretKeyTestABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnop"

# --- MANIFEST ID 26 ---
# Stripe Publishable Key — LIVE (format: pk_live_[A-Za-z0-9]{99})
STRIPE_PUBLISHABLE_KEY_LIVE = "pk_live_51FakeStripePublishableKeyLiveABCDEFGHIJKLMNOPQRSTUVWXYZ01234567890abcdef"

# --- MANIFEST ID 27 ---
# Stripe Publishable Key — TEST
STRIPE_PUBLISHABLE_KEY_TEST = "pk_test_51FakeStripePublishableKeyTestABCDEFGHIJKLMNOPQRSTUVWXYZ01234567890abcdef"

# --- MANIFEST ID 28 ---
# Stripe Webhook Signing Secret (format: whsec_[A-Za-z0-9]{32,})
STRIPE_WEBHOOK_SECRET = "whsec_FakeStripeWebhookSigningSecret1234ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef"

# --- MANIFEST ID 29 ---
# SendGrid API Key (format: SG.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43})
SENDGRID_API_KEY = "SG.FakeSendGridApiKey12345678.FakeSendGridSecondSegmentABCDEFGHIJKLMNOPQRS"

# --- MANIFEST ID 30 ---
# Twilio Account SID (format: AC[a-z0-9]{32})
TWILIO_ACCOUNT_SID = "ACfake1234567890abcdef1234567890ab"

# --- MANIFEST ID 31 ---
# Twilio Auth Token (format: [a-z0-9]{32})
TWILIO_AUTH_TOKEN = "fake1234567890abcdef1234567890ab"

# --- MANIFEST ID 32 ---
# Mailgun API Key (format: key-[a-z0-9]{32})
MAILGUN_API_KEY = "key-fake1234567890abcdef12345678901234"


Stripe.api_key = STRIPE_SECRET_KEY_LIVE

def charge_card(amount, currency, source, description)
  Stripe::Charge.create(
    amount: amount,
    currency: currency,
    source: source,
    description: description
  )
end

def send_receipt(to_email, subject, body)
  sg = SendGrid::API.new(api_key: SENDGRID_API_KEY)
  mail = SendGrid::Mail.new
  mail.from = SendGrid::Email.new(email: 'no-reply@example.com')
  mail.subject = subject
  personalization = SendGrid::Personalization.new
  personalization.add_to(SendGrid::Email.new(email: to_email))
  mail.add_personalization(personalization)
  mail.add_content(SendGrid::Content.new(type: 'text/plain', value: body))
  sg.client.mail._('send').post(request_body: mail.to_json)
end

def send_sms(to_number, message)
  client = Twilio::REST::Client.new(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN)
  client.messages.create(
    from: '+15005550006',
    to: to_number,
    body: message
  )
end
