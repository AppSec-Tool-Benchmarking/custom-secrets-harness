/**
 * Authentication module.
 *
 * TEST HARNESS: This file intentionally contains hardcoded authentication
 * secrets for secrets detection tool benchmarking. All tokens are FAKE.
 * See secrets-manifest.csv for ground truth.
 */

import jwt from 'jsonwebtoken';

// --- MANIFEST ID 15 ---
// JWT signing secret (short, high-entropy string — common developer mistake)
const JWT_SECRET = "s3cr3t!JWT$1gn1ng#K3y_d0_n0t_sh@r3";

// --- MANIFEST ID 16 ---
// JWT signing secret variant (longer)
const JWT_REFRESH_SECRET = "RefreshT0ken$ecretKeyV3ryL0ngAndC0mplex!!2024_prod_refresh_key_xyz";

// --- MANIFEST ID 17 ---
// JWT signing secret as bytes (common in Python/Go ports)
const JWT_SECRET_BYTES = Buffer.from("my_super_secret_jwt_signing_key_do_not_expose_2024").toString();

// --- MANIFEST ID 18 ---
// GitHub Personal Access Token (classic format: ghp_[A-Za-z0-9]{36})
const GITHUB_TOKEN = "ghp_FakeClassicPatToken1234567890abcdefABCD";

// --- MANIFEST ID 19 ---
// GitHub Fine-grained PAT (format: github_pat_[A-Za-z0-9_]{82})
const GITHUB_FINE_GRAINED_PAT = "github_pat_11ABCDEFG0FakeFinegrainedToken123456_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwx";

// --- MANIFEST ID 20 ---
// GitLab Personal Access Token (format: glpat-[A-Za-z0-9\-_]{20})
const GITLAB_TOKEN = "glpat-FakeGitLabPAToken1234";

// --- MANIFEST ID 21 ---
// NPM auth token (format: npm_[A-Za-z0-9]{36})
const NPM_AUTH_TOKEN = "npm_FakeNpmAuthToken1234567890abcdefABCDEFGH";

// --- MANIFEST ID 22 ---
// Slack Bot Token (format: xoxb-[0-9]{11}-[0-9]{11}-[A-Za-z0-9]{24})
const SLACK_BOT_TOKEN = "xoxb-12345678901-12345678901-FakeSlackBotTokenABCDEF";

// --- MANIFEST ID 23 ---
// Slack Webhook URL
const SLACK_WEBHOOK_URL = "https://hooks.slack.com/services/T00000000/B00000000/FakeSlackWebhookTokenXYZ123";


export function generateToken(userId: string): string {
    return jwt.sign({ sub: userId }, JWT_SECRET, { expiresIn: '1h' });
}

export function generateRefreshToken(userId: string): string {
    return jwt.sign({ sub: userId, type: 'refresh' }, JWT_REFRESH_SECRET, { expiresIn: '30d' });
}

export function verifyToken(token: string): jwt.JwtPayload | string {
    return jwt.verify(token, JWT_SECRET);
}

async function notifySlack(message: string): Promise<void> {
    await fetch(SLACK_WEBHOOK_URL, {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${SLACK_BOT_TOKEN}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({ text: message })
    });
}
