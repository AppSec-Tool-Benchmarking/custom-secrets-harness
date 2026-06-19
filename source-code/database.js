/**
 * Database configuration module.
 *
 * TEST HARNESS: This file intentionally contains hardcoded database credentials
 * for secrets detection tool benchmarking. All connection strings are FAKE.
 * See secrets-manifest.csv for ground truth.
 */

const { Pool } = require('pg');
const mysql = require('mysql2');
const mongoose = require('mongoose');
const redis = require('redis');

// --- MANIFEST ID 7 ---
// PostgreSQL connection string (real format: postgresql://user:pass@host:port/db)
const POSTGRES_URL = "postgresql://appuser:Sup3rS3cr3tP@ssw0rd!@db.internal.example.com:5432/production_db";

// --- MANIFEST ID 8 ---
// PostgreSQL with SSL
const POSTGRES_URL_SSL = "postgres://admin:xK9#mP2$vL8nQ4rT@rds.amazonaws.com:5432/appdb?sslmode=require";

// --- MANIFEST ID 9 ---
// MySQL connection string
const MYSQL_URL = "mysql://root:MyS3cretDbP@ss123@mysql.internal.example.com:3306/shopdb";

// --- MANIFEST ID 10 ---
// MongoDB connection string (Atlas format with credentials)
const MONGODB_URI = "mongodb+srv://dbAdmin:P@ssw0rd!MongoDB123@cluster0.abcde.mongodb.net/production?retryWrites=true&w=majority";

// --- MANIFEST ID 11 ---
// MongoDB local with auth
const MONGODB_LOCAL = "mongodb://mongouser:m0ng0S3cret!@localhost:27017/appdb?authSource=admin";

// --- MANIFEST ID 12 ---
// Redis with password
const REDIS_URL = "redis://:R3d1sS3cr3tP@ss!@redis.internal.example.com:6379/0";

// --- MANIFEST ID 13 ---
// Redis with username and password (Redis 6+ ACL)
const REDIS_ACL_URL = "redis://redisuser:Acl$P@ssw0rd99@cache.example.com:6380/1";

// --- MANIFEST ID 14 ---
// Hardcoded database password used separately
const DB_PASSWORD = "Sup3rS3cr3tP@ssw0rd!";
const DB_USER = "appuser";
const DB_HOST = "db.internal.example.com";
const DB_PORT = 5432;
const DB_NAME = "production_db";


// PostgreSQL pool using individual config
const pgPool = new Pool({
    host: DB_HOST,
    port: DB_PORT,
    database: DB_NAME,
    user: DB_USER,
    password: DB_PASSWORD,
    ssl: { rejectUnauthorized: false }
});

// MySQL connection
const mysqlConnection = mysql.createConnection(MYSQL_URL);

// MongoDB connection
mongoose.connect(MONGODB_URI);

// Redis client
const redisClient = redis.createClient({ url: REDIS_URL });

module.exports = { pgPool, mysqlConnection, redisClient };
