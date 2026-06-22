const express = require("express");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const nodemailer = require("nodemailer");
const rateLimit = require("express-rate-limit");

const db = require("./db");

const app = express();

app.use(express.json());
app.use(express.static("public"));

const SECRET = "secret123";

/* ---------------- EMAIL ---------------- */

const transporter = nodemailer.createTransport({
    service: "gmail",
    auth: {
        user: "pratyushkumar5630@gmail.com",
        pass: "qjkjnjxabtzfsrez"
    }
});

/* ---------------- MEMORY STORAGE ---------------- */

let otpCooldown = {};
let blacklistedTokens = [];

/* ---------------- RATE LIMITERS ---------------- */

const loginLimiter = rateLimit({
    windowMs: 60 * 1000,
    max: 5,
    message: { message: "Too many login attempts. Try again later." }
});

const otpLimiter = rateLimit({
    windowMs: 60 * 1000,
    max: 5,
    message: { message: "Too many OTP requests. Slow down." }
});

/* ---------------- APPLY LIMITERS ---------------- */

app.use("/login", loginLimiter);
app.use("/send-otp", otpLimiter);
app.use("/resend-otp", otpLimiter);

/* ---------------- REGISTER ---------------- */

app.post("/register", (req, res) => {

    const { email, password } = req.body;

    const hashedPassword = bcrypt.hashSync(password, 10);

    const sql = "INSERT INTO users (email, password) VALUES (?, ?)";

    db.query(sql, [email, hashedPassword], (err) => {

        if (err) {
            if (err.code === "ER_DUP_ENTRY") {
                return res.status(400).json({
                    message: "Email already registered"
                });
            }

            return res.status(500).json({
                message: "Database error"
            });
        }

        res.json({ message: "User registered successfully" });

    });
});

/* ---------------- SEND OTP ---------------- */

app.post("/send-otp", (req, res) => {

    const { email } = req.body;

    const otp = Math.floor(100000 + Math.random() * 900000);

    const sql =
        "INSERT INTO otp_codes (email, otp, created_at) VALUES (?, ?, NOW())";

    db.query(sql, [email, otp], (err) => {

        if (err) {
            return res.status(500).json({
                message: "Failed to send OTP"
            });
        }

        transporter.sendMail({
            from: "your_email@gmail.com",
            to: email,
            subject: "OTP Verification",
            text: `Your OTP is ${otp} (valid for 2 minutes)`
        });

        res.json({ message: "OTP sent successfully" });

    });
});

/* ---------------- RESEND OTP ---------------- */

app.post("/resend-otp", (req, res) => {

    const { email } = req.body;

    const now = Date.now();

    if (otpCooldown[email] && now - otpCooldown[email] < 30000) {
        return res.status(429).json({
            message: "Please wait before requesting another OTP"
        });
    }

    const otp = Math.floor(100000 + Math.random() * 900000);

    const sql =
        "INSERT INTO otp_codes (email, otp, created_at) VALUES (?, ?, NOW())";

    db.query(sql, [email, otp], (err) => {

        if (err) {
            return res.status(500).json({
                message: "Failed to resend OTP"
            });
        }

        otpCooldown[email] = now;

        transporter.sendMail({
            from: "your_email@gmail.com",
            to: email,
            subject: "Resend OTP",
            text: `Your new OTP is ${otp} (valid for 2 minutes)`
        });

        res.json({ message: "OTP resent successfully" });

    });
});

/* ---------------- VERIFY OTP ---------------- */

app.post("/verify-otp", (req, res) => {

    const { email, otp } = req.body;

    const sql = `
        SELECT * FROM otp_codes 
        WHERE email = ? 
        AND otp = ? 
        AND created_at >= NOW() - INTERVAL 2 MINUTE
    `;

    db.query(sql, [email, otp], (err, results) => {

        if (err) {
            return res.status(500).json({
                message: "Server error"
            });
        }

        if (results.length === 0) {
            return res.status(401).json({
                message: "OTP expired or invalid"
            });
        }

        const token = jwt.sign(
            { email },
            SECRET,
            { expiresIn: "1h" }
        );

        res.json({ token });

    });
});

/* ---------------- LOGIN ---------------- */

app.post("/login", (req, res) => {

    const { email, password } = req.body;

    const sql = "SELECT * FROM users WHERE email = ?";

    db.query(sql, [email], (err, results) => {

        if (err) {
            return res.status(500).json({
                message: "Server error"
            });
        }

        if (results.length === 0) {
            return res.status(401).json({
                message: "Invalid credentials"
            });
        }

        const user = results[0];

        const isMatch = bcrypt.compareSync(password, user.password);

        if (!isMatch) {
            return res.status(401).json({
                message: "Invalid credentials"
            });
        }

        const token = jwt.sign(
            { id: user.id },
            SECRET,
            { expiresIn: "1h" }
        );

        res.json({ token });

    });
});

/* ---------------- DASHBOARD ---------------- */

app.get("/dashboard", (req, res) => {

    const authHeader = req.headers.authorization;

    if (!authHeader) {
        return res.status(401).json({
            message: "No token"
        });
    }

    const token = authHeader.split(" ")[1];

    if (blacklistedTokens.includes(token)) {
        return res.status(401).json({
            message: "Token expired (logged out)"
        });
    }

    try {
        const decoded = jwt.verify(token, SECRET);

        res.json({
            message: "Welcome to dashboard",
            userId: decoded.id
        });

    } catch (err) {
        return res.status(401).json({
            message: "Invalid token"
        });
    }
});

/* ---------------- LOGOUT ---------------- */

app.post("/logout", (req, res) => {

    const token = req.headers.authorization?.split(" ")[1];

    if (token) {
        blacklistedTokens.push(token);
    }

    res.json({ message: "Logged out successfully" });

});

/* ---------------- CLEANUP OTP ---------------- */

setInterval(() => {

    const sql =
        "DELETE FROM otp_codes WHERE created_at < NOW() - INTERVAL 10 MINUTE";

    db.query(sql, (err) => {
        if (err) console.log(err);
        else console.log("Expired OTPs cleaned");
    });

}, 5 * 60 * 1000);

/* ---------------- START SERVER ---------------- */

app.listen(5000, () => {
    console.log("Server running on port 5000");
});