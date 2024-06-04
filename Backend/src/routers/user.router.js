import express, { Router } from "express";
import { UserModel } from "../models/user.model.js";
import bcrypt from 'bcrypt';
import session from "express-session";
import passport from "passport";
import { Strategy as LocalStrategy } from 'passport-local';
import bodyParser from "body-parser";
import { z } from "zod";

//for otp varification
import nodemailer from "nodemailer";
import twilio from "twilio";
import crypto from "crypto";

const router = Router();
const saltRounds = parseInt(process.env.SALTROUND) || 10; // Provide a default value if SALTROUND is not set
const app = express();
const otps = {}; // Store OTPs temporarily in memory

// Utility function to generate a 6-digit OTP
const generateOTP = () => crypto.randomInt(100000, 999999).toString();

// Your Twilio credentials
const accountSid = process.env.accountSid;
const authToken = process.env.authToken;
const twilioClient = twilio(accountSid, authToken);

// Your email transport configuration
const transporter = nodemailer.createTransport({
  service: 'Gmail',
  auth: {
    user: process.env.EMAIL,
    pass: process.env.PASSWORD
  }
});

const otp=(req,res,next)=>{
  const email = req.body.email;
  const phone="+91"+req.body.phoneNos;
  const otp = generateOTP();

  // Store OTP with a timestamp
  otps[email] = { otp, timestamp: Date.now() };
  otps[phone] = { otp, timestamp: Date.now() };

  // Send OTP via email
  transporter.sendMail({
    from: process.env.EMAIL,
    to: email,
    subject: 'Your OTP Code',
    text: `<!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>OTP Verification</title>
    </head>
    <body style="font-family: Arial, sans-serif; text-align: center;">
        <table style="width: 100%; height: 100vh; border-collapse: collapse;">
            <tr>
                <td style="vertical-align: middle;">
                    <div class="container" style="background-color: white; padding: 2em; box-shadow: 0 0 10px rgba(0, 0, 0, 0.1); border-radius: 8px; text-align: center;">
                        <table style="margin: 0 auto;">
                            <tr>
                                <td>
                                    <img src="https://uploads-ssl.webflow.com/63f672a2d2935abea90a1d67/665f7567ec60ffc89d1a7db7_bccl.jpg" alt="BCCL Logo" class="logo" style="max-height: 50px; margin: 0 1em;">
                                </td>
                               
                            </tr>
                        </table>
                        <h1 style="margin: 0.5em 0; color: #333;">OTP Verification</h1>
                        <p style="margin: 1em 0; color: #666;">Please find your otp below.</p>
                        <h2 style="margin: 0.5em 0; color: #333;">${otp}</p>
                    </div>
                </td>
            </tr>
        </table>
    </body>
    </html>
    `
  });

  // Send OTP via SMS
  twilioClient.messages.create({
    body: `Your OTP code is ${otp}`,
    from: process.env.PHONE, // Your Twilio phone number
    to: phone
  });

  next();
}

const verifyOtp=(req,res,next)=>{
  const { identifier, otp } = req.body;
  const storedOtpData = otps[identifier];

  if (storedOtpData && storedOtpData.otp === otp) {
    const currentTime = Date.now();
    const otpAge = currentTime - storedOtpData.timestamp;

    if (otpAge <= 5 * 60 * 1000) { // OTP is valid for 5 minutes
      res.send('OTP verified successfully.');
    } else {
      res.status(400).send('OTP expired.');
    }
  } else {
    res.status(400).send('Invalid OTP.');
  }
}

// Middleware setup
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());
router.use(session({
    secret: 'TOPSECRET', // replace with your actual secret key
    resave: false,
    saveUninitialized: false
  }));
  router.use(passport.initialize());
  router.use(passport.session());

// zod signup schema
const signupSchema = z.object({
  username: z.string(),
  email: z.string().email(),
  password: z.string().min(8, "Password must be at least 8 characters long")
    .max(64, "Password must not exceed 64 characters")
    .regex(/[a-z]/, "Password must contain at least one lowercase letter")
    .regex(/[A-Z]/, "Password must contain at least one uppercase letter")
    .regex(/[0-9]/, "Password must contain at least one digit")
    .regex(/[^a-zA-Z0-9]/, "Password must contain at least one special character"),
  organizationName: z.string().optional(),
  phoneNo: z.string().regex(/^\d{10}$/, "Phone number must be exactly 10 digits")
});

// zod login schema
const loginSchema = z.object({
  email: z.string().email(),
  password: z.string().min(8, "Password must be at least 8 characters long")
    .max(64, "Password must not exceed 64 characters")
    .regex(/[a-z]/, "Password must contain at least one lowercase letter")
    .regex(/[A-Z]/, "Password must contain at least one uppercase letter")
    .regex(/[0-9]/, "Password must contain at least one digit")
    .regex(/[^a-zA-Z0-9]/, "Password must contain at least one special character"),
});

// Signup route
router.post("/signup", async (req, res) => {
  const { username, email, password, organizationName, phoneNo } = req.body;
  const userData = { username, email, password, organizationName, phoneNo };
  const responseCheck = signupSchema.safeParse(userData);
  if (!responseCheck.success) {
    return res.status(400).json({ error: responseCheck.error });
  }

  try {
    const existingUser = await UserModel.findOne({ email });
    if (existingUser) {
      return res.status(409).json({ message: "User already exists" });
    } else {
      const hashedPassword = await bcrypt.hash(password, saltRounds);
      const newUser = new UserModel({ username, email, password: hashedPassword, organizationName, phoneNo });
      await newUser.save();
      return res.status(201).json({ message: "User created successfully" });
    }
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
});

// Input validation middleware for login
const inputValidate = (req, res, next) => {
  const { email, password } = req.body;
  const loginUser = { email, password };
  const inputValidate = loginSchema.safeParse(loginUser);
  if (!inputValidate.success) {
    return res.status(400).json({ msg: inputValidate.error });
  } else {
    next();
  }
};

// Passport Local Strategy
passport.use(
  new LocalStrategy({ usernameField: 'email' }, async (email, password, done) => {
    try {
      const user = await UserModel.findOne({ email });
      if (!user) {
        return done(null, false, { message: "Incorrect email." });
      }

      const isPasswordValid = await bcrypt.compare(password, user.password);
      if (!isPasswordValid) {
        return done(null, false, { message: "Incorrect password." });
      }

      return done(null, user);
    } catch (err) {
      return done(err);
    }
  })
);

// Login route
router.post('/login', inputValidate, (req, res, next) => {
  passport.authenticate('local', (err, user, info) => {
    if (err) {
      return next(err);
    }
    if (!user) {
      return res.status(401).json({ message: info.message });
    }
    req.logIn(user, (err) => {
      if (err) {
        return next(err);
      }
      return res.status(200).json({ message: 'Login successful' });
    });
  })(req, res, next);
});

// Passport serialize and deserialize
passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
  try {
    const user = await UserModel.findById(id);
    done(null, user);
  } catch (err) {
    done(err);
  }
});

app.use('/api', router);

// Define a catch-all route at the end
app.use((req, res, next) => {
  res.status(404).json({ message: 'Route not found' });
});

export default router;
