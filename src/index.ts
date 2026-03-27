import express, { Request, Response, NextFunction } from 'express';
import mongoose from 'mongoose';
import session from 'express-session';
import passport from 'passport';
import { Strategy as GoogleStrategy } from 'passport-google-oauth20';
import { Strategy as LocalStrategy } from 'passport-local';
import MongoStore from 'connect-mongo';
import dotenv from 'dotenv';
import cors from 'cors';
import bcrypt from 'bcrypt';
import nodemailer from 'nodemailer';

dotenv.config();

const app = express();

// --- 1. SETTINGS & MIDDLEWARES ---
const PORT = process.env.PORT || 5000;
// Frontend URL se last wala '/' hata dena agar .env mein ho
const FRONTEND_URL = process.env.FRONTEND_URL
  ? process.env.FRONTEND_URL.replace(/\/$/, '')
  : 'http://localhost:3000';

app.use(express.json());

// Trust Proxy: Railway/HTTPS ke liye bahut zaroori hai
app.set('trust proxy', 1);

app.use(
  cors({
    origin: [FRONTEND_URL, 'http://localhost:3000', 'http://192.168.1.4:3000'],
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization'],
  }),
);

// --- 2. MONGODB CONNECTION ---
mongoose
  .connect(process.env.MONGO_URI!)
  .then(() => console.log('✅ MongoDB Connected'))
  .catch((err) => console.error('❌ MongoDB Error:', err));

// --- 3. USER MODEL ---
const userSchema = new mongoose.Schema({
  displayName: { type: String, required: true },
  email: { type: String, unique: true, required: true },
  password: { type: String },
  googleId: { type: String },
  isVerified: { type: Boolean, default: false },
  otp: { type: String },
  otpExpires: { type: Date },
  image: { type: String },
});
const User = mongoose.model('User', userSchema);

// --- 4. SESSION CONFIG ---
app.use(
  session({
    secret: process.env.SESSION_SECRET!,
    resave: false,
    saveUninitialized: false,
    store: MongoStore.create({ mongoUrl: process.env.MONGO_URI! }),
    cookie: {
      maxAge: 24 * 60 * 60 * 1000,
      // Production mein HTTPS zaroori hai
      secure: process.env.NODE_ENV === 'production',
      sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax',
      httpOnly: true,
    },
  }),
);

app.use(passport.initialize());
app.use(passport.session());

// --- 5. PASSPORT STRATEGIES ---

// GOOGLE STRATEGY
passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID!,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET!,
      callbackURL: process.env.GOOGLE_CALLBACK_URL,
      proxy: true,
    },
    async (accessToken, refreshToken, profile, done) => {
      try {
        let user = await User.findOne({ email: profile.emails?.[0].value });
        if (!user) {
          user = await User.create({
            googleId: profile.id,
            displayName: profile.displayName,
            email: profile.emails?.[0].value,
            image: profile.photos?.[0].value,
            isVerified: true,
          });
        } else if (!user.googleId) {
          user.googleId = profile.id;
          user.isVerified = true;
          await user.save();
        }
        return done(null, user);
      } catch (err) {
        return done(err);
      }
    },
  ),
);

// LOCAL STRATEGY
passport.use(
  new LocalStrategy(
    { usernameField: 'email' },
    async (email, password, done) => {
      try {
        const user = await User.findOne({ email });
        if (!user) return done(null, false, { message: 'User not found.' });
        if (!user.isVerified)
          return done(null, false, { message: 'Verify OTP first.' });
        if (!user.password)
          return done(null, false, { message: 'Use Google Login.' });

        const isMatch = await bcrypt.compare(password, user.password);
        return isMatch
          ? done(null, user)
          : done(null, false, { message: 'Incorrect password.' });
      } catch (err) {
        return done(err);
      }
    },
  ),
);

passport.serializeUser((user: any, done) => done(null, user.id));
passport.deserializeUser(async (id, done) => {
  try {
    const user = await User.findById(id);
    done(null, user);
  } catch (err) {
    done(err);
  }
});

// --- 6. ROUTES ---

// Health Check
app.get('/', (req, res) => res.send('Gym App Backend is Live!'));

// SIGNUP (OTP SEND)
app.post('/auth/signup', async (req: Request, res: Response) => {
  const { displayName, email, password } = req.body;
  try {
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const hashedPassword = await bcrypt.hash(password, 10);

    await User.findOneAndUpdate(
      { email },
      {
        displayName,
        password: hashedPassword,
        otp,
        otpExpires: new Date(Date.now() + 600000),
        isVerified: false,
      },
      { upsert: true },
    );

    // Naya aur Stable Transporter
    const transporter = nodemailer.createTransport({
      host: 'smtp.gmail.com',
      port: 587,
      secure: false,
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,
      },
      // Ye block Railway ki ENETUNREACH error ko fix karega
      connectionTimeout: 15000,
      greetingTimeout: 15000,
      socketTimeout: 20000,
      dnsVapi: true, // DNS resolution force karne ke liye
      options: {
        family: 4, // Sirf IPv4 use karne ke liye, IPv6 skip karega
      },
    } as any); // Type assertion for family option

    await transporter.sendMail({
      from: `"ProFit Support" <${process.env.EMAIL_USER}>`,
      to: email,
      subject: 'Verify Your Account',
      html: `<div style="font-family: Arial, sans-serif; padding: 20px;">
              <h2>Welcome to ProFit!</h2>
              <p>Your OTP for account verification is:</p>
              <h1 style="color: #155DFC; letter-spacing: 5px;">${otp}</h1>
              <p>This OTP is valid for 10 minutes.</p>
            </div>`,
    });

    res.status(200).json({ message: 'OTP sent!' });
  } catch (err) {
    console.error('Signup Error:', err);
    res.status(500).json({ message: 'Error sending OTP' });
  }
});

// VERIFY OTP
app.post('/auth/verify-otp', async (req: Request, res: Response) => {
  const { email, otp } = req.body;
  try {
    const user = await User.findOne({
      email,
      otp,
      otpExpires: { $gt: new Date() },
    });
    if (!user)
      return res.status(400).json({ message: 'Invalid or expired OTP' });

    user.isVerified = true;
    user.otp = undefined;
    user.otpExpires = undefined;
    await user.save();
    res.json({ message: 'Verified!' });
  } catch (err) {
    res.status(500).json({ message: 'Verification failed' });
  }
});

// LOGIN
app.post('/auth/login', (req: Request, res: Response, next: NextFunction) => {
  passport.authenticate('local', (err: any, user: any, info: any) => {
    if (err) return next(err);
    if (!user)
      return res.status(401).json({ message: info?.message || 'Login failed' });
    req.logIn(user, (err) => {
      if (err) return next(err);
      res.json({ message: 'Logged in', user });
    });
  })(req, res, next);
});

// GOOGLE AUTH
app.get(
  '/auth/google',
  passport.authenticate('google', { scope: ['profile', 'email'] }),
);

app.get(
  '/auth/google/callback',
  passport.authenticate('google', { failureRedirect: `${FRONTEND_URL}/login` }),
  (req, res) => {
    res.redirect(`${FRONTEND_URL}/home`);
  },
);

// LOGOUT
app.get('/auth/logout', (req, res, next) => {
  req.logout((err) => {
    if (err) return next(err);
    res.json({ message: 'Logged out' });
  });
});

app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
