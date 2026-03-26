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
app.use(express.json());

// --- 1. MONGODB CONNECTION ---
mongoose
  .connect(process.env.MONGO_URI!, {
    // @ts-ignore
    tls: true,
    tlsAllowInvalidCertificates: true,
  })
  .then(() => console.log('✅ MongoDB Connected'))
  .catch((err) => console.error('❌ MongoDB Error:', err));

// --- 2. USER MODEL ---
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

// --- 3. SESSION & CORS ---
app.use(
  cors({
    origin: [
      'http://localhost:3000',
      'http://192.168.1.4:3000', // Phone wala URL bhi allow karo
    ],
    credentials: true,
  }),
);
app.use(
  session({
    secret: process.env.SESSION_SECRET!,
    resave: false,
    saveUninitialized: false,
    store: MongoStore.create({ mongoUrl: process.env.MONGO_URI! }),
    cookie: {
      maxAge: 24 * 60 * 60 * 1000,
      secure: false,
      httpOnly: true,
    },
  }),
);

app.use(passport.initialize());
app.use(passport.session());

// --- 4. PASSPORT CONFIG ---

// 4.1 GOOGLE STRATEGY (Ye missing tha!)
passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID!,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET!,
      callbackURL: process.env.GOOGLE_CALLBACK_URL || '/auth/google/callback',
    },
    async (accessToken, refreshToken, profile, done) => {
      try {
        let user = await User.findOne({ email: profile.emails?.[0].value });

        if (!user) {
          // Naya user banao agar nahi hai
          user = await User.create({
            googleId: profile.id,
            displayName: profile.displayName,
            email: profile.emails?.[0].value,
            image: profile.photos?.[0].value,
            isVerified: true, // Google users are pre-verified
          });
        } else if (!user.googleId) {
          // Agar email se account hai par Google link nahi hai
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

// 4.2 LOCAL STRATEGY
passport.use(
  new LocalStrategy(
    { usernameField: 'email' },
    async (email, password, done) => {
      try {
        const user = await User.findOne({ email });
        if (!user) return done(null, false, { message: 'User not found.' });
        if (!user.isVerified)
          return done(null, false, { message: 'Please verify OTP first.' });
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
  const user = await User.findById(id);
  done(null, user);
});

// --- 5. ROUTES ---

// SIGNUP
app.post('/auth/signup', async (req: Request, res: Response) => {
  const { displayName, email, password } = req.body;
  try {
    const existingUser = await User.findOne({ email, isVerified: true });
    if (existingUser)
      return res.status(400).json({ message: 'Email already registered' });

    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const hashedPassword = await bcrypt.hash(password, 10);

    await User.findOneAndUpdate(
      { email },
      {
        displayName,
        password: hashedPassword,
        otp,
        otpExpires: Date.now() + 600000,
        isVerified: false,
      },
      { upsert: true, returnDocument: 'after' },
    );

    const transporter = nodemailer.createTransport({
      service: 'gmail',
      auth: { user: process.env.EMAIL_USER, pass: process.env.EMAIL_PASS },
    });

    await transporter.sendMail({
      from: `"ProFit Support" <${process.env.EMAIL_USER}>`,
      to: email,
      subject: 'Verify Your Account',
      html: `<h2>OTP: ${otp}</h2>`,
    });

    res.status(200).json({ message: 'OTP sent!' });
  } catch (err) {
    res.status(500).json({ message: 'Error' });
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
    if (!user) return res.status(400).json({ message: 'Invalid OTP' });

    user.isVerified = true;
    user.otp = undefined;
    await user.save();
    res.json({ message: 'Verified!' });
  } catch (err) {
    res.status(500).json({ message: 'Failed' });
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

// GOOGLE AUTH ROUTES
app.get(
  '/auth/google',
  passport.authenticate('google', { scope: ['profile', 'email'] }),
);

app.get(
  '/auth/google/callback',
  passport.authenticate('google', {
    failureRedirect: 'http://localhost:3000/auth',
  }),
  (req, res) => {
    res.redirect('http://localhost:3000/home');
  },
);

app.listen(5000, () =>
  console.log('🚀 Server running on http://localhost:5000'),
);
