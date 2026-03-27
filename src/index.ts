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
import { fileURLToPath } from 'url';
import { dirname } from 'path';

// ES Modules ke liye __dirname ka alternative
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

dotenv.config();

const app = express();

// --- 1. SETTINGS & MIDDLEWARES ---
const PORT = process.env.PORT || 5000;
const FRONTEND_URL = process.env.FRONTEND_URL
  ? process.env.FRONTEND_URL.replace(/\/$/, '')
  : 'http://localhost:3000';

app.use(express.json());
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
  .connect(process.env.MONGO_URI as string)
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
    secret: process.env.SESSION_SECRET as string,
    resave: false,
    saveUninitialized: false,
    store: MongoStore.create({ mongoUrl: process.env.MONGO_URI as string }),
    cookie: {
      maxAge: 24 * 60 * 60 * 1000,
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
      clientID: process.env.GOOGLE_CLIENT_ID as string,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET as string,
      callbackURL: process.env.GOOGLE_CALLBACK_URL as string,
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
        return done(err as Error);
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
        return done(err as Error);
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

// --- 6. NODEMAILER TRANSPORTER FUNCTION (Production Ready - Fixed for TypeScript) ---
const createTransporter = () => {
  // @ts-ignore - TypeScript strict checking ko ignore kar rahe hain
  return nodemailer.createTransport({
    host: 'smtp.gmail.com',
    port: 587,
    secure: false,
    auth: {
      user: process.env.EMAIL_USER,
      pass: process.env.EMAIL_PASS,
    },
    // CRITICAL: Force IPv4 to bypass Railway's IPv6 issues
    family: 4,
    // Connection timeouts
    connectionTimeout: 30000,
    greetingTimeout: 30000,
    socketTimeout: 30000,
    // TLS configuration
    tls: {
      rejectUnauthorized: false,
      minVersion: 'TLSv1.2',
    },
  });
};

// Verify transporter on startup
const verifyTransporter = async () => {
  try {
    const transporter = createTransporter();
    await transporter.verify();
    console.log('✅ Nodemailer transporter is ready');
  } catch (error) {
    console.error('❌ Nodemailer transporter verification failed:', error);
  }
};

verifyTransporter();

// --- 7. ROUTES ---

// Health Check
app.get('/', (req, res) => res.send('Gym App Backend is Live!'));

// SIGNUP (OTP SEND)
app.post('/auth/signup', async (req: Request, res: Response) => {
  const { displayName, email, password } = req.body;

  // Input validation
  if (!displayName || !email || !password) {
    return res.status(400).json({ message: 'All fields are required' });
  }

  // Email validation
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(email)) {
    return res.status(400).json({ message: 'Invalid email format' });
  }

  // Password validation
  if (password.length < 6) {
    return res
      .status(400)
      .json({ message: 'Password must be at least 6 characters' });
  }

  try {
    // Check if user already exists and is verified
    const existingUser = await User.findOne({ email });
    if (existingUser && existingUser.isVerified) {
      return res.status(400).json({ message: 'Email already registered' });
    }

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
      { upsert: true, new: true },
    );

    const transporter = createTransporter();

    await transporter.sendMail({
      from: `"ProFit Support" <${process.env.EMAIL_USER}>`,
      to: email,
      subject: 'Verify Your Account - ProFit Gym',
      html: `
                <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
                    <h2>Welcome to ProFit, ${displayName}!</h2>
                    <p>Your OTP for account verification is:</p>
                    <h1 style="color: #155DFC;">${otp}</h1>
                    <p>This OTP is valid for 10 minutes.</p>
                </div>
            `,
    });

    console.log('✅ OTP email sent successfully to:', email);
    res.status(200).json({ message: 'OTP sent successfully!' });
  } catch (err: any) {
    console.error('❌ Signup Error:', err.message);

    if (
      err.code === 'ESOCKET' ||
      err.code === 'ECONNECTION' ||
      err.code === 'ETIMEDOUT'
    ) {
      return res.status(503).json({
        message: 'Email service temporarily unavailable. Please try again.',
      });
    }

    res.status(500).json({
      message: 'Error sending OTP. Please try again later.',
    });
  }
});

// VERIFY OTP
app.post('/auth/verify-otp', async (req: Request, res: Response) => {
  const { email, otp } = req.body;

  if (!email || !otp) {
    return res.status(400).json({ message: 'Email and OTP are required' });
  }

  try {
    const user = await User.findOne({
      email,
      otp,
      otpExpires: { $gt: new Date() },
    });

    if (!user) {
      return res.status(400).json({ message: 'Invalid or expired OTP' });
    }

    user.isVerified = true;
    user.otp = undefined;
    user.otpExpires = undefined;
    await user.save();

    res.json({ message: 'Verified successfully!' });
  } catch (err) {
    console.error('❌ Verification error:', err);
    res.status(500).json({ message: 'Verification failed' });
  }
});

// RESEND OTP
app.post('/auth/resend-otp', async (req: Request, res: Response) => {
  const { email } = req.body;

  if (!email) {
    return res.status(400).json({ message: 'Email is required' });
  }

  try {
    const user = await User.findOne({ email });

    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    if (user.isVerified) {
      return res.status(400).json({ message: 'Email already verified' });
    }

    const otp = Math.floor(100000 + Math.random() * 900000).toString();

    user.otp = otp;
    user.otpExpires = new Date(Date.now() + 600000);
    await user.save();

    const transporter = createTransporter();

    await transporter.sendMail({
      from: `"ProFit Support" <${process.env.EMAIL_USER}>`,
      to: email,
      subject: 'Resend OTP - ProFit Gym',
      html: `<h2>Your OTP is: ${otp}</h2><p>Valid for 10 minutes.</p>`,
    });

    res.json({ message: 'OTP resent successfully!' });
  } catch (err) {
    console.error('❌ Resend OTP error:', err);
    res.status(500).json({ message: 'Error resending OTP' });
  }
});

// LOGIN
app.post('/auth/login', (req: Request, res: Response, next: NextFunction) => {
  passport.authenticate('local', (err: any, user: any, info: any) => {
    if (err) return next(err);
    if (!user) {
      return res.status(401).json({ message: info?.message || 'Login failed' });
    }
    req.logIn(user, (err) => {
      if (err) return next(err);
      res.json({
        message: 'Logged in successfully',
        user: {
          id: user._id,
          displayName: user.displayName,
          email: user.email,
          image: user.image,
        },
      });
    });
  })(req, res, next);
});

// GET CURRENT USER
app.get('/auth/me', (req: Request, res: Response) => {
  if (req.isAuthenticated()) {
    const user = req.user as any;
    res.json({
      id: user._id,
      displayName: user.displayName,
      email: user.email,
      image: user.image,
      isVerified: user.isVerified,
    });
  } else {
    res.status(401).json({ message: 'Not authenticated' });
  }
});

// GOOGLE AUTH
app.get(
  '/auth/google',
  passport.authenticate('google', { scope: ['profile', 'email'] }),
);

app.get(
  '/auth/google/callback',
  passport.authenticate('google', {
    failureRedirect: `${FRONTEND_URL}/login`,
  }),
  (req, res) => {
    res.redirect(`${FRONTEND_URL}/home`);
  },
);

// LOGOUT
app.get('/auth/logout', (req, res, next) => {
  req.logout((err) => {
    if (err) return next(err);
    res.json({ message: 'Logged out successfully' });
  });
});

// 404 Handler
app.use((req: Request, res: Response) => {
  res.status(404).json({ message: 'Route not found' });
});

// Error Handler
app.use((err: any, req: Request, res: Response, next: NextFunction) => {
  console.error('Server error:', err);
  res.status(500).json({
    message: 'Internal server error',
  });
});

app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
