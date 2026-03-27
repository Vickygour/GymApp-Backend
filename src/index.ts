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

// --- 6. NODEMAILER TRANSPORTER FUNCTION (Production Ready) ---
const createTransporter = () => {
    return nodemailer.createTransport({
        host: 'smtp.gmail.com',
        port: 587,
        secure: false,
        auth: {
            user: process.env.EMAIL_USER,
            pass: process.env.EMAIL_PASS  // NOTE: EMAIL_PASS use karo, PASSWORD nahi
        },
        // Force IPv4 to bypass Railway's IPv6 issues
        family: 4,
        // Connection timeouts
        connectionTimeout: 30000,
        greetingTimeout: 30000,
        socketTimeout: 30000,
        // TLS configuration
        tls: {
            rejectUnauthorized: false,
            minVersion: 'TLSv1.2' as const,
            ciphers: 'HIGH:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5:!PSK:!SRP:!CAMELLIA'
        }
    } as any);  // 'as any' TypeScript error ko temporarily fix karega
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

// Call verification but don't wait for it
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

  // Password validation (minimum 6 characters)
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
        otpExpires: new Date(Date.now() + 600000), // 10 minutes
        isVerified: false,
      },
      { upsert: true, new: true },
    );

    // Create transporter with production config
    const transporter = createTransporter();

    // Send email with better error handling
    const info = await transporter.sendMail({
      from: `"ProFit Support" <${process.env.EMAIL_USER}>`,
      to: email,
      subject: 'Verify Your Account - ProFit Gym',
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; background-color: #f9f9f9;">
          <div style="background-color: #155DFC; padding: 20px; text-align: center; border-radius: 10px 10px 0 0;">
            <h1 style="color: white; margin: 0;">ProFit Gym</h1>
          </div>
          <div style="background-color: white; padding: 30px; border-radius: 0 0 10px 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1);">
            <h2>Welcome to ProFit, ${displayName}!</h2>
            <p>Thank you for signing up. Please use the following OTP to verify your email address:</p>
            <div style="text-align: center; margin: 30px 0;">
              <div style="font-size: 32px; font-weight: bold; color: #155DFC; letter-spacing: 8px; background-color: #f0f0f0; padding: 15px; border-radius: 8px; display: inline-block;">
                ${otp}
              </div>
            </div>
            <p>This OTP is valid for <strong>10 minutes</strong>.</p>
            <p>If you didn't request this, please ignore this email.</p>
            <hr style="margin: 20px 0; border: none; border-top: 1px solid #eee;">
            <p style="color: #666; font-size: 12px; text-align: center;">
              This is an automated message, please do not reply to this email.
            </p>
          </div>
        </div>
      `,
    });

    console.log(
      '✅ OTP email sent successfully to:',
      email,
      'Message ID:',
      info.messageId,
    );
    res.status(200).json({ message: 'OTP sent successfully!' });
  } catch (err: any) {
    console.error('❌ Signup Error Details:', {
      message: err.message,
      code: err.code,
      command: err.command,
      response: err.response,
      stack: err.stack,
    });

    // Provide more specific error messages
    if (
      err.code === 'ESOCKET' ||
      err.code === 'ECONNECTION' ||
      err.code === 'ETIMEDOUT'
    ) {
      return res.status(503).json({
        message:
          'Email service temporarily unavailable. Please try again in a few moments.',
      });
    }

    if (err.code === 'EAUTH') {
      return res.status(401).json({
        message: 'Email authentication failed. Please contact support.',
      });
    }

    res.status(500).json({
      message: 'Error sending OTP. Please try again later.',
      error: process.env.NODE_ENV === 'development' ? err.message : undefined,
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

    console.log('✅ User verified:', email);
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
    user.otpExpires = new Date(Date.now() + 600000); // 10 minutes
    await user.save();

    const transporter = createTransporter();

    await transporter.sendMail({
      from: `"ProFit Support" <${process.env.EMAIL_USER}>`,
      to: email,
      subject: 'Resend OTP - ProFit Gym',
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
          <h2>Your New OTP</h2>
          <p>Here is your new OTP for email verification:</p>
          <h1 style="color: #155DFC;">${otp}</h1>
          <p>This OTP is valid for 10 minutes.</p>
        </div>
      `,
    });

    console.log('✅ OTP resent to:', email);
    res.json({ message: 'OTP resent successfully!' });
  } catch (err) {
    console.error('❌ Resend OTP error:', err);
    res.status(500).json({ message: 'Error resending OTP' });
  }
});

// LOGIN
app.post('/auth/login', (req: Request, res: Response, next: NextFunction) => {
  passport.authenticate('local', (err: any, user: any, info: any) => {
    if (err) {
      console.error('Login error:', err);
      return next(err);
    }
    if (!user) {
      return res.status(401).json({ message: info?.message || 'Login failed' });
    }
    req.logIn(user, (err) => {
      if (err) {
        console.error('Session error:', err);
        return next(err);
      }
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
  passport.authenticate('google', { failureRedirect: `${FRONTEND_URL}/login` }),
  (req, res) => {
    res.redirect(`${FRONTEND_URL}/home`);
  },
);

// LOGOUT
app.get('/auth/logout', (req, res, next) => {
  req.logout((err) => {
    if (err) {
      console.error('Logout error:', err);
      return next(err);
    }
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
    error: process.env.NODE_ENV === 'development' ? err.message : undefined,
  });
});

app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
