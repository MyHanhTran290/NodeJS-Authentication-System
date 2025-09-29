import passport from 'passport';  // Importing passport for authentication
import express from 'express';    // Importing express for the web framework
import { googleSignInController } from '../controllers/authController.js';  // Importing the Google sign-in controller
import dotenv from 'dotenv';      // Importing dotenv to load environment variables
import jwt from "jsonwebtoken";
import User from "../models/userModel.js";

dotenv.config();  // Loading environment variables from .env file

const authRouter = express.Router(); // Creating an instance of express Router for handling authentication routes
const googleSignIn = new googleSignInController(); // Creating an instance of GoogleSignInController

// OAuth2 login with Google
authRouter.get("/google", passport.authenticate('google', { scope: ['email', 'profile'] }));

// Google OAuth2 callback
authRouter.get("/google/callback",
    passport.authenticate("google", {
        successRedirect: process.env.CLIENT_URL,
        failureRedirect: "/login/failed"
    })
);

// Routes for handling login success and failure
authRouter.get("/login/success", async (req, res) => {
    if (!req.user) {
        return res.status(401).json({ error: true, message: "Not Authorized" });
    }

    const { email, name, sub } = req.user._json;

    try {
        // Kiểm tra user có trong DB chưa
        let user = await User.findOne({ email: email });
        if (!user) {
            user = new User({
                username: name,
                email: email,
                password: sub   // ⚠️ không an toàn, chỉ demo
            });
            await user.save();
        }

        // Sinh token 60s
        const token = jwt.sign(
            { email: user.email },
            process.env.JWT_SECRET || "mySecret",
            { expiresIn: "60s" }
        );

        res.status(200).json({
            success: true,
            message: "Login successful",
            token,
            user
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: true, message: "Server error" });
    }
});

authRouter.get("/login/failed", googleSignIn.signInFailed);

export default authRouter; // Exporting the Auth Router
