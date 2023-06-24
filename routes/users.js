const express = require("express");
const router = express.Router();
const { createClient } = require("@supabase/supabase-js");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const jwt_decode = require("jwt-decode");

const saltRounds = 10;
const accessTokenExpirationTime = "15m"; // 15 minutes
const accessTokenCookieTime = 60 * 60 * 1000; // 1 Hour
const refreshTokenExpirationTime = "100d"; // 100 days
const refreshTokenCookieTime = 100 * 24 * 60 * 60 * 1000; // 200 days
require("dotenv").config();

const supabase = createClient(process.env.URL, process.env.API_KEY);

router.post("/signUp", async (req, res) => {
    const { data } = await supabase
        .from("users")
        .select("email")
        .eq("email", req.body.email);

    if (data.length > 0)
        res.send({ status: 401, message: "Email already exist" });
    else {
        let user = req.body;
        user.banned = false;

        bcrypt.hash(user.password, saltRounds, async (err, hash) => {
            console.log(err);
            user.password = hash;
            const { error } = await supabase.from("users").insert(req.body);

            if (error)
                res.send({ status: 401, message: "Fail to create user" });
            else {
                const jwt = require("jsonwebtoken");
                const payload = {
                    username: user.username,
                    email: user.email,
                    profile_pic: user.profile_pic,
                    banned: user.banned,
                    bio: user.bio,
                    is_user: true,
                };

                const accessToken = jwt.sign(
                    payload,
                    process.env.TOKEN_SECRET,
                    { expiresIn: accessTokenExpirationTime }
                );
                const refreshToken = jwt.sign(
                    payload,
                    process.env.TOKEN_SECRET,
                    { expiresIn: refreshTokenExpirationTime }
                );

                res.cookie("accessToken", accessToken, {
                    expires: new Date(Date.now() + accessTokenCookieTime),
                });
                res.cookie("refreshToken", refreshToken, {
                    expires: new Date(Date.now() + refreshTokenCookieTime),
                });

                res.send({
                    status: 200,
                    message: "Successfully created a user",
                });
            }
        });
    }
});

router.post("/login", async (req, res) => {
    console.log(req.body);
    const { error } = await supabase
        .from("users")
        .select("email")
        .eq("email", req.body.email);

    if (error) {
        res.send("Email does not exist");
        res.end();
    }
    let user = req.body;
    const { data } = await supabase
        .from("users")
        .select()
        .eq("email", req.body.email);
    if (data.length <= 0) {
        res.send({
            status: 401,
            message: "User with that email does not exist",
        });
        res.end();
    }

    bcrypt.compare(user.password, data[0].password).then((result) => {
        if (result) {
            const payload = {
                username: data[0].username,
                email: data[0].email,
                profile_pic: data[0].profile_pic,
                banned: data[0].banned,
                bio: data[0].bio,
                is_user: true,
            };

            const accessToken = jwt.sign(payload, process.env.TOKEN_SECRET, {
                expiresIn: accessTokenExpirationTime,
            });
            const refreshToken = jwt.sign(payload, process.env.TOKEN_SECRET, {
                expiresIn: refreshTokenExpirationTime,
            });

            res.cookie("accessToken", accessToken, {
                expires: new Date(Date.now() + accessTokenCookieTime),
            });
            res.cookie("refreshToken", refreshToken, {
                expires: new Date(Date.now() + refreshTokenCookieTime),
            });

            res.send({
                status: 200,
                message: "Successfully logged in",
            });
        } else res.send({ status: 401, message: "Wrong Password" });
    });
});

router.post("/autoLogin", async (req, res) => {
    let token = req.cookies.refreshToken;
    console.log(token);
    jwt.verify(token, process.env.TOKEN_SECRET, async (err, decoded) => {
        if (err) {
            res.send({ status: 401, message: "Invalid Token" });
            return res.end();
        }
        const userInfo = jwt_decode(token);

        const { data } = await supabase
            .from("users")
            .select("email")
            .eq("email", userInfo.email);

        if (data.length <= 0) {
            res.send({ status: 401, message: "Email does not exist" });
            return res.end();
        }

        const payload = {
            username: decoded.username,
            email: decoded.email,
            profile_pic: decoded.profile_pic,
            banned: decoded.banned,
            bio: decoded.bio,
            is_user: true,
        };

        const accessToken = jwt.sign(payload, process.env.TOKEN_SECRET, {
            expiresIn: accessTokenExpirationTime,
        });
        const refreshToken = jwt.sign(payload, process.env.TOKEN_SECRET, {
            expiresIn: refreshTokenExpirationTime,
        });

        res.cookie("accessToken", accessToken, {
            expires: new Date(Date.now() + accessTokenCookieTime),
        });
        res.cookie("refreshToken", refreshToken, {
            expires: new Date(Date.now() + refreshTokenCookieTime),
        });

        res.send({
            status: 200,
            message: "Successfully automatically logged in",
        });
    });
});

module.exports = router;
