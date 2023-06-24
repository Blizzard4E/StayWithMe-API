const express = require("express");
const router = express.Router();
const { createClient } = require("@supabase/supabase-js");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const jwt_decode = require("jwt-decode");

const saltRounds = 10;
const accessTokenExpirationTimeAdmin = "1h"; // 15 minutes
const accessTokenCookieTimeAdmin = 120 * 60 * 1000; // 2 Hour
require("dotenv").config();

const supabase = createClient(process.env.URL, process.env.API_KEY);

router.post("/admins/login", async (req, res) => {
    const { error } = await supabase
        .from("admins")
        .select("email")
        .eq("email", req.body.email);

    if (error) res.send("Email does not exist");
    else {
        let admin = req.body;
        const { data } = await supabase
            .from("admins")
            .select()
            .eq("email", req.body.email);

        if (data.length > 0) {
            bcrypt.compare(admin.password, data[0].password).then((result) => {
                if (result) {
                    const payload = {
                        username: data[0].username,
                        email: data[0].email,
                        role: data[0].role,
                    };

                    const accessToken = jwt.sign(
                        payload,
                        process.env.TOKEN_SECRET,
                        { expiresIn: accessTokenExpirationTimeAdmin }
                    );

                    res.cookie("accessToken", accessToken, {
                        expires: new Date(
                            Date.now() + accessTokenCookieTimeAdmin
                        ),
                    });

                    res.send({
                        status: 200,
                        message: "Successfully logged in",
                    });
                } else res.send({ status: 401, message: "Wrong Password" });
            });
        } else
            res.send({
                status: 401,
                message: "User with that email does not exist",
            });
    }
});

router.post("/admins/create", async (req, res) => {
    let token = req.cookies.accessToken;
    jwt.verify(token, process.env.TOKEN_SECRET, async (err, decoded) => {
        if (err) {
            res.send(err);
        } else if (decoded.role == 2) {
            const { data } = await supabase
                .from("admins")
                .select("email")
                .eq("email", req.body.email);

            if (data.length > 0)
                res.send({ status: 401, message: "Email already exist" });
            else {
                let admin = req.body;

                bcrypt.hash(admin.password, saltRounds, async (err, hash) => {
                    console.log(err);
                    admin.password = hash;
                    const { error } = await supabase
                        .from("admins")
                        .insert(req.body);

                    if (error)
                        res.send({
                            status: 401,
                            message: "Fail to create admin",
                        });
                    else
                        res.send({
                            status: 200,
                            message: "Successfully created a user",
                        });
                });
            }
        } else {
            res.send({ status: 440, message: "Unauthorized Access" });
        }
    });
});

module.exports = router;
