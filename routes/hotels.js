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
        .from("hotels")
        .select("email")
        .eq("email", req.body.email);

    if (data.length > 0) {
        res.send({ status: 401, message: "Email already exist" });
        return res.end();
    }

    let hotelRegister = req.body;
    hotelRegister.status = 0;
    hotelRegister.approved_by = null;
    const { error } = await supabase.from("registrations").insert(req.body);
    console.log(error);
    if (error) {
        res.send({ status: 401, message: "Fail to sign up" });
        return res.end();
    }

    res.send({ status: 200, message: "Successfully signed up" });
});

module.exports = router;
