const express = require("express");
const serverless = require("serverless-http");
const bodyParser = require("body-parser");
const morgan = require("morgan");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const jwt_decode = require("jwt-decode");
const cors = require("cors");
const cookieParser = require("cookie-parser");
const { createClient } = require("@supabase/supabase-js");
const app = express();
const port = 3000;
require("dotenv").config();

const accessTokenExpirationTime = "15m"; // 15 minutes
const refreshTokenExpirationTime = "200d"; // 100 days

const hotelRoutes = require("./routes/hotels");
const userRoutes = require("./routes/users");
const adminRoutes = require("./routes/admins");

app.use(morgan("combined"));
app.use(cookieParser());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(cors());
app.use("/hotels", hotelRoutes);
app.use("/users", userRoutes);
app.use("/admins", adminRoutes);

const router = express.Router();

// app.listen(port, () => {
//     console.log(`API listening on port ${port}`);
// });

// Create a single supabase client for interacting with your database
const supabase = createClient(process.env.SUPA_URL, process.env.API_KEY);
//console.log('Supabase Instance: ', supabase)

router.get("/", async (req, res) => {
    res.send("StayWithMe API");
});

function checkEmail(email) {
    return new Promise(async (resolve, reject) => {
        const userCheck = await supabase
            .from("users")
            .select()
            .eq("email", email);

        const hotelCheck = await supabase
            .from("hotels")
            .select()
            .eq("email", email);
        console.log(userCheck);
        if (userCheck.data.length <= 0 && hotelCheck.data.length <= 0) {
            console.log("No account with this email exist");
            reject({
                status: 401,
                message: "No account with this email exist",
            });
        } else if (hotelCheck.data.length > 0) {
            console.log("Hotel with this email exist");
            resolve({
                status: 200,
                message: "Hotel with this email exist",
                data: hotelCheck.data[0],
            });
        } else {
            resolve({
                status: 200,
                message: "User with this email exist",
                data: userCheck.data[0],
            });
        }
    });
}

function authToken(token) {
    return new Promise((resolve, reject) => {
        jwt.verify(token, process.env.TOKEN_SECRET, async (err, decoded) => {
            if (err) {
                return reject({ status: 401, message: "Invalid Token" });
            }
            const emailCheck = await checkEmail(decoded.email);
            resolve(emailCheck);
        });
    });
}

router.post("/autoLogin", async (req, res) => {
    if (req.body.token) {
        const accountCheck = await authToken(req.body.token).catch((err) => {
            return res.send(err);
        });
        delete accountCheck.data["password"];
        let payload = accountCheck.data;

        const accessToken = jwt.sign(payload, process.env.TOKEN_SECRET, {
            expiresIn: accessTokenExpirationTime,
        });
        return res.send({
            status: 200,
            message: accountCheck.message,
            accessToken: accessToken,
        });
    } else
        return res.send({
            status: 401,
            message: "Invalid Token",
        });
});

router.post("/login", async (req, res) => {
    console.log(req.body);
    const emailCheck = await checkEmail(req.body.email).catch((err) => {
        return res.send(err);
    });
    console.log(req.body.password);
    bcrypt
        .compare(req.body.password, emailCheck.data.password)
        .then((result) => {
            if (result) {
                delete emailCheck.data["password"];
                let payload = emailCheck.data;

                const accessToken = jwt.sign(
                    payload,
                    process.env.TOKEN_SECRET,
                    {
                        expiresIn: accessTokenExpirationTime,
                    }
                );
                console.log("Made access token");
                const refreshToken = jwt.sign(
                    payload,
                    process.env.TOKEN_SECRET,
                    {
                        expiresIn: refreshTokenExpirationTime,
                    }
                );
                console.log("Made refresh token");
                console.log("Sent to User");
                return res.send({
                    status: 200,
                    message: emailCheck.message,
                    accessToken: accessToken,
                    refreshToken: refreshToken,
                });
            } else {
                return res.send({
                    status: 401,
                    message: "Wrong Password",
                });
            }
        });
});

app.use("/.netlify/functions/api", router);

module.exports.handler = serverless(app);
