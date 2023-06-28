const express = require("express");
const router = express.Router();
const { createClient } = require("@supabase/supabase-js");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
require("dotenv").config();
const supabase = createClient(process.env.SUPA_URL, process.env.API_KEY);
const saltRounds = 10;
const accessTokenExpirationTime = "15m"; // 15 minutes
const refreshTokenExpirationTime = "200d"; // 100 days

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
            const emailCheck = await checkEmail(decoded.email).catch((err) => {
                return reject(err);
            });
            resolve(emailCheck);
        });
    });
}

router.post("/onGoing", async (req, res) => {
    if (req.body.token) {
        const tokenCheck = await authToken(req.body.token).catch((err) => {
            return res.send(err);
        });
        if (tokenCheck) {
            delete req.body["token"];
            const bookingsData = await supabase
                .from("bookings")
                .select(
                    "user_id ( profile_pic, username), days, created_at, id, room_id"
                )
                .eq("hotel_id", req.body.hotel_id)
                .eq("on_going", true);

            if (bookingsData.error) {
                return res.send({
                    status: 401,
                    message: "Cannot get bookings",
                });
            } else {
                return res.send({
                    status: 200,
                    message: "Successfully get bookings",
                    bookingsData: bookingsData.data,
                });
            }
        }
    } else return res.send({ status: 401, message: "Unauthorized Access" });
});

router.post("/removeRoom", async (req, res) => {
    if (req.body.token) {
        const tokenCheck = await authToken(req.body.token).catch((err) => {
            return res.send(err);
        });
        if (tokenCheck) {
            delete req.body["token"];
            const { error } = await supabase
                .from("rooms")
                .update({ availability: 2 })
                .eq("id", req.body.room_id);
            console.log(error);
            if (error) {
                return res.send({
                    status: 401,
                    message: "Cannot remove room",
                });
            } else {
                return res.send({
                    status: 200,
                    message: "Removed room",
                });
            }
        }
    } else return res.send({ status: 401, message: "Unauthorized Access" });
});

router.post("/update", async (req, res) => {
    if (req.body.token) {
        const tokenCheck = await authToken(req.body.token).catch((err) => {
            return res.send(err);
        });
        if (tokenCheck) {
            delete req.body["token"];
            const { error } = await supabase
                .from("hotels")
                .update(req.body)
                .eq("id", req.body.id);
            console.log(error);
            if (error) {
                return res.send({
                    status: 401,
                    message: "Cannot update hotel",
                });
            } else {
                return res.send({
                    status: 200,
                    message: "Updated Hotel",
                });
            }
        }
    } else return res.send({ status: 401, message: "Unauthorized Access" });
});

router.post("/createRoom", async (req, res) => {
    if (req.body.token) {
        const tokenCheck = await authToken(req.body.token).catch((err) => {
            return res.send(err);
        });
        if (tokenCheck) {
            delete req.body["token"];
            const { error } = await supabase.from("rooms").insert(req.body);
            if (error) {
                return res.send({ status: 401, message: "Cannot create room" });
            } else {
                return res.send({
                    status: 200,
                    message: "New room created",
                });
            }
        }
    } else return res.send({ status: 401, message: "Unauthorized Access" });
});

router.post("/getRooms", async (req, res) => {
    if (req.body.token) {
        const tokenCheck = await authToken(req.body.token).catch((err) => {
            return res.send(err);
        });
        if (tokenCheck) {
            const { data } = await supabase
                .from("rooms")
                .select()
                .eq("hotel_id", req.body.hotel_id)
                .lte("availability", 1);
            if (data.length > 0) {
                return res.send({
                    status: 200,
                    message: "Successfully get all rooms",
                    data: data,
                });
            } else {
                return res.send({
                    status: 401,
                    message: "Failed to get all rooms",
                });
            }
        }
    } else return res.send({ status: 401, message: "Unauthorized Access" });
});

router.post("/checkOut", async (req, res) => {
    if (req.body.token) {
        const tokenCheck = await authToken(req.body.token).catch((err) => {
            return res.send(err);
        });
        if (tokenCheck) {
            const roomData = await supabase
                .from("rooms")
                .update({ availability: 1 })
                .eq("id", req.body.room_id);
            console.log(roomData.error);
            if (roomData.error) {
                return res.send({
                    status: 401,
                    message: "Failed to update room",
                });
            }
            const bookingData = await supabase
                .from("bookings")
                .update({ on_going: false })
                .eq("id", req.body.booking_id);

            if (bookingData.error) {
                return res.send({
                    status: 401,
                    message: "Failed to checkout",
                });
            } else {
                return res.send({
                    status: 200,
                    message: "Successfully checkout",
                });
            }
        }
    } else return res.send({ status: 401, message: "Unauthorized Access" });
});

router.post("/signUp", async (req, res) => {
    console.log("Request received on SignUp");
    if (
        req.body.email &&
        req.body.password &&
        req.body.name &&
        req.body.images &&
        req.body.description &&
        req.body.country &&
        req.body.googleMap
    ) {
        const emailCheck = await checkEmail(req.body.email).catch((err) => {
            bcrypt.hash(
                req.body.password,
                saltRounds,
                async (errHash, hash) => {
                    if (errHash) {
                        return res.send({
                            status: 401,
                            message: "Cannot hash password",
                        });
                    }
                    let hotelInfo = req.body;
                    hotelInfo.password = hash;
                    const { error } = await supabase
                        .from("hotels")
                        .insert(hotelInfo);
                    if (error) {
                        return res.send({
                            status: 401,
                            message: "Cannot create hotel",
                        });
                    } else {
                        const newCheck = await checkEmail(hotelInfo.email);
                        delete newCheck["password"];
                        let payload = newCheck.data;

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
                            message: "New Hotel account created",
                            accessToken: accessToken,
                            refreshToken: refreshToken,
                        });
                    }
                }
            );
        });
        if (emailCheck) {
            return res.send({ status: 401, message: emailCheck.message });
        }
    } else return res.send({ status: 401, message: "Invalid request body" });
});

module.exports = router;
