const express = require("express");
const router = express.Router();
const { createClient } = require("@supabase/supabase-js");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const jwt_decode = require("jwt-decode");
require("dotenv").config();
const supabase = createClient(process.env.URL, process.env.API_KEY);
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
            const emailCheck = await checkEmail(decoded.email);
            resolve(emailCheck);
        });
    });
}

router.post("/report", async (req, res) => {
    if (req.body.token) {
        const accountCheck = await authToken(req.body.token).catch((err) => {
            return res.send(err);
        });
        if (accountCheck.status == 200) {
            console.log(req.body);
            const { error } = await supabase.from("reports").insert({
                user_id: req.body.user_id,
                review_id: req.body.review_id,
            });
            if (error) {
                return res.send({
                    status: 401,
                    message: error,
                });
            }
            return res.send({
                status: 200,
                message: "Successfully reported a review",
            });
        }
    } else return res.send({ status: 401, message: "Unauthorized Access" });
});

router.post("/searchHotels", async (req, res) => {
    if (req.body.token) {
        const accountCheck = await authToken(req.body.token).catch((err) => {
            return res.send(err);
        });
        if (accountCheck.status == 200) {
            console.log(req.body);
            const hotelsData = await supabase
                .from("hotels")
                .select("id,images,name,country,description,benefits,ratings")
                .eq("country", req.body.country);
            if (hotelsData.error) {
                return res.send({
                    status: 401,
                    message: hotelsData.error,
                });
            }
            return res.send({
                status: 200,
                message: "Successfully search hotels",
                data: hotelsData.data,
            });
        }
    } else return res.send({ status: 401, message: "Unauthorized Access" });
});

router.post("/update", async (req, res) => {
    if (req.body.token) {
        const accountCheck = await authToken(req.body.token).catch((err) => {
            return res.send(err);
        });
        if (accountCheck.status == 200) {
            const { error } = await supabase
                .from("users")
                .update({
                    username: req.body.username,
                    bio: req.body.bio,
                    profile_pic: req.body.profile_pic,
                })
                .eq("id", req.body.user_id);
            if (error) {
                return res.send({
                    status: 401,
                    message: error,
                });
            }
            return res.send({
                status: 200,
                message: "Successfully updated user",
            });
        }
    } else return res.send({ status: 401, message: "Unauthorized Access" });
});

router.post("/review", async (req, res) => {
    if (req.body.token) {
        const accountCheck = await authToken(req.body.token).catch((err) => {
            return res.send(err);
        });
        if (accountCheck.status == 200) {
            const reviewsData = await supabase.from("reviews").insert({
                hotel_id: req.body.hotel_id,
                user_id: req.body.user_id,
                feedback: req.body.feedback,
                ratings: req.body.ratings,
            });
            if (reviewsData.error) {
                return res.send({
                    status: 401,
                    message: reviewsData.error,
                });
            }
            const totalReviews = await supabase
                .from("reviews")
                .select("ratings")
                .eq("hotel_id", req.body.hotel_id);
            if (totalReviews.error) {
                return res.send({ status: 401, message: totalReviews.error });
            } else {
                let totalCount = 0;
                let totalStars = 0;
                totalReviews.data.forEach((review) => {
                    totalCount++;
                    totalStars += review.ratings;
                });
                let finalRatings =
                    Math.round((totalStars / totalCount) * 10) / 10;
                const { error } = await supabase
                    .from("hotels")
                    .update({ ratings: finalRatings })
                    .eq("id", req.body.hotel_id);
                if (error) {
                    return res.send({
                        status: 401,
                        message: error,
                    });
                }
                return res.send({
                    status: 200,
                    message: "Successfully create a review",
                });
            }
        }
    } else return res.send({ status: 401, message: "Unauthorized Access" });
});

router.post("/getInfo", async (req, res) => {
    if (req.body.token) {
        const accountCheck = await authToken(req.body.token).catch((err) => {
            return res.send(err);
        });
        if (accountCheck.status == 200) {
            const reviewsData = await supabase
                .from("reviews")
                .select("hotel_id(name,images, id), *")
                .order("created_at", { ascending: false })
                .eq("user_id", req.body.user_id);
            if (reviewsData.error) {
                return res.send({ status: 401, message: reviewsData.error });
            }
            const bookingsData = await supabase
                .from("bookings")
                .select(
                    "room_id (number), hotel_id(name,images, id, country),*"
                )
                .order("created_at", { ascending: false })
                .eq("user_id", req.body.user_id);
            if (bookingsData.error) {
                return res.send({ status: 401, message: bookingsData.error });
            }
            return res.send({
                status: 200,
                message: "Successfully get hotel reviews",
                reviewsData: reviewsData.data,
                bookingsData: bookingsData.data,
            });
        }
    } else return res.send({ status: 401, message: "Unauthorized Access" });
});

router.post("/getHotelReviews", async (req, res) => {
    if (req.body.token) {
        const accountCheck = await authToken(req.body.token).catch((err) => {
            return res.send(err);
        });
        if (accountCheck.status == 200) {
            const reviewsData = await supabase
                .from("reviews")
                .select("user_id (profile_pic, id, username), *")
                .order("created_at", { ascending: false })
                .eq("hotel_id", req.body.hotel_id);
            if (reviewsData.error) {
                return res.send({ status: 401, message: reviewsData.error });
            }
            return res.send({
                status: 200,
                message: "Successfully get hotel reviews",
                data: reviewsData.data,
            });
        }
    } else return res.send({ status: 401, message: "Unauthorized Access" });
});

router.post("/bookRoom", async (req, res) => {
    if (req.body.token) {
        const accountCheck = await authToken(req.body.token).catch((err) => {
            return res.send(err);
        });
        if (accountCheck.status == 200) {
            const roomsData = await supabase
                .from("rooms")
                .update({
                    availability: 0,
                })
                .eq("id", req.body.room_id);
            if (roomsData.error) {
                return res.send({ status: 401, message: "Cannot update room" });
            }

            const bookingsData = await supabase.from("bookings").insert({
                hotel_id: req.body.hotel_id,
                user_id: req.body.user_id,
                days: req.body.days,
                room_id: req.body.room_id,
                total_cost: req.body.total_cost,
            });
            if (bookingsData.error) {
                return res.send({
                    status: 401,
                    message: "Cannot create booking",
                });
            }

            return res.send({
                status: 200,
                message: "Successfully book a room",
            });
        }
    } else return res.send({ status: 401, message: "Unauthorized Access" });
});

router.post("/getHotelInfo", async (req, res) => {
    if (req.body.token) {
        const accountCheck = await authToken(req.body.token).catch((err) => {
            return res.send(err);
        });
        if (accountCheck.status == 200) {
            const hotelData = await supabase
                .from("hotels")
                .select()
                .eq("id", req.body.hotel_id);
            if (hotelData.error) {
                return res.send({
                    status: 401,
                    message: "Hotel does not exist",
                });
            }
            delete hotelData.data[0]["password"];
            const roomsData = await supabase
                .from("rooms")
                .select()
                .order("created_at", { ascending: true })
                .eq("hotel_id", req.body.hotel_id)
                .lte("availability", 1);

            const reviewsData = await supabase
                .from("reviews")
                .select()
                .eq("hotel_id", req.body.hotel_id);

            return res.send({
                status: 200,
                message: "Successfully get hotel info",
                hotelData: hotelData.data[0],
                roomsData: roomsData.data,
                reviewsData: reviewsData.data,
            });
        }
    } else return res.send({ status: 401, message: "Unauthorized Access" });
});

router.post("/getHotels", async (req, res) => {
    if (req.body.token) {
        const accountCheck = await authToken(req.body.token).catch((err) => {
            return res.send(err);
        });
        if (accountCheck.status == 200) {
            const { data } = await supabase
                .from("hotels")
                .select("id, name, country, ratings, images")
                .order("created_at", { ascending: true });
            res.send({
                status: 200,
                message: "Successfully get all hotels",
                data: data,
            });
        }
    } else return res.send({ status: 401, message: "Unauthorized Access" });
});

router.post("/signUp", async (req, res) => {
    console.log("Request received on SignUp");
    if (
        req.body.email &&
        req.body.password &&
        req.body.username &&
        req.body.profile_pic &&
        req.body.bio
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
                    let userInfo = req.body;
                    userInfo.password = hash;
                    const { error } = await supabase
                        .from("users")
                        .insert(userInfo);
                    if (error) {
                        return res.send({
                            status: 401,
                            message: "Cannot create account",
                        });
                    } else {
                        const newCheck = await checkEmail(userInfo.email);
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
                            message: "New user account created",
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
