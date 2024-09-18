const jwt = require("jsonwebtoken");
const pool = require('../db');
const bcrypt = require('bcrypt');
const saltRounds = 10; 

function generateAccessToken(user) {
    const token = jwt.sign(user, process.env.JWT_SECRET, { algorithm: "HS256" });
    return token;
}

const userController = {
    async userLogin (req, res, next) {
        try {
            const { username, password } = req.body;

            const userQuery = 'SELECT * FROM "User" WHERE username = $1';
            const userResult = await pool.query(userQuery, [username]);

            if (userResult.rows.length === 0) {
                return res.status(404).json("User not found");
            }

            const user = userResult.rows[0];

            const isMatch = await bcrypt.compare(password, user.password);
            if (!isMatch) {
                return res.status(401).json("Wrong password");
            }

            const jwtToken = generateAccessToken({ id: user.user_id });

            res.cookie('jwtToken', jwtToken, {
                httpOnly: true,
                maxAge: 3600000,
            });
            
            res.status(200).json({ user, jwtToken });
        } catch (err) {
            return next({
                log: `userController error from userLogin ${err}`,
                status: 500,
                message: { err: "An error occurred while logging in the user" },
              });
        }
    },

    async userRegister (req, res, next) {
        try {
            const { username, password, email, address, payment_info } = req.body;
            const rental_ids = '{}';
            const booking_ids = '{}';

            // check for duplicate user
            const dupeUserQuery = 'SELECT * FROM "User" WHERE username = $1';
            const dupeUserResult = await pool.query(dupeUserQuery, [username]);
            // console.log('Check if user exists:', dupeUserResult);

            if (dupeUserResult.rows.length > 0) {
                return res.status(409).json("duplicate user");
            }

            const hashedPassword = await bcrypt.hash(password, saltRounds);

            const result = await pool.query(
                'INSERT INTO "User" (username, password, email, address, payment_info, rental_ids, booking_ids) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING *',
                [username, hashedPassword, email, address, payment_info, rental_ids, booking_ids]
            );

            const user = result.rows[0];
            console.log('Creation succussful', user);
            
            const jwtToken = generateAccessToken({ id: user.user_id });

            res.cookie('jwtToken', jwtToken, {
                httpOnly: true,
                maxAge: 3600000,
            });

            if(user) {
                res.status(200).json({ user, jwtToken });
            } else {
                res.status(404).json({ message: "User could not be created" });
            }
        } catch (err) {
            return next({
                log: `userController error from userRegister ${err}`,
                status: 500,
                message: { err: 'An error occured while registering user'},
            })
        }
    }
}

module.exports = userController;