let express = require('express');
let router = express.Router();
let userController = require('../controllers/users');
let bcrypt = require('bcrypt');
let { generateToken, authenticateToken } = require('../utils/authHandler');
let { validatedResult, ChangePasswordValidator } = require('../utils/validator');

router.post('/register', async function (req, res, next) {
    try {
        let { username, password, email } = req.body;
        if (!username || !password || !email) {
            throw new Error("Missing username, password or email in request body");
        }
        let newUser = await userController.CreateAnUser(username, password, email,
            "69b1265c33c5468d1c85aad8"
        );
        res.send(newUser);
    } catch (error) {
        res.status(404).send({
            message: error.message
        });
    }
});

router.post('/login', async function (req, res, next) {
    try {
        let { username, password } = req.body;
        let user = await userController.GetAnUserByUsername(username);
        if (!user) {
            return res.status(404).send({
                message: "thong tin dang nhap khong dung"
            });
        }
        if (user.lockTime > Date.now()) {
            return res.status(404).send({
                message: "ban dang bi ban"
            });
        }
        if (bcrypt.compareSync(password, user.password)) {
            user.loginCount = 0;
            await user.save();

            let token = generateToken({
                id: user._id,
                username: user.username,
                role: user.role
            });

            res.send({
                id: user._id,
                token: token
            });
        } else {
            user.loginCount++;
            if (user.loginCount == 3) {
                user.loginCount = 0;
                user.lockTime = Date.now() + 3600 * 1000;
            }
            await user.save();
            res.status(404).send({
                message: "thong tin dang nhap khong dung"
            });
        }
    } catch (error) {
        res.status(404).send({
            message: error.message
        });
    }
});

router.get('/me', authenticateToken, async function (req, res, next) {
    try {
        let user = await userController.GetAnUserById(req.user.id);
        if (!user) {
            return res.status(404).send({ message: "Nguoi dung khong ton tai" });
        }
        res.send(user);
    } catch (error) {
        res.status(500).send({ message: error.message });
    }
});

router.put('/change-password', authenticateToken, ChangePasswordValidator, validatedResult,
    async function (req, res, next) {
        try {
            let { oldPassword, newPassword } = req.body;
            let result = await userController.ChangePassword(req.user.id, oldPassword, newPassword);
            res.send(result);
        } catch (error) {
            res.status(400).send({
                message: error.message
            });
        }
    }
);

module.exports = router;