const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { PrismaClient } = require('@prisma/client');
const prisma = new PrismaClient();

const router = express.Router();

const secret = process.env.JWT_SECRET_KEY

router.post('/register', async (req, res) => {
    const { username, password } = req.body
    const passwordHash = await bcrypt.hash(password, 8)
    const user = await prisma.user.create({
        data: {
            username: username,
            password: passwordHash
        }
    })

    res.status(201).json({
        user
    })
});

router.post('/login', async (req, res) => {
    const { username, password } = req.body
    const user = await prisma.user.findUnique({
        where: {
            username: username
        }
    })

    if (user) {
        const match = await bcrypt.compare(password, user.password)

        if (!match) {
            res.status(401).json({
                error: "The password provided doesn't match"
            })
        }

        const token = jwt.sign({ "username": username }, secret)

        res.status(201).json({
            token
        })
    } else {
        res.status(401).json({
            error: "The username provided doesn't exist"
        })
    }
});

module.exports = router;
