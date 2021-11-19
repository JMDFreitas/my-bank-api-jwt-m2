import express from "express";
import winston from "winston";
import accountsRouter from "./routes/account.routes.js"
import usersRouter from "./routes/user.routes.js"
import { promises as fs } from "fs";
import cors from "cors";
import swaggerUi from "swagger-ui-express";
import { swaggerDocument } from "./doc.js"
import jwt from 'jsonwebtoken';

const { readFile, writeFile } = fs;

global.fileName = "accounts.json";

const { combine, timestamp, label, printf } = winston.format;
const myFormat = printf(({ level, message, label, timestamp }) => {
    return `${timestamp} [${label}] ${level}: ${message}`;
});
global.logger = winston.createLogger({
    level: "silly",
    transports: [
        new (winston.transports.Console)(),
        new (winston.transports.File)({ filename: "my-bank-api.log" })
    ],
    format: combine(
        label({ label: "my-bank-api" }),
        timestamp(),
        myFormat
    )
});

const app = express();
app.use(express.json());
app.use(cors());
app.use(express.static("public"));
app.use("/doc", swaggerUi.serve, swaggerUi.setup(swaggerDocument));

function authorize(...allowed) {

    const isAllowed = role => allowed.indexOf(role) > -1;

    return async (req, res, next) => {

        var authHeader = req.headers['authorization'];

        if (!authHeader || !authHeader.startsWith("Bearer ")) {
            res.status(401).json({ message: "Denied Access" });
            return;
        }

        const jwtToken = authHeader.substring(7, authHeader.length);

        const publicKey = await readFile('./security/public.key', 'utf-8')

        jwt.verify(jwtToken, publicKey, { algorithms: ['RS256'] }, function (err, decoded) {
            if (err) {
                res.status(401).json({ message: "Invalid token" });
                return;
            }

            if (isAllowed(decoded.role)) {
                next()
            } else {
                res.status(403).json({ message: "Denied" });
            }
        })
    }
}

app.use("/user", usersRouter);
app.use("/account", authorize('admin', 'role1'), accountsRouter);

app.listen(3000, async () => {
    try {
        await readFile(global.fileName);
        logger.info("API Started!");
    } catch (err) {
        const initialJson = {
            nextId: 1,
            accounts: []
        }
        writeFile(global.fileName, JSON.stringify(initialJson)).then(() => {
            logger.info("API Started and File Created!");
        }).catch(err2 => {
            logger.error(err2);
        });
    }
});