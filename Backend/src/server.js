import dotenv from 'dotenv';
dotenv.config();

import express from "express";
import path, { dirname } from 'path';
import { fileURLToPath } from 'url';
import userRouter from './routers/user.router.js';
import { dbconnect } from './config/database.config.js';
import morgan from 'morgan';


const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const app = express();
dbconnect();
app.use(express.json());

app.use(morgan());

app.use('/api/users', userRouter);

app.get('*', (req, res) => {
    console.log("i dont know what has happened");
    res.status(200).send('Catch-all route');
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, (err) => {
    if (err) throw err;
    console.log('Server is running on port ' + PORT);
});