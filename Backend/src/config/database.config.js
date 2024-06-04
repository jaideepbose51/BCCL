import mongoose from 'mongoose';
import dotenv from 'dotenv';

dotenv.config();

const dbconnect = async () => {
    try {
        await mongoose.connect(process.env.MONGODB_URI, {
            useNewUrlParser: true,
            useUnifiedTopology: true,
            serverSelectionTimeoutMS: 50000, // Adjust the timeout as needed
        });
        console.log('Database connected!');
    } catch (err) {
        console.log(err);
    }
};

export { dbconnect };