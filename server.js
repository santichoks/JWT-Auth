const AppError = require('./utils/appError');
const mongoose = require('mongoose');
const morgan = require('morgan');
const express = require('express');
const dotenv = require('dotenv');

const globalErrorHandler = require('./controllers/errorController');
const userRouter = require('./routes/userRoutes');

dotenv.config({ path: './.env' });

const app = express();

const DB = process.env.DATABASE.replace(
    '<PASSWORD>',
    process.env.DATABASE_PASSWORD
);

mongoose.connect(DB, {
    useNewUrlParser: true
}).then(() => console.log('Database connection successful!'));

// Development logging
if (process.env.NODE_ENV === 'development') {
    app.use(morgan('dev'));
}

// Body parser, reading data from body into req.body
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: true, limit: '10kb' }))

// Routes
app.use('/api/v1/users', userRouter);

app.all('*', (req, res, next) => {
    next(new AppError(`Can't find ${req.originalUrl} on this server!`, 404));
});

app.use(globalErrorHandler);

const port = process.env.PORT;
app.listen(port, () => {
    console.log(`Server running on port ${port}...`);
});
