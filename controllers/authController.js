const AppError = require('./../utils/appError');
const crypto = require('crypto');
const User = require('./../models/userModel');
const jwt = require('jsonwebtoken');

const signToken = id => {
    return jwt.sign({ id }, process.env.JWT_SECRET, {
      expiresIn: process.env.JWT_EXPIRES_IN
    });
};

const createSendToken = (user, statusCode, res) => {
    const token = signToken(user._id);
    const cookieOptions = {
        expires: new Date(
        Date.now() + process.env.JWT_COOKIE_EXPIRES_IN * 24 * 60 * 60 * 1000),
        httpOnly: true
    };

    if (process.env.NODE_ENV === 'production') cookieOptions.secure = true;

    res.cookie('jwt', token, cookieOptions);

    user.password = undefined;
    res.status(statusCode).json({
        status: 'success',
        token,
        data: {
            user
        }
    });
};

exports.signup = async (req, res, next) => {
    try {
        const { name, email, password, passwordConfirm } = req.body
        const newUser = await User.create({
            name,
            email,
            password,
            passwordConfirm
        });
        createSendToken(newUser, 201, res);

    } catch (err) {
        return next(new AppError(err, 400));
    }  
}

exports.login = async (req, res, next) => {
    try {
        const { email, password } = req.body;

        // Check if email and password exist
        if (!email || !password) {
            return next(new AppError('Please provide email and password!', 400));
        }
        
        // Check if user exists && password is correct
        const user = await User.findOne({ email }).select('+password');
    
        if (!user || !(await user.correctPassword(password, user.password))) {
            return next(new AppError('Incorrect email or password', 401));
        }
        
        // If everything ok, send token to client
        createSendToken(user, 200, res);
        
    } catch (err) {
        return next(new AppError(err, 400));
    }
}

exports.logout = (req, res) => {
    try {
        res.cookie('jwt', null, {
            expires: new Date(
                Date.now() + 10 * 1000),
            httpOnly: true
        });
        
        res.status(200).json({ status: 'success' });

    } catch (err) {
        return next(new AppError(err, 400));
    }
}

exports.protect = async (req, res, next) => {
    try {
        // Getting token and check of it's there
        let token
        if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
            token = req.headers.authorization.split(' ')[1];
        }
        else if (req.cookie.jwt) {
            token = req.cookie.jwt;
        }
        
        if (!token) {
            return next(new AppError('You are not logged in! Please log in to get access.', 401));
        }
        
        // Verification token
        const decoded = await jwt.verify(token, process.env.JWT_SECRET);
        
        // Check if user still exists
        const currentUser = await User.findById(decoded.id);
        
        if (!currentUser) {
            return next(new AppError('The user belonging to this token does no longer exist.', 401));
        }

        // Check if user changed password after the token was issued
        if (currentUser.changedPasswordAfter(decoded.iat)) {
            return next(new AppError('User recently changed password! Please log in again.', 401));
        }

        // Grant access to protected route
        req.user = currentUser;
        next();

    } catch (err) {
        next(new AppError(err, 401));
    }
}

exports.permission = (...roles) => {
    try {
        return (req, res, next) => {
            if (roles.includes(req.user.role)) {
                return next(new AppError('You do not have permission to perform this action', 403));
            }
           
            next();
        };
    }
    catch (err) {
        return next(new AppError(err, 403));
    }
}

exports.forgotPassword = async (req, res, next) => {
    try {
        // Get user based on email
        const user = await User.findOne({ email: req.body.email });
        if (!user) {
            return next(new AppError('There is no user with email address', 404));
        }
        
        // Generate the random reset token
        const resetToken = user.createPasswordResetToken();
        await user.save({ validateBeforeSave: false });

        // Send to user email
        res.status(200).json({
            status: 'success',
            message: user,
            resetToken
        });

    } catch (err) {
        return next(new AppError(err, 400));
    }

}

exports.resetPassword = async (req, res, next) => {
    try {
        // Get user based on the token
        const hashedToken = crypto
            .createHash('sha256')
            .update(req.params.token)
            .digest('hex');

        const user = await User.findOne({ passwordResetToken: hashedToken, passwordResetExpires: { $gt: Date.now() }});

        // If token has not expired, and there is user, set the new password
        if (!user) {
            return next(new AppError('Token is invalid or has expired', 400));
        }

        user.password = req.body.password;
        user.passwordConfirm = req.body.passwordConfirm;
        user.passwordResetToken = undefined;
        user.passwordResetExpires = undefined;
        await user.save();

        // Update changedPasswordAt property for the user
        // Log the user in, send JWT
        createSendToken(user, 200, res);     

    } catch (err) {
        return next(new AppError(err, 400));
    }
}

exports.updatePassword = async (req, res, next) => {
    try {
        // Get user from collection
        const user = await User.findById(req.user._id).select('+password');

        // Check if current password is correct
        if (!(await user.correctPassword(req.body.passwordCurrent, user.password))) {
            return next(new AppError('Your current password is wrong.', 401));
        }

        if (req.body.passwordCurrent === req.body.password) {
            return next(new AppError('New password cannot be the same as your old password', 401));
        }

        // Update password
        user.password = req.body.password;
        user.passwordConfirm = req.body.passwordConfirm;
        // If we use findByIdAndUpdate() the Validation and pre Middleware is not works !!!
        await user.save();

        // Log user in, send JWT
        createSendToken(user, 200, res);
    } catch (err) {
        return next(new AppError(err, 400));
    }
}