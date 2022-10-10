const AppError = require('./../utils/appError');
const User = require('./../models/userModel');

const filter = function(rawObject, ...allowObject) {
    const newObject = {};
    Object.keys(rawObject).forEach((key, value) => {
        if (allowObject.includes(key)) {
            newObject[key] = rawObject[key];
        }
    });
    
    return newObject;
}

exports.updateAccount = async (req, res, next) => {
    try {
        const filtered = filter(req.body, 'name', 'email');
        const user = await User.findByIdAndUpdate(req.user._id, filtered, {
            new: true,
            runValidators: true
        });
    
        res.status(200).json({
            status: 'success',
            filtered
        });

    } catch (err) {
        return next(new AppError(err, 400));
    }
}

exports.deleteAccount = async (req, res, next) => {
    try {
        const user = await User.findByIdAndUpdate(req.user._id, { active: false }, { new: true});

        res.status(200).json({
            status: 'success',
            user
        });

    } catch (err) {
        return next(new AppError(err, 400));
    }
}