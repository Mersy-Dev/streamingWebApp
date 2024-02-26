const User = require('../models/userModel');
const jwt = require('jsonwebtoken');
const asyncHandler = require('express-async-handler');



const authMiddleware = asyncHandler(async (req, res, next) => {
    let token;
    if(req.headers.authorization && req.headers.authorization.startsWith('Bearer')){
        try{
            token = req.headers.authorization.split(" ")[1];
            const decoded = jwt.verify(token, process.env.JWT_SECRET);
            const user = await User.findById(decoded.id).select('-password');
            req.user = user;
            next();
        }catch(error){
            console.error(error);
            res.status(401);
            throw new Error('Not authorized, token failed');
        }
    }
    if(!token){
        res.status(401);
        throw new Error('Not authorized, no token');
    }
});


module.exports = { authMiddleware } ;

