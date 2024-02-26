const mongoose = require('mongoose');
const bcrypt = require('bcryptjs'); 
const crypto = require('crypto');


const userSchema = new mongoose.Schema({
    firstName: {
        type: String,
        required: true,
        trim: true,
        min: 3,
        max: 20
    },
    lastName: {
        type: String,
        required: true,
        trim: true,
        min: 3,
        max: 20
    },
    email: {
        type: String,
        required: true,
        trim: true,
        unique: true,
        lowercase: true
    },
    mobile:{
        type: String,
        required: true,
        trim: true,
        unique: true,
        lowercase: true
    },
    password: {
        type: String,
        required: true,
    },
    address:{
        type:String,
    },
    refreshToken: {
        type: String,
    }, 
    passwordChangedAt: {
        type: Date,
        default: Date.now()
    
    },
    passwordResetToken: {
        type: String
    
    },
    passwordResetExpires: {
        type: Date
   },
},
{
    timestamps: true
});



userSchema.pre('save', async function(next){
    if(!this.isModified('password')) {
        next();
    }
    const salt = await bcrypt.genSaltSync(10);
    this.password = await bcrypt.hashSync(this.password, salt);
    next();
});

userSchema.methods.isPasswordMatched = async function(enteredPassword){
    return await bcrypt.compareSync(enteredPassword, this.password);
}

userSchema.methods.createPasswordResetToken = async function(){
    const resetToken =  crypto.randomBytes(32).toString('hex');
    this.passwordResetToken = crypto.createHash('sha256').update(resetToken).digest('hex');
    this.passwordResetExpires =  Date.now() + 30 * 60 * 1000;
    return resetToken; 
}

module.exports = mongoose.model('User', userSchema);