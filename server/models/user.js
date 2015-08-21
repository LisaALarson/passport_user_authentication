var mongoose = require('mongoose'),
    Schema = mongoose.Schema,
    bcrypt = require('bcrypt'),
    //bcrypt uses a “key setup phase” that makes computing passwords computationally expensive. Computing one with known salts is easy, but computing many is hard, which is actually a good thing when trying to thwart brute-force attacks.
    SALT_WORK_FACTOR = 10;
    //The purpose of the salt is to defeat rainbow table attacks and to resist brute-force attacks in the event that someone has gained access to your database.

var UserSchema = new Schema({
    username: {type: String, required: true, index: {unique: true}},
    password: {type: String, required: true}
});

UserSchema.pre('save', function(next){
    var user = this;

    //only hash the password if it has been modified (or is new)
    if(!user.isModified('password'))return next();

    //generate a SALT
    bcrypt.genSalt(SALT_WORK_FACTOR, function(err, salt){
        if(err)return next(err);

        //hash the password along with our new salt
        bcrypt.hash(user.password, salt, function(err, hash){
            if(err) return next(err);

            //override the cleartext password with the hashed one
            user.password = hash;
            next();
        });
    });
});

//this is a convenience method for comparing passwords later on
UserSchema.methods.comparePassword = function(candidatePassword, cb){
    bcrypt.compare(candidatePassword, this.password, function(err, isMatch){
        if(err) return cb(err);
        cb(null, isMatch);
    });
};

module.exports = mongoose.model('User', UserSchema);