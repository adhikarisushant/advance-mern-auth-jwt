const crypto = require("crypto");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

var validatePassword = function(password) {
  var re = /^(?=.*[0-9])(?=.*[a-zA-Z])(?=.*[!@#$%^&*])[a-zA-Z0-9!@#$%^&*]{8,20}$/;
  return re.test(password)
};

var validateEmail = function(email) {
  var re = /^(([^<>()[\]\\.,;:\s@"]+(\.[^<>()[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/;
  return re.test(email)
};

var validateUsername = function(username) {
  var re = /^[A-Za-z0-9]{3,16}$/;
  return re.test(username)
};

const UserSchema = new mongoose.Schema({
  username: {
    type: String,
    required: [true, "Please provide username"],
    validate: [validateUsername, 'Username should be 3-16 characters and should not include any special character'],
    match: [
      /^[A-Za-z0-9]{3,16}$/,
      'Username should be 3-16 characters and should not include any special character',
    ],
  },
  email: {
    type: String,
    required: [true, "Please provide email address"],
    unique: true,
    validate: [validateEmail, 'Please provide a valid email'],
    match: [
      /^(([^<>()[\]\\.,;:\s@"]+(\.[^<>()[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/,
      'Please provide a valid email',
    ],
  },
  password: {
    type: String,
    required: [true, "Please add a password"],
    validate: [validatePassword, 'Password should be 8-20 characters and include at least 1 letter, 1 number and 1 special character'],
    match: [/^(?=.*[0-9])(?=.*[a-zA-Z])(?=.*[!@#$%^&*])[a-zA-Z0-9!@#$%^&*]{8,20}$/, 'Password should be 8-20 characters and include at least 1 letter, 1 number and 1 special character'],
    select: false,
  },
  resetPasswordToken: String,
  resetPasswordExpire: Date,
});

UserSchema.pre("save", async function (next) {
  if (!this.isModified("password")) {
    next();
  }

  const salt = await bcrypt.genSalt(10);
  this.password = await bcrypt.hash(this.password, salt);
  next();
});

UserSchema.methods.matchPassword = async function (password) {
  return await bcrypt.compare(password, this.password);
};

UserSchema.methods.getSignedJwtToken = function () {
  return jwt.sign({ id: this._id }, process.env.JWT_SECRET, {
    expiresIn: process.env.JWT_EXPIRE,
  });
};

UserSchema.methods.getResetPasswordToken = function () {
  const resetToken = crypto.randomBytes(20).toString("hex");

  // Hash token (private key) and save to database
  this.resetPasswordToken = crypto
    .createHash("sha256")
    .update(resetToken)
    .digest("hex");

  // Set token expire date
  this.resetPasswordExpire = Date.now() + 10 * (60 * 1000); // Ten Minutes

  return resetToken;
};

const User = mongoose.model("User", UserSchema);

module.exports = User;
