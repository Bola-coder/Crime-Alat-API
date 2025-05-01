const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const userSchema = mongoose.Schema({
  firstname: {
    type: String,
    required: [true, "Please provide your firstname"],
    trim: true,
  },
  lastname: {
    type: String,
    required: [true, "Please provide your lastname"],
    trim: true,
  },
  email: {
    type: String,
    unique: [true, "Email aleady in use"],
    required: [true, "Please provide an email address"],
    trim: true,
  },
  password: {
    type: String,
    required: [true, "Please provide a password"],
    minLength: [8, "Your password should be a minimum of 8 characters"],
    select: false,
  },
  phoneNumber: {
    type: String,
    unique: [true, "Phone number already in use"],
    required: [true, "Please provide your phone number"],
  },
  role: {
    type: String,
    enum: ["user", "admin", "superadmin"],
    default: "user",
  },
  permissions: {
    type: [String],
    default: [],
  },
  profileImage: {
    type: String,
  },
  passwordChangedAt: {
    type: Date,
  },
  emailVerified: {
    type: Boolean,
    default: false,
  },
  verificationToken: {
    type: String,
    select: false,
  },
  verificationTokenExpires: {
    type: Date,
    select: false,
  },
  active: {
    type: Boolean,
    default: true,
  },
});

// A database middleware to hash the password before saving to the database;
userSchema.pre("save", async function (next) {
  if (!this.isModified("password")) return next();
  const salt = await bcrypt.genSalt(12);
  this.password = await bcrypt.hash(this.password, salt);
  next();
});

// Hook to check if password has been modifeid and then give a value to passwordChangedAt
userSchema.pre("save", async function (next) {
  if (!this.isModified("password") || this.isNew) {
    return next();
  }
  this.passwordChangedAt = Date.now - 2000;
});

// Creating an instance method to compare password entered by user to the one in the database during login
userSchema.methods.confirmPassword = async function (
  enteredPassword,
  userPassword
) {
  return await bcrypt.compare(enteredPassword, userPassword);
};

// Creating an instance method to check if the password has been changed after token has been issued
userSchema.methods.passwordChangedAfterTokenIssued = async function (
  JWTTimestamp
) {
  if (this.passwordChangedAt) {
    const changedTimestamp = parseInt(
      this.passwordChangedAt.getTime() / 100,
      10
    );
    return JWTTimestamp < changedTimestamp;
  }
  return false;
};

const Users = mongoose.model("Users", userSchema);

module.exports = Users;
