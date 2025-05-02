const {
  createNewUser,
  getUserByEmail,
  updateUserById,
} = require("../repositories/user");
const {
  validateUserLogin,
  validateUserSignup,
} = require("../validations/user");
const { signJWTToken } = require("../utils/jwt");
const catchAsync = require("../utils/catchAsync");
const AppError = require("../utils/AppError");
const { isVerificationCodeValid } = require("../utils/token");
const {
  createVerificationTokenAndSendToEmail,
} = require("../utils/createVerificationToken");

// Signup function
const signup = catchAsync(async (req, res, next) => {
  const { firstname, lastname, phoneNumber, email, password } = req.body;

  const validation = validateUserSignup({
    firstname,
    lastname,
    email,
    password,
    phoneNumber,
  });
  if (validation.error)
    return next(new AppError(validation.error.message, 400));

  const existingUser = await getUserByEmail(email);
  if (existingUser) {
    if (!existingUser.emailVerified) {
      return next(
        new AppError(
          "Email already registered but not verified. Please verify your email or resend verification code.",
          409
        )
      );
    }

    return next(
      new AppError("User with the specified email already exists", 400)
    );
  }

  const newUser = await createNewUser({
    firstname,
    lastname,
    phoneNumber,
    email,
    password,
    role: "user",
  });

  if (!newUser) {
    return next(new AppError("Failed to create new user", 500));
  }

  // Generate 6-digit code, hash it, email it, and store the hash
  const hashedCode = await createVerificationTokenAndSendToEmail(newUser.email);

  const user = await updateUserById(newUser._id, {
    verificationToken: hashedCode,
    verificationTokenExpires: Date.now() + 10 * 60 * 1000,
  });

  const token = signJWTToken(user._id);
  res.status(201).json({
    status: "success",
    data: { user, token },
  });
});

// Login function
const login = catchAsync(async (req, res, next) => {
  const { email, password } = req.body;

  // Validating the request body
  const validation = validateUserLogin({ email, password });
  if (validation.error) {
    return next(new AppError(validation.error.message, 404));
  }

  // Fetching user from db based on email
  const user = await getUserByEmail(email).select("+password");
  // console.log(user);

  //   Checking if user exist and if password is the same with the hashed one
  if (!user || !(await user.confirmPassword(password, user.password))) {
    console.log("Can it be this?");
    return next(new AppError("Invalid email or password!"));
  }

  const token = signJWTToken(user._id);
  res.status(200).json({
    status: "success",
    data: { user, token },
  });
});

// Resend Verification email
const resendEmailVerificationToken = catchAsync(async (req, res, next) => {
  const { email } = req.body;
  const user = await getUserByEmail(email).select("+verificationToken");

  if (!user) {
    return next(
      new AppError("User with the specified email does not exist", 404)
    );
  }

  if (user.emailVerified) {
    return next(new AppError("User has already been verified", 400));
  }

  const hashedCode = await createVerificationTokenAndSendToEmail(newUser.email);

  await updateUserById(user._id, {
    verificationToken: hashedCode,
    verificationTokenExpires: Date.now() + 10 * 60 * 1000,
  });

  res.status(200).json({
    status: "success",
    message: "Verification code resent to your email address",
  });
});

// Verify User Email
const verifyUserEmail = catchAsync(async (req, res, next) => {
  const { email, verification_code } = req.body;

  const user = await getUserByEmail(email).select(
    "+verificationToken +verificationTokenExpires"
  );

  if (!user) {
    return next(
      new AppError("User with the specified email does not exist", 404)
    );
  }

  if (user.emailVerified) {
    return next(new AppError("User has already been verified", 400));
  }

  if (Date.now() > user.verificationTokenExpires) {
    return next(new AppError("Verification code has expired", 400));
  }

  const isValidCode = await isVerificationCodeValid(
    verification_code,
    user.verificationToken
  );
  if (!isValidCode) {
    return next(new AppError("Invalid verification code", 400));
  }

  const verifiedUser = await updateUserById(user._id, {
    emailVerified: true,
    verificationToken: null,
    verificationTokenExpires: null,
  });

  res.status(200).json({
    status: "success",
    message: "Email verified successfully",
    user: verifiedUser,
  });
});

// Check auth status
const checkAuthStatus = catchAsync(async (req, res, next) => {
  return res.status(200).json({
    status: "success",
    message: "User is authenticated",
    user: req.user,
  });
});

// Logout function
const logout = async (req, res) => {
  res
    .clearCookie("token")
    .status(200)
    .json({ message: "Successfully logged out " });
};

module.exports = {
  signup,
  login,
  resendEmailVerificationToken,
  verifyUserEmail,
  checkAuthStatus,
  logout,
};
