const { promisify } = require("util");
const jwt = require("jsonwebtoken");
const { getUserById } = require("../repositories/user");
const catchAsync = require("../utils/catchAsync");
const AppError = require("../utils/AppError");

// Protect route from unauthorised users function
const protectRoute = catchAsync(async (req, res, next) => {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) {
    return next(
      new AppError(
        "You are currently not logged in. Please sign in to continue",
        401
      )
    );
  }

  // Verifying token
  const decoded = await promisify(jwt.verify)(token, process.env.JWT_SECRET);

  // Checking if user still exists
  const id = decoded.id;
  const currentUser = await getUserById(id);
  if (!currentUser) {
    return next(
      new AppError("The user with the token does not exist anymore", 401)
    );
  }

  // Checking if user hasn't changed password since the token was last issued
  if (!currentUser.passwordChangedAfterTokenIssued(decoded.iat)) {
    return next(
      new AppError(
        "User password has been changed. Please login to get a new token"
      ),
      401
    );
  }

  // If everything checks out
  req.user = currentUser;
  next();
});

const checkIfEmailIsVerified = catchAsync(async (req, res, next) => {
  const user = req.user;

  if (!user.emailVerified) {
    return next(
      new AppError(
        "Email has not been verified, Please verify your email address!",
        401
      )
    );
  }

  next();
});

module.exports = { protectRoute, checkIfEmailIsVerified };
