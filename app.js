const express = require("express");
const morgan = require("morgan");
const cookieParser = require("cookie-parser");
const errorHandler = require("./middlewares/error.middleware");
const authRoutes = require("./routes/auth.route");
const userRoutes = require("./routes/user.route");
const adminRoutes = require("./routes/admin.route");
const AppError = require("./utils/AppError");
const { cloudinaryConfig } = require("./utils/cloudinary");

const app = express();

app.use(morgan("dev"));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use("*", cloudinaryConfig);
const appName = "AppName";

// req.isAuthenticated is provided from the auth router
app.get("/", (req, res) => {
  res.json({
    message: `Welcome to ${appName}`,
  });
});

app.get("/api/v1", (req, res) => {
  res.json({
    message: `Welcome to ${appName} API`,
  });
});

// Routes
app.use("/api/v1/auth", authRoutes);
app.use("/api/v1/user", userRoutes);
app.use("/api/v1/admin", adminRoutes);

app.all("*", (req, res, next) => {
  const error = new AppError(
    `Can't find ${req.originalUrl} using http method ${req.method} on this server. Route not defined`,
    404
  );
  next(error);
});

app.use(errorHandler);

module.exports = app;
