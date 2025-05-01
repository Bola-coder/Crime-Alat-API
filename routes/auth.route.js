const express = require("express");
const authMiddleware = require("../middlewares/auth.middleware");

const authcontroller = require("../controllers/auth.controller");

const router = express.Router();

router.route("/signup").post(authcontroller.signup);
router.route("/login").post((req, res, next) => {
  console.log(req.body);
  // console.log(res);
  next();
}, authcontroller.login);
router.route("/verify").get(authcontroller.verifyUserEmail);
router.post("/verify/resend/", authcontroller.resendEmailVerificationToken);

router.get(
  "/status",
  authMiddleware.protectRoute,
  authMiddleware.checkIfEmailIsVerified,
  authcontroller.checkAuthStatus
);

router.get("/logout", authMiddleware.protectRoute, authcontroller.logout);

// router.route("/me/:slug").get(authcontroller.getUserBySlug);

module.exports = router;
