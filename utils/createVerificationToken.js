const sendEmail = require("./email");
const { generateVerificationCode } = require("./token");
const { encryptString } = require("./encryption");

// Function that generates a 6-digit code, emails it to the user, and returns its hash
const createVerificationTokenAndSendToEmail = async (email) => {
  const { code, hashedCode } = generateVerificationCode();

  await sendEmail({
    email: email,
    subject: "Email Verification Code",
    message: `Your email verification code is: ${code}\n\nIt will expire in 10 minutes.`,
  });

  return hashedCode;
};

module.exports = { createVerificationTokenAndSendToEmail };
