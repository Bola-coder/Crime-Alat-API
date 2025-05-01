const crypto = require("crypto");
const createToken = (encryptionMethod) => {
  // Generate verification token using crypto
  let token = crypto.randomBytes(32).toString(encryptionMethod);
  return token;
};

generateVerificationCode = () => {
  const code = Math.floor(100000 + Math.random() * 900000).toString(); // 6-digit code
  const hashedCode = crypto.createHash("sha256").update(code).digest("hex");
  return { code, hashedCode };
};

// A function to check if the verification code is valid
const isVerificationCodeValid = (inputCode, hashedCode) => {
  const hashedInputCode = crypto
    .createHash("sha256")
    .update(inputCode)
    .digest("hex");
  return hashedInputCode === hashedCode;
};
module.exports = {
  createToken,
  generateVerificationCode,
  isVerificationCodeValid,
};
