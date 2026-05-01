// A perfectly innocuous file with no secrets — used to assert that
// secret-scan returns zero findings on clean code.
const greet = (name) => `Hello, ${name}!`;
const config = {
  port: 3000,
  // password = changeme would be an obvious placeholder; keep it benign.
  retries: 3,
};
module.exports = { greet, config };
