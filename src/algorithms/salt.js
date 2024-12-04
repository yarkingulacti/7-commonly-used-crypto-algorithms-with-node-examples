const { scryptSync, randomBytes, timingSafeEqual } = require("crypto");

const users = [];

function signup(email, password) {
  const salt = randomBytes(16).toString("hex");
  const hashedPassword = scryptSync(password, salt, 64).toString("hex");

  const user = { email, password: `${salt}:${hashedPassword}` };
  users.push(user);
}

function login(email, password) {
  const user = users.find((user) => user.email === email);

  const [salt, key] = user.password.split(":");
  const hashedBuffer = scryptSync(password, salt, 64);

  const keyBuffer = Buffer.from(key, "hex");
  const match = timingSafeEqual(hashedBuffer, keyBuffer);

  if (match) {
    return "login success!";
  } else {
    return "login fail!";
  }
}

signup("yarkingulacti98@hotmail.com", "hi-mom!");
console.log(login("yarkingulacti98@hotmail.com", "hi-mom!"));
