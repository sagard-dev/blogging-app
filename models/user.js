const { createHmac, randomBytes } = require("crypto");
const { Schema, model } = require("mongoose");
const { createTokenForUser } = require("../services/authentication");

const userSchema = new Schema(
  {
    fullName: {
      type: String,
      required: true,
    },
    email: {
      type: String,
      required: true,
      unique: true,
    },
    salt: {
      type: String,
    },
    password: {
      type: String,
      required: true,
    },
    profileImageURL: {
      type: String,
      default: "/images/default.png",
    },
    role: {
      type: String,
      enum: ["USER", "ADMIN"],
      default: "USER",
    },
  },
  {
    timestamps: true,
  },
);

//middleware runs before saving to DB
userSchema.pre("save", function (next) {
  //this refers to the document created using Model User
  const user = this;

  //this will check is the password modified ? for new user it is true , suppose if user only change the fullName then this will be false & return

  if (!user.isModified("password")) return;

  const salt = randomBytes(16).toString();
  const hashedPassword = createHmac("sha256", salt)
    .update(user.password)
    .digest("hex");

  this.salt = salt;
  this.password = hashedPassword;
});

//static used to add a method to class , here mongoose treats the Model as class
//this should be added to schema not to User model
userSchema.static(
  "matchPasswordAndGenerateToken",
  async function (email, password) {
    // this refers to User Model, because when Mongoose creates the User model and attaches the method to it so ...
    const user = await this.findOne({ email });
    if (!user) throw new Error("User not found!");

    const salt = user.salt;
    const hashedPassword = user.password;

    const userProvidedHash = createHmac("sha256", salt)
      .update(password)
      .digest("hex");

    if (hashedPassword !== userProvidedHash)
      throw new Error("Incorrect Password");

    const token = createTokenForUser(user);

    return token;
  },
);

const User = model("user", userSchema);

module.exports = User;
