const User = require("../models/user");
const BigPromise = require("../middlewares/bigPromise");
const CustomError = require("../utils/customError");
const cookieToken = require("../utils/cookieToken");
const fileUpload = require("express-fileupload");
const cloudinary = require("cloudinary");
const mailHelper = require("../utils/emailHelper");
const crypto = require("crypto");
const { resourceLimits } = require("worker_threads");

exports.signup = BigPromise(async (req, res, next) => {
  if (!req.files) {
    return next(new CustomError("photo is required for signup", 400));
  }
  const { name, email, password } = req.body;
  if (!email || !name || !password) {
    return next(new CustomError("please send email ,name and password", 400));
  }
  let file = req.files.photo;
  const result = await cloudinary.v2.uploader.upload(file.tempFilePath, {
    folder: "users",
    width: 150,
    crop: "scale",
  });

  const user = await User.create({
    name,
    email,
    password,
    photo: {
      id: result.public_id,
      secure_url: result.secure_url,
    },
  });
  cookieToken(user, res);
});

exports.login = BigPromise(async (req, res, next) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return next(new CustomError("please provide email and password", 400));
  }
  const user = await User.findOne({ email }).select("+password");
  if (!user) {
    return next(new CustomError("email or pass not match", 400));
  }
  const isPasswordCorrect = await user.isValidatedPassword(password);
  if (!isPasswordCorrect) {
    return next(new CustomError(" email and password does not match", 400));
  }
  cookieToken(user, res);
});

exports.logout = BigPromise(async (req, res, next) => {
  res.cookie("token", null, {
    expires: new Date(Date.now()),
    httpOnly: true,
  });
  res.status(200).json({
    success: true,
    message: "logout success",
  });
});

exports.forgotPassword = BigPromise(async (req, res, next) => {
  const { email } = req.body;
  const user = await User.findOne({ email });
  if (!user) {
    return next(new CustomError("email not found registered", 400));
  }
  const forgotToken = user.getForgotPasswordToken();
  await user.save({ validateBeforeSave: false });
  const myUrl = `${req.protocol}://${req.get(
    "host"
  )}/password/reset/${forgotToken}`;

  const message = `copy paste this link in url and hit enter \n\n ${myUrl}`;

  try {
    await mailHelper({
      email: user.email,
      subject: "password reset email",
      message,
    });
    res.status(200).json({
      success: true,
      message: "email sent successfully",
    });
  } catch (error) {
    user.forgotPasswordToken = undefined;
    user.forgotPasswordExpiry = undefined;
    await user.save({ validateBeforeSave: false });

    return next(new CustomError(error.message, 500));
  }
});

exports.passwordReset = BigPromise(async (req, res, next) => {
  const token = req.params.token;
  const encryToken = crypto.createHash("sha256").update(token).digest("hex");

  const user = await User.findOne({
    encryToken,
    forgotPasswordExpiry: { $gt: Date.now() },
  });

  if (!user) {
    return next(new CustomError("token is invalid or expired", 400));
  }
  if (req.body.password !== req.body.confirmPassword) {
    return next(
      new CustomError("password and confirm pass does not match", 400)
    );
  }
  user.password = req.body.password;
  user.forgotPasswordToken = undefined;
  user.forgotPasswordExpiry = undefined;
  await user.save();

  cookieToken(user, res);
});

exports.getLoggedInUserDetails = BigPromise(async (req, res, next) => {
  const user = await User.findById(req.user.id);
  res.status(200).json({
    success: true,
    user,
  });
});

exports.changePassword = BigPromise(async (req, res, next) => {
  const userId = req.user.id;
  const user = await User.findById(userId).select("+password");
  const isCorrectOldPassword = await user.isValidatedPassword(
    req.body.oldPassword
  );
  if (!isCorrectOldPassword) {
    return next(new CustomError("old password is incorrect", 400));
  }
  user.password = req.body.password;
  await user.save();
  cookieToken(user, res);
});

exports.updateUserDetails = BigPromise(async (req, res, next) => {
  const newData = {
    name: req.body.name,
    email: req.body.email,
  };
  if (req.files) {
    const user = await User.findById(req.user.id);
    const imageId = user.photo.id;

    const resp = await cloudinary.v2.uploader.destroy(imageId);

    const result = await cloudinary.v2.uploader.upload(
      req.files.photo.tempFilePath,
      {
        folder: "users",
        width: 150,
        crop: "scale",
      }
    );
    newData.photo = {
      id: result.public_id,
      secure_url: result.secure_url,
    };
  }
  const user = await User.findByIdAndUpdate(req.user.id, newData, {
    new: true,
    runValidators: true,
    useFindAndModify: false,
  });
  res.status(200).json({
    success: true,
  });
});

exports.adminAllUser = BigPromise(async (req, res, next) => {
  const users = await User.find();
  res.status(200).json({
    success: true,
    users,
  });
});

exports.managerAllUser = BigPromise(async (req, res, next) => {
  const users = await User.find({ role: "user" });
  res.status(200).json({
    success: true,
    users,
  });
});

exports.admingetOneUser = BigPromise(async (req, res, next) => {
  const user = await User.findById(req.params.id);

  if (!user) {
    next(new CustomError("no user found", 400));
  }
  res.status(200).json({
    success: true,
    user,
  });
});

exports.adminUpdateOneUserDetails = BigPromise(async (req, res, next) => {
  const newData = {
    name: req.body.name,
    email: req.body.email,
    role: req.body.role,
  };

  const user = await User.findByIdAndUpdate(req.params.id, newData, {
    new: true,
    runValidators: true,
    useFindAndModify: false,
  });
  res.status(200).json({
    success: true,
  });
});

exports.adminDeleteOneUser = BigPromise(async (req, res, next) => {
  const user = await User.findById(req.params.id);
  if (!user) {
    return next(new CustomError("no such user found", 401));
  }
  const imageId = user.photo.id;
  await cloudinary.v2.uploader.destroy(imageId);
  await user.remove;

  res.status(200).json({
    success: true,
  });
});
