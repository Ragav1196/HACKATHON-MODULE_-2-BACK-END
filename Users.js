import express from "express";
import {
  GetUsername,
  GetEmail,
  GenerateHash,
  AddUsers,
  GetAllLeads,
  AddLeads,
  GetLeadsById,
  UpdateLeadsById,
  DeleteLeadsById,
  ResetPassword,
  FindUserWithToken,
  UpdatePassword,
} from "./Functions.js";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import { transporter } from "./forgotPassword.js";
import crypto from "crypto";

const router = express.Router();

// END POINTS FOR THE REGISTER:
router.route("/register").post(async (req, res) => {
  const dataProvided = req.body;
  const UsernameFrmDB = await GetUsername(dataProvided.name);
  const emailFrmDB = await GetEmail(dataProvided.email);

  if (UsernameFrmDB && emailFrmDB) {
    res.status(400).send({ message: "Username and Email already exists" });
    return;
  }

  if (UsernameFrmDB) {
    res.status(400).send({ message: "Username already exists" });
    return;
  }
  if (emailFrmDB) {
    res.status(400).send({ message: "User Email already exists" });
    return;
  }

  if (dataProvided.password.length < 8) {
    res.status(400).send({ message: "Password must be longer" });
    return;
  }

  if (
    !/^(?=.*[0-9])(?=.*[a-z])(?=.*[A-Z])(?=.*[@!#%&]).{8,}$/g.test(
      dataProvided.password
    )
  ) {
    res.status(400).send({ message: "Password pattern doesn't match" });
    return;
  }

  if (
    !/^(([^<>()[\]\\.,;:\s@"]+(\.[^<>()[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/.test(
      dataProvided.email
    )
  ) {
    res.status(400).send({ message: "Email pattern doesn't match" });
    return;
  }

  const hashedPassword = await GenerateHash(dataProvided.password);

  const result = await AddUsers(
    dataProvided.lname,
    dataProvided.fname,
    dataProvided.name,
    hashedPassword,
    dataProvided.email,
    dataProvided.userType
  );
  res.send(result);
});

// END POINTS FOR THE LOGIN:
router.route("/login").post(async (req, res) => {
  const dataProvided = req.body;

  const DataFrmDB = await GetUsername(dataProvided.name);

  if (!DataFrmDB) {
    res.status(400).send({ message: "Invalid credentials" });
    return;
  }

  const storedPassword = DataFrmDB.password;

  const isPasswordMatch = await bcrypt.compare(
    dataProvided.password,
    storedPassword
  );

  const tokenId = {
    fname: DataFrmDB.fname,
    userType: DataFrmDB.userType,
    id: DataFrmDB._id,
  };

  if (isPasswordMatch) {
    const token = jwt.sign({ id: tokenId }, process.env.SECRET_KEY);

    res.send({
      message: "Successfull login",
      token: token,
      name: DataFrmDB.name,
      userType: DataFrmDB.userType,
    });
  } else {
    res.status(401).send({ message: "Invalid credentials" });
  }
});

// END POINTS FOR THE RESET PASSWORD:
router.route("/reset-password").post((req, res) => {
  crypto.randomBytes(32, async (err, buffer) => {
    if (err) {
      console.log(err);
    }
    const token = buffer.toString("hex");

    const dataProvided = req.body;
    const emailFromDB = await GetEmail(dataProvided.email);

    if (!emailFromDB) {
      return res
        .status(422)
        .send({ message: "User doesn't exist with that E-mail" });
    }

    const email = emailFromDB.email;
    const tokenExpire = new Date();
    tokenExpire.setMinutes(tokenExpire.getMinutes() + 10);

    const result = await ResetPassword(token, tokenExpire.toString(), email);

    // TO SEND AN AUTOMATIC EMAIL RESET PASSWORD:
    transporter.sendMail({
      to: emailFromDB.email,
      from: "ragavofficial01@outlook.com",
      subject: "Reset Password",
      html: `
        <h1>You requested for a password change</h1>
        <h3>Click on this <a href="http://localhost:3000/new-password/${token}">link</a> to reset your password</h3>
        `,
    });

    res.send({
      reponse: result,
      token: token,
      tokenExpire: tokenExpire.toString(),
    });
  });
});

// END POINTS FOR UPDATING NEW PASSWORD:
router.route("/new-password").post(async (req, res) => {
  const dataProvided = req.body;

  const newPassword = dataProvided.password;
  const token = dataProvided.token;

  const user = await FindUserWithToken(token);
  if (!user) {
    return res.status(422).send({ message: "Try again session expired" });
  }

  bcrypt
    .hash(newPassword, 10)
    .then(async (hashedPassword) => {
      await UpdatePassword(hashedPassword, token);
      res.send({ message: "Password successfully updated" });
    })
    .catch((err) => {
      console.log(err);
    });
});

// END POINTS FOR THE LEADS:
router
  .route("/lead")
  .get(async (req, res) => {
    const leadData = await GetAllLeads();
    res.send(leadData);
  })
  .post(async (req, res) => {
    const data = req.body;

    const addLead = await AddLeads(data);

    res.send(addLead);
  });

router
  .route("/lead/:id")
  .get(async (req, res) => {
    const { id } = req.params;

    const leadData = await GetLeadsById(id);
    res.send(leadData);
  })
  .put(async (req, res) => {
    const { id } = req.params;

    const data = req.body;

    const updateLead = await UpdateLeadsById(id, data);

    res.send(updateLead);
  })
  .delete(async (req, res) => {
    const { id } = req.params;

    const deleteLeadData = await DeleteLeadsById(id);
    res.send(deleteLeadData);
  });

export const userRouter = router;
