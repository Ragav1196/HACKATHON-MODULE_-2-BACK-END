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
  GetAllServiceReq,
  AddServiceReq,
  GetServiceReqById,
  UpdateServiceReqById,
  DeleteServiceReqById,
  GetAllContacts,
  AddContacts,
  GetContactsById,
  UpdateContactsById,
  DeleteContactsById,
  GetLeadCounts,
  GetServceReqCounts,
  GetContactsCounts,
  GetAdminMailAddress,
  SendMail,
} from "./Functions.js";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import { transporter } from "./forgotPassword.js";
import crypto from "crypto";

const router = express.Router();

// END POINTS FOR THE REGISTER:
router.route("/register").post(async (req, res) => {
  const dataProvided = req.body;
  const UsernameFrmDB = await GetUsername(dataProvided.username);
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
    dataProvided.username,
    hashedPassword,
    dataProvided.email,
    dataProvided.userType
  );
  res.send(result);
});

// END POINTS FOR THE LOGIN:
router.route("/login").post(async (req, res) => {
  const dataProvided = req.body;

  const DataFrmDB = await GetUsername(dataProvided.username);

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
      username: DataFrmDB.username,
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
    const subject = "Reset Password";
    const content = ` <h1>You requested for a password change</h1>
          <h3>Click on this <a href="http://localhost:3000/new-password/${token}">link</a> to reset your password</h3>
          `;
    SendMail(emailFromDB.email, subject, content);

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

    const GetAdmin = await GetAdminMailAddress();
    const subject = "New lead is added";
    const content = `<h3>Check CRM app, to know more about the newly added lead</h3>`;
    GetAdmin.forEach(({ email }) => SendMail(email, subject, content));

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

// END POINTS FOR THE SERVICE REQUESTS:
router
  .route("/service-request")
  .get(async (req, res) => {
    const ServiceReqData = await GetAllServiceReq();

    res.send(ServiceReqData);
  })
  .post(async (req, res) => {
    const data = req.body;

    const addServiceReq = await AddServiceReq(data);

    const GetAdmin = await GetAdminMailAddress();
    const subject = "New service request is added";
    const content = `<h3>Check CRM app, to know more about the newly added service request</h3>`;
    GetAdmin.forEach(({ email }) => SendMail(email, subject, content));

    res.send(addServiceReq);
  });

router
  .route("/service-request/:id")
  .get(async (req, res) => {
    const { id } = req.params;

    const ServiceReqData = await GetServiceReqById(id);
    res.send(ServiceReqData);
  })
  .put(async (req, res) => {
    const { id } = req.params;

    const data = req.body;

    const updateServiceReq = await UpdateServiceReqById(id, data);

    res.send(updateServiceReq);
  })
  .delete(async (req, res) => {
    const { id } = req.params;

    const deleteServiceReqData = await DeleteServiceReqById(id);
    res.send(deleteServiceReqData);
  });

// END POINTS FOR THE CONTACTS:
router
  .route("/contacts")
  .get(async (req, res) => {
    const ContactsData = await GetAllContacts();
    res.send(ContactsData);
  })
  .post(async (req, res) => {
    const data = req.body;

    const addContacts = await AddContacts(data);

    const GetAdmin = await GetAdminMailAddress();
    const subject = "New contact is added";
    const content = `<h3>Check CRM app, to know more about the newly added contact</h3>`;
    GetAdmin.forEach(({ email }) => SendMail(email, subject, content));

    res.send(addContacts);
  });

router
  .route("/contacts/:id")
  .get(async (req, res) => {
    const { id } = req.params;

    const ContactsData = await GetContactsById(id);
    res.send(ContactsData);
  })
  .put(async (req, res) => {
    const { id } = req.params;

    const data = req.body;

    const updateContacts = await UpdateContactsById(id, data);

    res.send(updateContacts);
  })
  .delete(async (req, res) => {
    const { id } = req.params;

    const deleteContactsData = await DeleteContactsById(id);
    res.send(deleteContactsData);
  });

// TO GET COUNTS OF THE LEADS, SERVICE REQUESTS AND CONTACTS:
router.route("/get-counts").get(async (req, res) => {
  const leadsCount = await GetLeadCounts();
  const serviceReqCount = await GetServceReqCounts();
  const ContactsCount = await GetContactsCounts();
  res.send({ leadsCount, serviceReqCount, ContactsCount });
});

export const userRouter = router;
