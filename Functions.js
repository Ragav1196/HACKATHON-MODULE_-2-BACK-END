import bcrypt from "bcrypt";
import { client } from "./index.js";
import { ObjectId } from "mongodb";
import { transporter } from "./forgotPassword.js";

function GetUsername(username) {
  return client
    .db("hackathonModule-2")
    .collection("login")
    .findOne({ username: username });
}

function GetEmail(email) {
  return client
    .db("hackathonModule-2")
    .collection("login")
    .findOne({ email: email });
}

async function GenerateHash(password) {
  const NO_OF_ROUNDS = 10;
  const salt = await bcrypt.genSalt(NO_OF_ROUNDS);
  const hashedPassword = await bcrypt.hash(password, salt);
  return hashedPassword;
}

function AddUsers(lname, fname, username, hashedPassword, email, userType) {
  return client
    .db("hackathonModule-2")
    .collection("login")
    .insertMany([
      { lname, fname, username, password: hashedPassword, email, userType },
    ]);
}

function ResetPassword(token, expireTime, email) {
  return client
    .db("hackathonModule-2")
    .collection("login")
    .updateOne(
      { email: email },
      { $set: { token: token, expireTime: expireTime } }
    );
}

function FindUserWithToken(token) {
  return client
    .db("hackathonModule-2")
    .collection("login")
    .findOne({
      token: token,
      expireTime: { $gt: new Date().toString() },
    });
}

function UpdatePassword(hashedPassword, token) {
  return client
    .db("hackathonModule-2")
    .collection("login")
    .updateOne(
      { token: token },
      {
        $set: {
          password: hashedPassword,
        },
        $unset: { token: 1, expireTime: 1 },
      }
    );
}

// LEADS:
function GetAllLeads() {
  return client.db("hackathonModule-2").collection("lead").find({}).toArray();
}

function AddLeads(data) {
  return client.db("hackathonModule-2").collection("lead").insertMany(data);
}

function GetLeadsById(id) {
  return client
    .db("hackathonModule-2")
    .collection("lead")
    .findOne({ _id: ObjectId(id) });
}

function UpdateLeadsById(id, data) {
  return client
    .db("hackathonModule-2")
    .collection("lead")
    .updateOne({ _id: ObjectId(id) }, { $set: data });
}

function DeleteLeadsById(id) {
  return client
    .db("hackathonModule-2")
    .collection("lead")
    .deleteOne({ _id: ObjectId(id) });
}

// SERVICE REQUEST:
function GetAllServiceReq() {
  return client
    .db("hackathonModule-2")
    .collection("service request")
    .find({})
    .toArray();
}

function AddServiceReq(data) {
  return client
    .db("hackathonModule-2")
    .collection("service request")
    .insertMany(data);
}

function GetServiceReqById(id) {
  return client
    .db("hackathonModule-2")
    .collection("service request")
    .findOne({ _id: ObjectId(id) });
}

function UpdateServiceReqById(id, data) {
  return client
    .db("hackathonModule-2")
    .collection("service request")
    .updateOne({ _id: ObjectId(id) }, { $set: data });
}

function DeleteServiceReqById(id) {
  return client
    .db("hackathonModule-2")
    .collection("service request")
    .deleteOne({ _id: ObjectId(id) });
}

// CONTACTS:
function GetAllContacts() {
  return client
    .db("hackathonModule-2")
    .collection("contacts")
    .find({})
    .toArray();
}

function AddContacts(data) {
  return client.db("hackathonModule-2").collection("contacts").insertMany(data);
}

function GetContactsById(id) {
  return client
    .db("hackathonModule-2")
    .collection("contacts")
    .findOne({ _id: ObjectId(id) });
}

function UpdateContactsById(id, data) {
  return client
    .db("hackathonModule-2")
    .collection("contacts")
    .updateOne({ _id: ObjectId(id) }, { $set: data });
}

function DeleteContactsById(id) {
  return client
    .db("hackathonModule-2")
    .collection("contacts")
    .deleteOne({ _id: ObjectId(id) });
}

// TO GET COUNTS OF THE LEADS, SERVICE REQUESTS AND CONTACTS:
function GetLeadCounts() {
  return client.db("hackathonModule-2").collection("lead").find({}).count();
}

function GetServceReqCounts() {
  return client
    .db("hackathonModule-2")
    .collection("service request")
    .find({})
    .count();
}

function GetContactsCounts() {
  return client.db("hackathonModule-2").collection("contacts").find({}).count();
}

function GetAdminMailAddress() {
  return client
    .db("hackathonModule-2")
    .collection("login")
    .find({ userType: "admin" })
    .toArray();
}

// TO SEND AN EMAIL WHEN NEW CONTACTS, SERVICE REQUESTS OR LEADS ADDED:
function SendMail(email, subject, content) {
  transporter.sendMail({
    to: email,
    from: "ragavofficial01@outlook.com",
    subject: subject,
    html: content,
  });
}

// transporter.sendMail({
//   to: emailFromDB.email,
//   from: "ragavofficial01@outlook.com",
//   subject: "Reset Password",
//   html: `
//   <h1>You requested for a password change</h1>
//   <h3>Click on this <a href="http://localhost:3000/new-password/${token}">link</a> to reset your password</h3>
//   `,
// });

export {
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
};
