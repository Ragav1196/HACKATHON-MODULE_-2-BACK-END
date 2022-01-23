import bcrypt from "bcrypt";
import { client } from "./index.js";
import { ObjectId } from "mongodb";

function GetUsername(name) {
  return client
    .db("hackathonModule-2")
    .collection("login")
    .findOne({ name: name });
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

function AddUsers(lname, fname, name, hashedPassword, email, userType) {
  return client
    .db("hackathonModule-2")
    .collection("login")
    .insertMany([
      { lname, fname, name, password: hashedPassword, email, userType },
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
      expireTime: { $lt: new Date(ISODate().getTime() + 3600000) },
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
};
