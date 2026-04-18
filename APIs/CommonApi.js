import exp from "express"
import {compare, hash} from 'bcryptjs'
import {UserModel} from '../models/UserModel.js'
import jwt from 'jsonwebtoken'
import {config} from 'dotenv'
import { verifyToken } from "../middlewares/verifyToken.js"
import { upload } from "../config/multer.js"
import { uploadToCloudinary } from "../config/cloudinaryUpload.js"
import cloudinary from "../config/cloudinary.js"
export const commonApp = exp.Router()
const {sign} = jwt
config()


//router to rigester user
commonApp.post("/users", upload.single("profileImageUrl"), async (req, res, next) => {
  let cloudinaryResult;
  try {
    let allowedRoles = ["USER", "AUTHOR"];
    //get user from req
    const newUser = req.body;
    console.log(newUser);
    console.log(req.file);

    //check role
    if (!allowedRoles.includes(newUser.role)) {
      return res.status(400).json({ message: "Invalid role" });
    }

    //Upload image to cloudinary from memoryStorage
    if (req.file) {
      cloudinaryResult = await uploadToCloudinary(req.file.buffer);
    }

    // console.log("cloudinaryResult", cloudinaryResult);
    //add CDN link(secure_url) of image to newUserObj
    newUser.profileImageUrl = cloudinaryResult?.secure_url;

    //run validators manually
    //hash password and replace plain with hashed one
    newUser.password = await hash(newUser.password, 12);

    //create New user document
    const newUserDoc = new UserModel(newUser);

    //save document
    await newUserDoc.save();
    //send res
    res.status(201).json({ message: "User created" });
  } catch (err) {
    console.log("err is ", err);
    //delete image from cloudinary
    if (cloudinaryResult?.public_id) {
      await cloudinary.uploader.destroy(cloudinaryResult.public_id);
    }
    next(err);
  }
});

// router to login: submit the cred and get the token
    commonApp.post("/login", async(req,res)=>{
        // get user credentials from body
        const {email,password} = req.body
        // find user from email
        let user = await UserModel.findOne({email:email})
        // if not found 
        if(!user){
            return res.status(400).json({message:"Invalid Email"})
        }
        console.log(user)
        if(user.isUserActive === false){
            return res.status(403).json({message:"user not found"})
        }
        // compare password
        let isMatched = await compare(password,user.password)
        if(!isMatched){
            return res.status(400).json({message:"Invalid password"})
        }


        // If email and password are correct
        // create jwt token for authentication
        const signtoken = sign(
            {   
                id: user._id,
                email:email,
                role:user.role,
                firstName: user.firstName,
                lastName: user.lastName,
                profileImageUrl:user.profileImageUrl
            },
            process.env.SECRET_KEY,
            {
                expiresIn:"1h"
            }
        )

        

        // store token in HTTP-only cookie
        res.cookie("token", signtoken, {
            httpOnly: true,
            sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax',
            secure: process.env.NODE_ENV === 'production'
        })

        // delete password

        let userObj = user.toObject();
        delete userObj.password

        // Send successful login response 
        res.status(200).json({message:"login success",payload:userObj})
    })
// router for logout
    commonApp.get("/logout", (req,res)=>{
        // delete token from cookies storage
        res.clearCookie("token", {
            httpOnly: true,
            sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax',
            secure: process.env.NODE_ENV === 'production'
        })
        // send res
        res.status(200).json({message:"Logout success"})
    })

// change password
    commonApp.put("/password",verifyToken("USER","AUTHOR","ADMIN"),async (req,res) => {
        const {currentPassword, newPassword} = req.body
        // check current password and new password are same
        if(currentPassword == newPassword){
            return res.status(400).json({message:"Current and new password are same"})
        }
        // get current password of user/admin/author
        const userId = req.user?.id
        const user = await UserModel.findById(userId)
        // check the current password of req and user are same
        let isMatched = await compare(currentPassword,user.password)
        if(!isMatched){
            return res.status(400).json({message:"Invalid current password"})
        }
        // hash new password
        // repalce current password of user with hashed new password
        user.password = await hash(newPassword,12)
        // save
        await user.save()
        // send res
        res.status(200).json({message:"password successfuly changed"})
    })
// page refresh 
commonApp.get("/check-auth",verifyToken("USER","AUTHOR","ADMIN"),async (req,res) => {
    res.status(200).json({
        message:"authenicated",
        payload: req.user,
    })
})