const mongoose = require('mongoose');
const bcrypt = require('bcryptjs'); 

const appointmentSchema = new mongoose.Schema({
  adminId:{
    type: String,
    require: true,
  },
  name: {
    type: String,
    required: true,
  },
  phoneNumber: {
    type: String,
    required: true,
  },
  email : {
    type: String,
    required: true,
  },
  appointmentDate: {
    type: Date,
    required: true,
  },
  appointmentTime: {
    type: String,
    required: true,
  },
  status: {
    type: String,
    enum: ['Pending', 'Confirmed', 'Cancelled'],
    default: 'Pending',  // Default status is pending
  },
  submittedAt: {
    type: Date,
    default: Date.now,  // Automatically set submission time to now
  },

  remark:  String,

  updatedAt: {
    type: Date,
    default: Date.now,  // Automatically track when the appointment is updated
  },
});

// Middleware to update `updatedAt` field whenever the document is modified
appointmentSchema.pre('save', function(next) {
  this.updatedAt = Date.now();
  next();
});


// to get available slots
const SlotSchema = new mongoose.Schema({
  adminId: {
    type: String,
    required: true
  },
  date: {
    type: Date,
    required: true
  },
  time: {
    type: String,
    required: true
  },
  isAvailable: {
    type: Boolean,
    default: true,
    required: true
  },
});

// ✅ Add compound unique index on adminId + date + time
SlotSchema.index({ adminId: 1, date: 1, time: 1 });


// Define the schema for admin sign up
const adminSchema = new mongoose.Schema({
  adminId:{
    type: String,
    unique: true,
  },
  username: {
    type: String,
    required: true,
    unique: true,
    minlength: 3,
  },
  corporateAdress:{
    type: String,
    required: true,
  },
  email: {
    type: String,
    required: true,
    unique: true,
    match: [/^\S+@\S+\.\S+$/, 'Please enter a valid email address'],
  },
  mobile: {
    type: String,
    required: true,
    unique: true,
    match: /^\+?\d{1,15}$/,
  },
  password: {
    type: String,
    required: true,
    minlength: 6, // Password should be at least 6 characters
  },
  createdAt: {
    type: Date,
    default: Date.now,
  },
  lastLogin: {
    type: Date,
    default: null,
  },
  appointmentLink: { type: String },

  // Subscription plan and access
  subscriptionPlan: { type: String, enum: ['Free', 'Basic', 'Premium'], default: 'Free' },
  subscriptionStart: { type: Date},
  subscriptionEnd: { type: Date},
  isSubscribed: { type: Boolean, default: false }
});

// Middleware to hash the password before saving
adminSchema.pre('save', async function(next) {
  if (!this.isModified('password')) return next();

  try {
    // const salt = await bcrypt.genSalt(10);
    // this.password = await bcrypt.hash(this.password, salt);
    next();
  } catch (error) {
    next(error);
  }
  
});

// Method to compare passwords
adminSchema.methods.comparePassword = async function(candidatePassword) {
  return await bcrypt.compare(candidatePassword, this.password);
};

// Create the model

// Create the Appointment model based on the schema
const Appointment = mongoose.model('Appointment', appointmentSchema);
const Admin = mongoose.model('Admin', adminSchema);
const Slot = mongoose.model('Slot', SlotSchema);
module.exports = {
  Appointment,
  Admin,
  Slot,

};
