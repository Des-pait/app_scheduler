const express = require("express");
const https = require('https');
const fs = require('fs');
const twilio = require('twilio');
const path = require("path");
const mongoose = require("mongoose");
const bcrypt = require('bcryptjs');
const bodyparser = require("body-parser");
const session = require('express-session'); // Add session middleware
const app = express();
const QRCode = require('qrcode');
const port = 3000;


const sslOptions = {
  key: fs.readFileSync('./certs/key.pem'),
  cert: fs.readFileSync('./certs/cert.pem'),
};

// const adminController = require('./adminController'); 

const { Appointment, User, Service, Admin, SyncDateTime, AppointmentSlot, Slot} = require('./models/User');

const url = 'mongodb://127.0.0.1:27017/dk';
mongoose.connect(url, { useNewUrlParser: true, useUnifiedTopology: true });

// Define mongoose schema
const contactSchema = new mongoose.Schema({
  name: { type: String, required: true },
  state: { type: String, required: true },
  phone: { type: String, required: true },
  email: { type: String, required: true },
  require: { type: String } // user query/requirement
});


var queries = mongoose.model('queries', contactSchema);

// Use the crypto module to generate a strong secret key (or use an environment variable)
const crypto = require('crypto');
const secretKey = crypto.randomBytes(32).toString('hex');  // Generate a 64-character random key

// Session middleware with the secret key
app.use(session({
    secret: secretKey,  // Ensure the session is signed securely
    resave: false,
    saveUninitialized: true,
    cookie: { secure: false }  // Set to true only if using HTTPS
}));

// Serve static files
app.use(express.static('views', {
  setHeaders: (res, path) => {
    if (path.endsWith('.html')) res.setHeader('Content-Type', 'text/html');
    else if (path.endsWith('.css')) res.setHeader('Content-Type', 'text/css');
    else if (path.endsWith('.js')) res.setHeader('Content-Type', 'text/javascript');
    else if (path.endsWith('.png')) res.setHeader('Content-Type', 'image/png');
    else if (path.endsWith('.jpg') || path.endsWith('.jpeg')) res.setHeader('Content-Type', 'image/jpeg');
    else if (path.endsWith('.gif')) res.setHeader('Content-Type', 'image/gif');
  }
}));




app.use('/static', express.static('static'));
app.use(express.urlencoded({ extended: true }));
app.use('/uploads', express.static('uploads'));

// PUG SPECIFIC STUFF
app.set('view engine', 'pug');
app.set('views', path.join(__dirname, 'views'));

app.use(express.json());


// Route to show the admin login page or dashboard
app.get("/admin/login", (req, res) => {
  // Check if the admin is authenticated using the session
  if (req.session.user && req.session.user.isAdminAuthenticated) {
    // Admin is authenticated, show the dashboard
    res.render('admin_dashboard.pug');
  } else {
    // Admin is not authenticated, show the login page
    res.render('admin_auth.pug');
  }
});

app.get("/dashboard", (req, res) => {
  if (req.session.user && req.session.user.role === 'admin') {
    res.render('admin_dashboard.pug'); // Render dashboard for admin
  } else {
    res.render("admin_auth.pug"); // Show login page if not authenticated
  }
});



// Route to handle admin logout (destroy the session)
app.get("/admin/logout", (req, res) => {
  req.session.destroy((err) => {
    if(err) {
      return res.status(500).send("Failed to log out.");
    }
    res.redirect("/admin/login");  // Redirect to login page after logout
  });
});

app.get('/', (req, res) => {
  res.status(200).render('index.pug', { title: 'Welcome !!' });
});

app.get('/contact', (req, res) => {
  res.status(200).render('contact.pug');
});

app.get('/services', (req, res) => {
  res.status(200).render('services.pug');
});

app.get('/user_auth', (req, res) => {
  res.status(200).render('user_auth.pug');
});


app.get('/appointments/data', async (req, res) => {
  try {
    const { date, adminId } = req.query;
    console.log('adminId:', adminId)

    const user = await Admin.findOne({adminId})
    console.log('useris: ', );
    
    let today = new Date();
    today.setHours(today.getHours() + 5);
    today.setMinutes(today.getMinutes() + 30);
    
    console.log(today)
    if (!adminId) {
      return res.status(400).json({ message: 'Admin ID is required' });
    }

    if (!user.isSubscribed){
      return res.json('No available slots for this receipent')
    }

    if (!date ) {
      // First part: Get all distinct available dates for this admin
      const distinctDates = await Slot.aggregate([
        {
          $match: {
            isAvailable: true,
            adminId: adminId, // Filter by adminId
            date: {$gte:today}
          }
        },
        {
          $project: {
            date: {
              $dateToString: {
                format: "%d-%m-%Y",
                date: "$date"
              }
            }
          }
        },
        {
          $group: {
            _id: "$date"
          }
        },
        {
          $sort: { _id: 1 }
        }
      ]);

      const availableDates = distinctDates.map(item => item._id);
      console.log(availableDates)
      return res.json({availableDates, rname : user.username});
    }

    // If a date is provided, fetch the time slots for that admin & date
    const dateObj = new Date(date.split('-').reverse().join('-'));
    const endOfDay = new Date(dateObj.setHours(28, 89, 59, 999));

    const slots = await Slot.find({
      adminId: adminId,  // Filter by adminId
      date: { $gte: today, $lt: endOfDay },
      isAvailable: true
    }).exec();

    const availableSlots = slots.map(slot => ({
      time: slot.time,
    }));

    res.json(availableSlots);
  } catch (error) {
    console.error('Error fetching available slots:', error);
    res.status(500).json({ message: 'Error fetching available slots' });
  }
});
// GET /appointments OR /appointments/:uniqueId (optional param approach)
app.get('/appointments/:uniqueId?', async (req, res) => {
  const uniqueId = req.params.uniqueId || ''; // Get from URL param if available
  let user = null;

  if (uniqueId) {
    console.log('Fetching user for uniqueId:', uniqueId);
    try {
      user = await Admin.findOne({ adminId: uniqueId });
      console.log('User found:', user);

      if (!user) {
        return res.status(404).send('Invalid link or user not found');
      }
    } catch (err) {
      console.error('Server error:', err);
      return res.status(500).send('Server error');
    }
  }

  res.render('appointments', {
    uniqueId: user ? user.adminId : '',
    rname: user ? user.username : '',
    readonly: !!user // If user found, make readonly
  });
});



// Middleware to check if the user is an admin
const isAdminAuthenticated = (req, res, next) => {
  if (req.session.user && req.session.user.role === 'admin') {
    return next();
  }
  res.status(403).send('Forbidden: Admins only');
};

// for user authentication

function isUserAuthenticated(req, res, next) {
  if (req.session && req.session.userEmail) {
    return next();
  } else {
    return res.status(401).send('Unauthorized: Please login first.');
  }
}



// New route for fetching and categorizing appointments
app.get('/appointments-overview', isAdminAuthenticated, async (req, res) => {
  // Fetch the appointments from the database
    const currentDate = new Date();
    
    // Get the local start of the day (midnight in IST)
    const startOfDay = new Date(currentDate.getFullYear(), currentDate.getMonth(), currentDate.getDate(), 5, 30, 0, 0);
    console.log('startOfDay', startOfDay)
    // Convert to IST (Indian Standard Time) and display
    const options = { timeZone: 'Asia/Kolkata', hour12: false };
    const startOfDayInIST = new Date(startOfDay.toLocaleString('en-US', options));
    
    
    // To calculate the end of the day in IST, we use a new Date instance
    const endOfDay = new Date(currentDate.getFullYear(), currentDate.getMonth(), currentDate.getDate(), 28, 89, 59, 999);
    console.log('endOfDay', endOfDay)
    // Convert endOfDay to IST (Indian Standard Time) and display
    const endOfDayInIST = new Date(endOfDay.toLocaleString('en-US', options));
    
  
  try {
    console.log(currentDate)
    // Query for current appointments (appointments that are on the same day as currentDate)
    const allAppointments = await Appointment.find({ adminId: req.session.adminId }); // ✅ only fetch appointments for this admin

    const currentAppointments = allAppointments.filter(appointment => {
      console.log(appointment.appointmentDate);
      return appointment.appointmentDate >= startOfDay && appointment.appointmentDate < endOfDay;
    });
    
    const upcomingAppointments = allAppointments.filter(appointment => {
      console.log(appointment.appointmentDate);
      return appointment.appointmentDate >= endOfDay;
    });
    
    const pastAppointments = allAppointments.filter(appointment => {
      console.log(appointment.appointmentDate);
      return appointment.appointmentDate < startOfDay;
    });
    
    // Send the appointments data to the frontend
    console.log(currentAppointments,upcomingAppointments,pastAppointments);
    res.json({
      currentAppointments,
      upcomingAppointments,
      pastAppointments
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Failed to fetch appointments' });
  }
});

// admin signup
app.get('/admin/signup', (req, res)=>{
  return res.render('admin_signup.pug');
})

// for signup-email verification
app.post('/send-email-otp', async (req, res) => {
  const { email, subject, message } = req.body;
  const otp = Math.floor(100000 + Math.random() * 900000).toString();  // 6-digit OTP
  
  // Check if the admin already exists
  const existingAdmin = await Admin.findOne({ email });
  if (existingAdmin) {
    return res.status(400).json({ error: 'Admin already exists with the same email use another. ' });
  }

  console.log(otp)

  otpMap.set(`email-otp-${email}`, { otp, timestamp: Date.now() });
  // try {
  //   await sendEMail(email, subject, `${message} Your OTP is: ${otp}`);
  //   return res.json({ success: true, message: 'OTP sent successfully' });
  // } catch (err) {
  //   return res.status(500).json({ error: 'Failed to send OTP' });
  // }
});

// for signup-email verification
app.post('/send-usr-email-otp', async (req, res) => {
  const { email, subject, message } = req.body;
  const otp = Math.floor(100000 + Math.random() * 900000).toString();  // 6-digit OTP
  
  // Check if the admin already exists
  const existingAdmin = await Appointment.findOne({ email });
  if (! existingAdmin) {
    return res.status(400).json({ error: 'No Appointments booked in past.' });
  }

  console.log(otp)

  otpMap.set(`usr-email-otp-${email}`, { otp, timestamp: Date.now() });
  // try {
  //   await sendEMail(email, subject, `${message} Your OTP is: ${otp}`);
  //   return res.json({ success: true, message: 'OTP sent successfully' });
  // } catch (err) {
  //   return res.status(500).json({ error: 'Failed to send OTP' });
  // }
});

// Route to generate and send OTP to mobile
app.post('/send-mobile-otp', async (req, res) => {
  const { mobile } = req.body;

  if (!mobile || !/^\d{10}$/.test(mobile)) {
    return res.status(400).json({ error: 'Invalid mobile number.' });
  }
    // Check if the admin already exists
    const existingAdmin = await Admin.findOne({ mobile });
    if (existingAdmin) {
      return res.status(400).json({ error: 'Admin already exists with the same mobile number use anotherOne.' });
    }

  const otp = Math.floor(100000 + Math.random() * 900000).toString();  // 6-digit OTP
  otpMap.set(`mobile-otp-${mobile}`, { otp, timestamp: Date.now() });

  sendSms(mobile, otp);  // Simulated SMS sending

  res.json({ message: `OTP sent to ${mobile}` });
});

// POST request endpoints
app.post('/admin_signup', async (req, res) => {
  const { username, email, mobile, password, confirm_password, emailOtp, mobileOtp, corporateAdress } = req.body;

  // 🛡 Basic Validation
  if (!username || username.length < 3 || username.length > 30) {
    return res.status(400).json({ error: 'Username must be between 3 and 30 characters long.' });
  }

  const existingAdmin = await Admin.findOne({
    $or: [{ mobile }, { email }]
  });

  if (existingAdmin) {
    let errorMessage = 'Admin already exists.';
    if (existingAdmin.mobile === mobile) {
      errorMessage = 'An admin already exists with this mobile number. Please use another one.';
    } else if (existingAdmin.email === email) {
      errorMessage = 'An admin already exists with this email address. Please use another one.';
    }
    return res.status(400).json({ error: errorMessage });
  }

  const emailRegex = /^\S+@\S+\.\S+$/;
  if (!email || !emailRegex.test(email)) return res.status(400).json({ error: 'Please provide a valid email address.' });
  if (!mobile || !/^\d{10}$/.test(mobile)) return res.status(400).json({ error: 'Mobile number must be exactly 10 digits.' });
  if (!password || password.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters long.' });
  if (password !== confirm_password) return res.status(400).json({ error: 'Passwords must match.' });

  // ✅ Verify Email & Mobile OTP
  const emailOtpRecord = otpMap.get(`email-otp-${email}`);
  if (!emailOtpRecord || emailOtpRecord.otp !== emailOtp) return res.status(400).json({ error: 'Invalid or expired email OTP.' });
  const mobileOtpRecord = otpMap.get(`mobile-otp-${mobile}`);
  if (!mobileOtpRecord || mobileOtpRecord.otp !== mobileOtp) return res.status(400).json({ error: 'Invalid or expired mobile OTP.' });

  // 🔑 Generate adminId
  const generateRandomNumber = () => Math.floor(10000000 + Math.random() * 90000000);
  let adminId, isUnique = false;
  const firstName = username.trim()[0].toUpperCase();
  const lastChar = username.trim().slice(-1).toUpperCase();

  while (!isUnique) {
    adminId = `${firstName}${generateRandomNumber()}${lastChar}`;
    if (!await Admin.findOne({ adminId })) isUnique = true;
  }

  // 🌐 Create Appointment Link
  const appointmentLink = `https://localhost:3000/appointments/${adminId}`;

  // 📂 Save QR Code to public folder
  const qrCodeDir = path.join(__dirname, 'views/img');
  const qrCodeFilename = `${adminId}.png`;
  const qrCodePath = path.join(qrCodeDir, qrCodeFilename);
  if (!fs.existsSync(qrCodeDir)) fs.mkdirSync(qrCodeDir, { recursive: true });

  await QRCode.toFile(qrCodePath, appointmentLink, {
    color: { dark: '#000', light: '#FFF' }
  });

  try {
    const hashedPassword = await bcrypt.hash(password, 10);

    
    const x = new Date("2026-01-01T12:59:59.000Z");
    x.setTime(x.getTime()+330*60*1000);
    console.log(x)
    // Save Admin with appointmentLink & qrCodePath
    const newAdmin = new Admin({
      adminId,
      username,
      corporateAdress,
      email,
      mobile,
      password: hashedPassword,
      appointmentLink,
      qrCodePath: `img/${qrCodeFilename}`,
      subscriptionPlan: 'Free',
      isSubscribed: true,
      subscriptionStart: null,
      subscriptionEnd : x
    });

    await newAdmin.save();

    // ✅ Clean up OTP
    otpMap.delete(`email-otp-${email}`);
    otpMap.delete(`mobile-otp-${mobile}`);

    res.status(201).json({ message: 'Admin created successfully!' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error, please try again.' });
  }
});

// user authentication to fetch past appointments
app.post('/user/auth', async (req, res) => {
  const { email, emailOtp } = req.body;

  try {
    const userAppointments = await Appointment.find({ email });

    if (!userAppointments || userAppointments.length === 0) {
      return res.status(400).json({ error: 'You have not scheduled any appointment yet.' });
    }

    const emailOtpRecord = otpMap.get(`usr-email-otp-${email}`);
    const OTP_EXPIRATION = 5 * 60 * 1000; // 5 minutes

    if (
      !emailOtpRecord ||
      emailOtpRecord.otp !== emailOtp ||
      Date.now() - emailOtpRecord.timestamp > OTP_EXPIRATION
    ) {
      return res.status(400).json({ error: 'Invalid or expired email OTP.' });
    }

    // Remove OTP after successful verification
    otpMap.delete(`usr-email-otp-${email}`);

    // Store authenticated user in session
    req.session.userEmail = email;

    // Redirect to appointments display page
    return res.redirect('/user/display');

  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: 'Server error, please try again.' });
  }
});

// Show the page
app.get('/user/display', isUserAuthenticated, (req, res) => {
  res.render('display.pug'); 
});

// Provide JSON data for the frontend
app.get('/user/appointments-overview', isUserAuthenticated, async (req, res) => {
  try {
    const email = req.session.userEmail;
    const currentDate = new Date();

    const startOfDay = new Date(currentDate.getFullYear(), currentDate.getMonth(), currentDate.getDate(), 0, 0, 0);
    const endOfDay = new Date(currentDate.getFullYear(), currentDate.getMonth(), currentDate.getDate(), 23, 59, 59, 999);

    const allAppointments = await Appointment.aggregate([
      { $match: { email } },
      {
        $lookup: {
          from: "admins",
          localField: "adminId",
          foreignField: "adminId",
          as: "adminDetails"
        }
      },
      { $unwind: "$adminDetails" }
    ]);

    const currentAppointments = allAppointments.filter(
      ap => ap.appointmentDate >= startOfDay && ap.appointmentDate <= endOfDay
    );
    const upcomingAppointments = allAppointments.filter(ap => ap.appointmentDate > endOfDay);
    const pastAppointments = allAppointments.filter(ap => ap.appointmentDate < startOfDay);

    res.json({ currentAppointments, upcomingAppointments, pastAppointments });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});



// Admin login route
app.post('/admin/login', async (req, res) => {
  const { adminPassword, adminEmail } = req.body;

  try {
    // Look up admin using the email provided
    const existingAdmin = await Admin.findOne({ email: adminEmail });

    if (!existingAdmin) {
      return res.status(400).json({ error: 'Admin with this email not found.' });
    }

    const isMatch = await bcrypt.compare(adminPassword, existingAdmin.password);

    if (isMatch) {
      req.session.user = { _id: existingAdmin._id, role: 'admin' };
      req.session.adminId = existingAdmin.adminId;
      existingAdmin.lastLogin = new Date();
      await existingAdmin.save();
  
      return res.redirect('/admin/admin_dashboard');
    } else {
      return res.status(400).json({ error: 'Incorrect password. Please try again.' });
    }
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: 'Server error, please try again.' });
  }
});

// forgot password
require('dotenv').config();
const nodemailer = require('nodemailer');
const otpMap = new Map(); // Temporary OTP store (could use Redis for prod)

//  Route to send OTP
app.post('/admin/forgot-password', async (req, res) => {
  try {
    const { email } = req.body;

    if (!email) {
      return res.status(400).send('Email is required.');
    }

    const admin = await Admin.findOne({ email });
    if (!admin) {
      return res.status(400).send('No admin found with this email.');
    }

    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    otpMap.set(email, otp);

    const transporter = nodemailer.createTransport({
      service: 'gmail',
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,
      }
    });

    await transporter.sendMail({
      from: `"Admin Panel" <${process.env.EMAIL_USER}>`,
      to: email,
      subject: 'Your Admin OTP Login Code',
      text: `Your OTP is: ${otp}. It is valid for 5 minutes.`,
    });

    //  Render the Pug template with email context
    res.render('verify_otp', { email });

  } catch (err) {
    console.error('Error sending OTP:', err);
    res.status(500).send('Something went wrong while sending OTP.');
  }
});
// Route to verify OTP
app.post('/admin/verify-otp', async (req, res) => {
  try {
    const { email, otp } = req.body;

    if (!email || !otp) {
      return res.status(400).send('Email and OTP are required.');
    }

    const storedOtp = otpMap.get(email);

    if (storedOtp === otp) {
      otpMap.delete(email); // Remove OTP after use

      const admin = await Admin.findOne({ email });
      if (!admin) {
        return res.status(400).send('Admin not found.');
      }

      req.session.user = { _id: admin._id, role: 'admin' };
      return res.redirect('/admin/admin_dashboard');
    }

    res.status(400).send('Invalid OTP. Please try again.');
  } catch (err) {
    console.error('Error verifying OTP:', err);
    res.status(500).send('Something went wrong during verification.');
  }
});
// Subscription Page 
app.get('/admin/subscription', isAdminAuthenticated, async (req, res) => {
  try {
    const admin = await Admin.findOne({ adminId: req.session.adminId });
    res.render('admin_subscription', {
      user: admin,
      errorMessage: req.session.subscriptionError || null
    });
    req.session.subscriptionError = null; // clear message after rendering
  } catch (error) {
    console.error(error);
    res.status(500).send('Server Error');
  }
});

// Change Subscription Plan
app.post('/admin/subscribe', isAdminAuthenticated, async (req, res) => {
  const { plan } = req.body; // 'Basic' | 'Premium'
  const adminId = req.session.adminId;

  if (!['Basic', 'Premium'].includes(plan)) {
    return res.status(400).json({ message: 'Invalid subscription plan.' });
  }

  const start = new Date();
  const end = new Date();
  end.setMonth(end.getMonth() + (plan === 'Basic' ? 1 : 12)); // Basic: 1 month, Premium: 1 year

  try {
    await Admin.findOneAndUpdate(
      { adminId },
      {
      subscriptionPlan: plan,
      isSubscribed: true,
      subscriptionStart:start,
      subscriptionEnd: end
    }
    );

    res.json({ message: `Subscribed to ${plan} plan successfully.` });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Subscription failed.' });
  }
});



// Admin dashboard route
app.get('/admin/admin_dashboard', isAdminAuthenticated, (req, res) => {
  res.render('admin_dashboard.pug', {
    currentAppointments: [],  // Replace with actual data
    upcomingAppointments: [],
    pastAppointments: []
  });
});

app.post('/admin/update-appointment-status', isAdminAuthenticated, async (req, res) => {
  const { appointmentId, status } = req.body;

  // Validate input
  if (!appointmentId || !status) {
    return res.status(400).json({
      success: false,
      message: 'Appointment ID and status are required'
    });
  }

  const validStatuses = ['Pending', 'Confirmed', 'Cancelled'];
  if (!validStatuses.includes(status)) {
    return res.status(400).json({
      success: false,
      message: 'Invalid status value'
    });
  }

  try {
    // Fetch appointment
    const appointment = await Appointment.findById(appointmentId);

    if (!appointment) {
      return res.status(404).json({
        success: false,
        message: 'Appointment not found'
      });
    }

    // Allow status update only from "Pending"
    if (appointment.status !== 'Pending') {
      return res.status(400).json({
        success: false,
        message: 'Status update not allowed. Appointment already processed.'
      });
    }

    // Update status
    appointment.status = status;
    await appointment.save();

    // Send email
    const message = `Dear ${appointment.name},\n\nYour appointment status has been updated to "${appointment.status}".\n\nThank you,\nAdmin Team`;

    await sendEMail(appointment.email, 'Appointment Status Updated', message);

    //  Single response
    return res.json({
      success: true,
      message: 'Status updated and email sent.',
      updatedAppointment: appointment
    });

  } catch (err) {
    console.error('Error updating appointment status:', err);
    return res.status(500).json({
      success: false,
      message: 'Internal server error while updating appointment status'
    });
  }
});

// Utility: Convert to 12-hour format (IST assumed)
function convertTo12HourFormat(date) {
  let hours = date.getHours();
  let minutes = date.getMinutes();
  const ampm = hours >= 12 ? 'PM' : 'AM';

  hours = hours % 12 || 12;
  minutes = minutes.toString().padStart(2, '0');

  return `${hours}:${minutes} ${ampm}`;
}

function formatIndian12Hour(date) {
  return date.toLocaleString('en-IN', {
    timeZone: 'Asia/Kolkata',
    hour12: true,
    day: '2-digit',
    month: '2-digit',
    year: 'numeric',
    hour: '2-digit',
    minute: '2-digit'
  });
}

// Handle POST request to set an appointment
app.post('/admin/set-appointment', isAdminAuthenticated,  async (req, res) => {
  try {
    const { 'appointment-date': date, 'appointment-time': time } = req.body;
    const admin = await Admin.findOne({ adminId:req.session.adminId });

    // if (!admin.isSubscribed || (admin.subscriptionEnd && admin.subscriptionEnd < new Date())) {
    //   return res.status(403).json({
    //     message: 'You are not subscribed to create appointments.',
    //     redirectTo: '/admin/subscription'
    //   });
    // }
    
    if (!date || !time) {
      return res.status(400).json({ message: 'appointment date, and time must all be provided.' });
    }
    const today = new Date();
    const todayStr = today.toISOString().split('T')[0];  // "YYYY-MM-DD"
    
    console.log('today:', todayStr, 'date:', date, 'time:', time, 'localtime:', today.toLocaleTimeString('en-IN'));
    
    if (date === todayStr) {
      const [inputHour, inputMinute] = time.split(':').map(Number);
      const nowHour = today.getHours();
      const nowMinute = today.getMinutes();
    
      if (inputHour < nowHour || (inputHour === nowHour && inputMinute <= nowMinute)) {
        return res.status(400).json({
          message: `Select a time greater than ${today.toLocaleTimeString('en-IN')}`
        });
      }
    }
    
    
    // ✅ Convert input date and time to Date object (assuming IST input)
    const [year, month, day] = date.split('-').map(Number);
    const [hours, minutes] = time.split(':').map(Number);

    const localDate = new Date(year, month - 1, day, hours, minutes, 0, 0);
    const appointmentDate = new Date(localDate.getTime() + 330 * 60 * 1000); // Convert IST to UTC

    // ✅ Format time in 12-hour format
    const formattedTime = convertTo12HourFormat(localDate); // implement this function

    // ✅ Check if a slot already exists for this admin, date & time
    const adminId = req.session.adminId;
    if (!adminId) {
      return res.status(401).json({ error: 'Admin is not logged in.' });
    }    
    const existingSlot = await Slot.findOne({
      adminId: adminId,
      date: appointmentDate,
      time: formattedTime
    });

    if (existingSlot) {
      return res.status(400).json({ message: 'This time slot is already booked for this admin.' });
    }

    // ✅ Save the new slot
    const newSlot = new Slot({
      adminId: adminId,
      date: appointmentDate,
      time: formattedTime,
      isAvailable: true,
    });

    await newSlot.save();

    console.log('New slot saved:', { adminId, date: appointmentDate, time: formattedTime });

    res.status(200).json({ message: 'Appointment slot created successfully.', time: formattedTime });

  } catch (error) {
    console.error('Error setting appointment:', error);
    res.status(500).json({ message: 'An error occurred while setting the appointment.' });
  }
});

// Time period slot creation
app.post('/admin/set-appointment-period', isAdminAuthenticated, async (req, res) => {
  try {
    const { appointmentDate, startTime, endTime, slotsCount } = req.body;
    const adminId = req.session.adminId;

    console.log('Received:', req.body);
    console.log('AdminId:', adminId);

    if (!adminId || !appointmentDate || !startTime || !endTime || !slotsCount) {
      return res.status(400).send('Missing required fields');
    }

    // ✅ Get current IST date (without time for date comparison)
    const nowIST = new Date(Date.now() + 5.5 * 60 * 60 * 1000);
    const nowISTDateStr = nowIST.toISOString().split('T')[0];  // yyyy-mm-dd

    // ✅ Parse the appointment date as yyyy-mm-dd
    const appointmentDateStr = new Date(appointmentDate).toISOString().split('T')[0];

    console.log('Today IST:',  nowIST, 'Appointment Date:', appointmentDateStr);

    // ✅ Compare as strings to avoid timezone issues
    if (appointmentDateStr === nowISTDateStr) {
      const [startHour, startMinute] = startTime.split(':').map(Number);
      const startTotalMinutes = startHour * 60 + startMinute;
      const [hoursStr, minutesStr] = nowIST.toISOString().split('T')[1].split(':');
      const nowTotalMinutes = Number(hoursStr) * 60 + Number(minutesStr);
      console.log('isth',  nowIST.getHours(), 'startm', startTotalMinutes, 'totalm', nowTotalMinutes)

      if (startTotalMinutes <= nowTotalMinutes) {
        return res.status(400).send(
          `Choose a start time greater than current time: ${new Date().toLocaleString('en-IN')}`
        );
      }
    }
    // Parse start and end time
    const [startHour, startMinute] = startTime.split(':').map(Number);
    const [endHour, endMinute] = endTime.split(':').map(Number);

    const startTotalMinutes = startHour * 60 + startMinute;
    const endTotalMinutes = endHour * 60 + endMinute;

    if (endTotalMinutes <= startTotalMinutes) {
      return res.status(400).send('End time must be after start time');
    }

    const totalDuration = endTotalMinutes - startTotalMinutes;
    const slotInterval = Math.floor(totalDuration / slotsCount);

    if (slotInterval <= 0) {
      return res.status(400).send('Slot duration must be greater than 0');
    }

    // Generate slots
    const slotsToInsert = [];
    for (let i = 0; i < slotsCount; i++) {
      const slotMinutes = startTotalMinutes + i * slotInterval;
      const slotHours = Math.floor(slotMinutes / 60);
      const slotMins = slotMinutes % 60;
    
      const hoursForDisplay = slotHours % 12 || 12;
      const minutesPadded = slotMins.toString().padStart(2, '0');
      const ampm = slotHours >= 12 ? 'PM' : 'AM';
    
      const timeStr = `${hoursForDisplay}:${minutesPadded} ${ampm}`;
    
      // ✅ Create date + time
      const slotDateTime = new Date(appointmentDate);
      slotDateTime.setHours(slotHours);
      slotDateTime.setMinutes(slotMins);
      slotDateTime.setSeconds(0);
      slotDateTime.setMilliseconds(0);
    
      // ✅ Add 5 hours 30 minutes (19800000 milliseconds)
      const slotDateTimeIST = new Date(slotDateTime.getTime() + 5.5 * 60 * 60 * 1000);
    
      slotsToInsert.push({
        adminId,
        date: slotDateTimeIST,  // Date shifted to IST
        time: timeStr,
        isAvailable: true,
      });
    }

    // Save slots in bulk
    await Slot.insertMany(slotsToInsert);
    console.log(`Inserted ${slotsCount} slots.`);

    res.send('Slots created successfully');
  } catch (error) {
    console.error('Error creating slots:', error);
    res.status(500).send('Internal server error');
  }
});

const axios = require('axios');

// Replace simulated sendSms with Fast2SMS integration
// async function sendSms(mobile, otp) {
//   try {
//     const response = await axios.post(
//       'https://www.fast2sms.com/dev/bulkV2',
//       {
//         variables_values: otp,
//         route: 'otp',
//         numbers: mobile
//       },
//       {
//         headers: {
//           'authorization': process.env.FAST2SMS_API_KEY,
//           'Content-Type': 'application/json'
//         }
//       }
//     );

//     console.log("SMS sent:", response.data);
//   } catch (error) {
//     console.error("Error sending SMS:", error.response?.data || error.message);
//   }
// }


// function to generate OTP
function generateOtp() {
  return Math.floor(100000 + Math.random() * 900000).toString();  // 6-digit OTP as string
}

function sendSms(mobile, otp) {
  console.log(`[SIMULATED] OTP ${otp} sent to ${mobile}`);
}

// function to share email on otp
async function sendEMail(toEmail, subject, message) {
  try {
    const transporter = nodemailer.createTransport({
      service: 'gmail',
      auth: {
        user: process.env.EMAIL_USER,     // your Gmail address (e.g., admin@gmail.com)
        pass: process.env.EMAIL_PASS      // app password, not your normal Gmail password
      }
    });

    const mailOptions = {
      from: `"Admin Panel" <${process.env.EMAIL_USER}>`,
      to: toEmail,
      subject: subject,
      text: message
    };

    await transporter.sendMail(mailOptions);
    console.log(` Email sent to ${toEmail}`);
  } catch (err) {
    console.error(' Error sending email:', err.message);
    throw err;
  }
}


app.post('/admin/send-otp-mobile', isAdminAuthenticated, async (req, res) => {
  try {
    const adminId = req.session?.user?._id;
    const { newMobile } = req.body; // Correct way to fetch

    if (!adminId) return res.status(401).json({ error: "Unauthorized" });
    if (!newMobile || newMobile.length !== 10) {
      return res.status(400).json({ error: "Enter a valid 10-digit mobile number" });
    }

    const existingAdmin = await Admin.findOne({ mobile: newMobile, _id: { $ne: adminId } });
    if (existingAdmin) {
      return res.status(409).json({ error: "This mobile number is already registered with another account." });
    }

    const otp = Math.floor(100000 + Math.random() * 900000).toString();

    //  Save both OTP and new mobile
    otpMap.set(`verify-mobile-${adminId}`, { otp, newMobile });

    sendSms(req.session.user.mobile, otp); // send to current mobile, not new
    return res.json({ message: `OTP sent to registered mobile number.` });

  } catch (err) {
    console.error("Send mobile OTP error:", err);
    res.status(500).json({ error: "Failed to send OTP to mobile" });
  }
});



app.post('/admin/change-mobile', isAdminAuthenticated, async (req, res) => {
  try {
    const adminId = req.session?.user?._id;
    const { mobile, otp } = {
      mobile: req.body.mobile,
      otp: req.body["otp-mobile"]
    };
    
    if (!adminId) return res.status(401).json({ error: "Unauthorized" });

    const storedOtp = otpMap.get(`verify-mobile-${adminId}`);
    console.log("🧾 Expected OTP:", storedOtp, "| Received:", otp);

      if (!storedOtp) {
        return res.status(400).json({ error: "OTP record not found or expired." });
      }
      
      if (storedOtp.otp != otp) {
        return res.status(400).json({ error: "Invalid OTP. Please try again." });
      }
      
      try {
        await Admin.findByIdAndUpdate(adminId, { mobile: storedOtp.newMobile });
        otpMap.delete(`change-mobile-${adminId}`);
        return res.json({ success: true, message: "Mobile number updated successfully." });
      } catch (err) {
        console.error("Error updating mobile:", err);
        return res.status(500).json({ error: "Failed to update mobile number." });
      }
      
  } catch (err) {
    console.error("Verify OTP Error:", err);
    res.status(500).json({ error: "Server error during OTP verification." });
  }
});


app.post('/admin/send-otp-password', isAdminAuthenticated, async (req, res) => {
  try {
    const adminId = req.session?.user?._id;
    const { newPassword, confirmPassword } = req.body;

    if (!adminId) return res.status(401).json({ error: "Unauthorized" });

    if (!newPassword || !confirmPassword) {
      return res.status(400).json({ error: "New and confirm passwords are required." });
    }

    if (newPassword !== confirmPassword) {
      return res.status(400).json({ error: "new and confirm Passwords do not match." });
    }

    const admin = await Admin.findById(adminId);
    if (!admin || !admin.mobile) {
      return res.status(404).json({ error: "Admin not found or mobile number missing" });
    }

    const otp = Math.floor(100000 + Math.random() * 900000).toString();

    //  Save OTP + password temporarily
    otpMap.set(`verify-password-${adminId}`, { otp, newPassword });
    console.log("Saved OTP record:", otpMap.get(`verify-password-${adminId}`));


    sendSms(admin.mobile, otp);

    return res.json({ message: `OTP sent to registered mobile ending in ${admin.mobile.slice(-4)}` });

  } catch (err) {
    console.error("Password OTP error:", err);
    return res.status(500).json({ error: "Failed to send OTP for password change" });
  }
});


// to verify otp for change-password
app.post('/admin/verify-password-otp', async (req, res) => {
  try {
    const adminId = req.session?.user?._id;
    const { newPassword, confirmPassword, otp } = req.body;

    console.log("Route hit at", new Date().toISOString());
    console.log("adminId:", adminId);
    console.log("Entered OTP:", otp);

    if (!adminId) {
      return res.status(401).json({ error: "Unauthorized" });
    }

    // ✅ Verify OTP
    const record = otpMap.get(`verify-password-${adminId}`);
    console.log("OTP record:", record);

    if (!record || record.otp !== otp) {
      return res.status(400).json({ error: "Invalid or expired OTP" });
    }

    // ✅ Validate passwords
    if (!newPassword || !confirmPassword || newPassword !== confirmPassword) {
      return res.status(400).json({ error: "Passwords do not match" });
    }

    // ✅ Hash and save the new password
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    await Admin.findByIdAndUpdate(adminId, { password: hashedPassword });

    // ✅ Clear OTP
    otpMap.delete(`verify-password-${adminId}`);
    console.log(`OTP for admin ${adminId} cleared.`);

    return res.json({ success: true, message: "Password updated successfully." });

  } catch (err) {
    console.error("Error verifying password OTP:", err);
    return res.status(500).json({ error: "Failed to change password. Please try again." });
  }
});




app.post('/admin/send-otp-email', async (req, res) => {
  try {
    const adminId = req.session?.user?._id;
    const { newEmail } = req.body;

    if (!adminId) return res.status(401).json({ error: "Unauthorized" });

    if (!newEmail || !/^\S+@\S+\.\S+$/.test(newEmail)) {
      return res.status(400).json({ error: "Please provide a valid email address." });
    }

    // Check if the new email is already taken by another admin
    const existingAdmin = await Admin.findOne({ email: newEmail, _id: { $ne: adminId } });
    if (existingAdmin) {
      return res.status(409).json({ error: "This email is already registered with another account." });
    }

    // ✅ Get current registered email from DB
    const admin = await Admin.findById(adminId);
    if (!admin || !admin.email) {
      return res.status(404).json({ error: "Admin's current email not found." });
    }

    // ✅ Generate OTP and store using adminId
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    otpMap.set(`verify-email-${adminId}`, { otp, newEmail });


    // ✅ Send OTP to the currently registered email (not newEmail)
    await sendEMail(admin.email, "OTP for Changing Email", `Your OTP is: ${otp}`);

    return res.json({
      message: `OTP sent to your registered email ending in ${admin.email.slice(-10)}`
    });

  } catch (err) {
    console.error("Email OTP error:", err);
    return res.status(500).json({ error: "Failed to send OTP to current email" });
  }
});

app.post('/admin/change-email', async (req, res) => {
  const adminId = req.session?.user?._id;
  const { 'new-email': newEmail, 'otp-email': otp } = req.body;

  if (!adminId) return res.status(401).send("Unauthorized");

  const admin = await Admin.findById(adminId);
  if (!admin) return res.status(404).send("Admin not found");

  const record = otpMap.get(`verify-email-${adminId}`);
  console.log({ storedOtp: record?.otp, receivedOtp: otp });

  if (!record || record.otp !== otp) {
    return res.status(400).send("OTP verification failed");
  }

  admin.email = newEmail;
  await admin.save();
  otpMap.delete(`verify-email-${adminId}`);

  res.send("Email updated successfully");
});

// Office Address OTP Sending
app.post('/admin/send-address-otp', isAdminAuthenticated, async (req, res) => {
  const { office_address } = req.body;
  const adminId = req.session.adminId;

  if (!office_address) {
    return res.status(400).json({ error: 'Office address is required.' });
  }

  const otp = Math.floor(100000 + Math.random() * 900000).toString();

  // Save OTP & new address in memory (for production, use Redis or DB)
  otpMap.set(`verify-address-${adminId}`, {
    otp,
    office_address,
    createdAt: Date.now()
  });

  console.log("Saved OTP record:", otpMap.get(`verify-address-${adminId}`));

  try {
    await sendSms(req.session.mobile, otp);
    res.json({ message: 'OTP sent to your registered mobile.' });
  } catch (error) {
    console.error('Error sending SMS:', error);
    res.status(500).json({ error: 'Failed to send OTP.' });
  }
});

// Office Address OTP Verification & Update
app.post('/admin/verify-address-otp', isAdminAuthenticated, async (req, res) => {
  const { 'otp_office': enteredOtp } = req.body;
  const adminId = req.session.adminId;

  const record = otpMap.get(`verify-address-${adminId}`);

  if (!record) {
    return res.status(400).send('OTP expired or not requested.');
  }

  console.log('Record found:', record);

  // Optional: Expiry check (5 mins)
  const otpExpiryMs = 5 * 60 * 1000;
  if (Date.now() - record.createdAt > otpExpiryMs) {
    otpMap.delete(`verify-address-${adminId}`);
    return res.status(400).send('OTP has expired. Please request a new one.');
  }

  if (enteredOtp !== record.otp) {
    return res.status(400).send('Invalid OTP.');
  }

  try {
    await Admin.findOneAndUpdate(
      { adminId },
      { corporateAdress: record.office_address }
    );

    console.log(`Admin ${adminId} address updated to:`, record.office_address);
    otpMap.delete(`verify-address-${adminId}`);
    console.log(`OTP for admin ${adminId} cleared.`);

    res.redirect('/admin/admin_dashboard');
  } catch (error) {
    console.error('Error updating address:', error);
    res.status(500).send('Failed to update address.');
  }
});




app.post('/contact', (req, res)=>{
    var myData = new queries(req.body);
    console.log(myData)
    myData.save().then(()=>{
        res.status(200).render('../views/index.pug');
    }).catch((error)=>{
        console.error(error);
        res.status(400).send("Item was not saved to the database");
    });
});


// Utility: Convert to 24-hour format from 12-hour (hh:mm AM/PM)
function convertTo24Hour(hours, minutes, ampm) {
  hours = parseInt(hours, 10);
  minutes = parseInt(minutes, 10);

  if (ampm === 'PM' && hours !== 12) hours += 12;
  if (ampm === 'AM' && hours === 12) hours = 0;

  return { hours, minutes };
}


// otp verification to submit appointment finally:
app.post('/send-appointment-otp', async (req, res) => {
  try {
    const { phoneNumber } = req.body;

    if (!phoneNumber || !/^\d{10}$/.test(phoneNumber)) {
      return res.status(400).json({ success: false, message: 'Invalid phone number' });
    }

    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    otpMap.set(`verify-appointment-${phoneNumber}`, { otp });

    sendSms(phoneNumber, `Your OTP for appointment booking is: ${otp}`);

    return res.json({ success: true, message: `OTP sent to ${phoneNumber.slice(-4)}` });
  } catch (err) {
    console.error('Error sending appointment OTP:', err);
    return res.status(500).json({ success: false, message: 'Failed to send OTP' });
  }
});

app.post('/submit-appointment', async (req, res) => {
  try {
    const { appointmentDate, appointmentTime, name, phoneNumber, email, otp, uniqueId } = req.body;

    if (!otp) {
      return res.status(400).json({ success: false, error: 'OTP is required' });
    }

    // ✅ Step 1: Verify OTP First
    const record = otpMap.get(`verify-appointment-${phoneNumber}`);
    console.log('OTP record:', record, otp.toString());

    if (!record || record.otp !== otp.toString()) {
      return res.status(400).json({ success: false, error: 'Invalid or expired OTP' });
    }

    // ⚠️ Delete OTP immediately to prevent reuse
    otpMap.delete(`verify-appointment-${phoneNumber}`);

    // ✅ Step 2: Parse date and time
    const [day, month, year] = appointmentDate.split('-').map(Number);
    const [timePart, ampm] = appointmentTime.split(' ');
    const [hh, mm] = timePart.split(':');
    const { hours, minutes } = convertTo24Hour(hh, mm, ampm);

    // ✅ Step 3: Create IST date and shift to UTC
    const localDate = new Date(year, month - 1, day, hours, minutes, 0, 0);
    const appointmentDateUTC = new Date(localDate.getTime() + 330 * 60 * 1000);
    console.log('Booking Date (UTC):', appointmentDateUTC);

    // ✅ Step 4: Find and update slot
    const slot = await Slot.findOne({ adminId:uniqueId, date: appointmentDateUTC, time: appointmentTime });
    if (!slot) {
      return res.status(404).json({ success: false, error: 'Slot does not exist.' });
    }

    if (!slot.isAvailable) {
      return res.status(400).json({ success: false, error: 'Slot is no longer available.' });
    }

    slot.isAvailable = false;
    await slot.save();

    // ✅ Step 5: Save appointment
    const newAppointment = new Appointment({
      adminId: uniqueId,
      name,
      phoneNumber,
      email,
      appointmentDate: appointmentDateUTC,
      appointmentTime,
      status: 'Pending',
    });
    await newAppointment.save();

    // ✅ Step 6: Send confirmation email
    const message = `Dear ${name},\n\nYour appointment is booked for ${appointmentDate} at ${appointmentTime}.\n\nThank you.`;
    // await sendEMail(email, 'Appointment Confirmation', message);

    return res.json({ success: true, message: 'Appointment booked successfully and email sent.' });

  } catch (err) {
    console.error('Error submitting appointment:', err);
    res.status(500).json({ success: false, error: 'Internal server error. Please try again.' });
  }
});



// update remarks
app.post('/admin/update-remark', isAdminAuthenticated, async (req, res) => {
  const { appointmentId, remark } = req.body;

  try {
    await Appointment.findByIdAndUpdate(appointmentId, { remark });
    res.json({ success: true, message: 'Remark updated.' });
  } catch (error) {
    console.error('Error updating remark:', error);
    res.status(500).json({ error: 'Failed to update remark.' });
  }
});

// for interactive stats
app.get('/admin/stats', isAdminAuthenticated, async (req, res) => {
  try {
    const total = await Appointment.countDocuments({adminId:req.session.adminId});
    const confirmed = await Appointment.countDocuments({ adminId:req.session.adminId, status: 'Confirmed' });

    const now = new Date();
    now.setTime(now.getTime()+330*60*1000);
    console.log(now)
    const upcoming = await Appointment.countDocuments({ adminId:req.session.adminId, appointmentDate: { $gte: now }, status: 'Pending' });
    console.log(upcoming)
    const past = await Appointment.countDocuments({ adminId:req.session.adminId, appointmentDate: { $lt: now }, status: { $in: ['Pending', 'Confirmed'] } });

    res.json({ total, confirmed, upcoming, past });
  } catch (err) {
    console.error('Error fetching stats:', err);
    res.status(500).json({ total: 0, confirmed: 0, upcoming: 0, past: 0 });
  }
});

app.get('/profile', async (req, res) => {
  if (!req.session.user) {
    return res.redirect('/admin/login');
  }

  try {
    const user = await Admin.findById(req.session.user._id); // ✅ fetch full user data

    if (!user) {
      return res.redirect('/admin/login'); // or show an error page
    }

    res.render('profile', { user });
  } catch (error) {
    console.error('Error fetching user profile:', error);
    res.status(500).send('Error loading profile');
  }
});

// START THE SERVER
https.createServer(sslOptions, app).listen(3000, () => {
  console.log('Server running at https://localhost:3000');
});



// module.exports = app;