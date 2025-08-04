require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const nodemailer = require('nodemailer');
const { google } = require('googleapis');
const path = require('path');
const app = express();

// OAuth2 setup
const OAuth2 = google.auth.OAuth2;
const oauth2Client = new OAuth2(
  process.env.EMAIL_CLIENT_ID,
  process.env.EMAIL_CLIENT_SECRET,
  'https://developers.google.com/oauthplayground' // redirect URI
);
oauth2Client.setCredentials({
  refresh_token: process.env.EMAIL_REFRESH_TOKEN
});

app.use(bodyParser.urlencoded({ extended: false }));
app.use(express.static(path.join(__dirname, 'public')));

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'contact.html'));
});

app.post('/send', async (req, res) => {
  const { from_name, from_email, message } = req.body;

  try {
    const accessToken = await oauth2Client.getAccessToken();

    const transporter = nodemailer.createTransport({
      service: 'gmail',
      auth: {
        type: 'OAuth2',
        user: process.env.EMAIL_USER,
        clientId: process.env.EMAIL_CLIENT_ID,
        clientSecret: process.env.EMAIL_CLIENT_SECRET,
        refreshToken: process.env.EMAIL_REFRESH_TOKEN,
        accessToken:'ya29.a0AS3H6Nxgl63U_NO_XoU-imUSgV3ajeutUPK8jTA4zuTjvz4TjWvJ9KG9faSt_hYOwnu5zMU36Pkat7bD8wJpgK84gbWauIkOvZdARz1RumdovWn6jCFWcRTIU5ClhZRkqvi3p25XdkeDNJbJlW4PwrqIf5KSgZWVGEFTCQx_aCgYKAVsSARISFQHGX2MigvQq6RMx9CMp3OBhaf7B1A0175'
      }
    });

    const mailOptions = {
      from: from_email,
      to: 'daniel.portis@hgs.hiddengeniusproject.org',
      subject: `Contact from ${from_name}`,
      text: message
    };

    const info = await transporter.sendMail(mailOptions);
    console.log("Email sent:", info.response);
    res.redirect('/?sent=true');
  } catch (err) {
    console.error("Email error:", err);
    res.status(500).send("Error sending email: " + err.message);
  }
});

const PORT = 3000;
app.listen(PORT, () => console.log(`Server running at http://localhost:${PORT}`));
