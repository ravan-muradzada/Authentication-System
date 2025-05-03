import sgMail from '@sendgrid/mail';
import chalk from 'chalk';

const sendGridAPIKey = process.env.SENDGRIDAPIKEY;

sgMail.setApiKey(sendGridAPIKey);

export const sendMail = async (emailTo, subject, text, html) => {
    const msg = {
        to: emailTo,
        from: process.env.EMAIL_FROM,
        subject,
        text,
        html
    };

    try {
        await sgMail.send(msg);
        console.log(chalk.green.bold('Email sent successfully!'));
    } catch(e) {
        console.log(chalk.red.bold('Error happened in otp sending via Email!'), error.message);
        throw new Error('Failed to send email!');
    }
}


