# Email Configuration Guide

## Overview
This application supports two modes for email functionality:
1. **GreenMail (Development/Testing)**: An embedded email server for testing without external dependencies
2. **Real SMTP Server (Production)**: Configuration for sending emails to real users

## Configuration

### Basic Configuration in application.properties
```properties
# Toggle between GreenMail and real SMTP
mail.use.greenmail=true  # Set to false to use real SMTP

# Real SMTP server settings
spring.mail.host=smtp.gmail.com
spring.mail.port=587
spring.mail.username=your-email@gmail.com
spring.mail.password=your-app-password
spring.mail.properties.mail.smtp.auth=true
spring.mail.properties.mail.smtp.starttls.enable=true
spring.mail.properties.mail.debug=true

# Email sender configuration
mailing.from-email=noreply@example.com
mailing.frontend.activation-url=http://localhost:8080/api/auth/activate-account
```

### Gmail Configuration
For Gmail, you need to use an App Password instead of your regular password:
1. Enable 2-Step Verification on your Google account
2. Generate an App Password at: https://myaccount.google.com/apppasswords
3. Use this App Password in your configuration

### Other Email Providers
Adjust the SMTP settings according to your email provider:

#### Outlook/Office 365
```properties
spring.mail.host=smtp.office365.com
spring.mail.port=587
```

#### Yahoo
```properties
spring.mail.host=smtp.mail.yahoo.com
spring.mail.port=587
```

#### Amazon SES
```properties
spring.mail.host=email-smtp.us-east-1.amazonaws.com
spring.mail.port=587
```

## Testing Email Functionality

### Using GreenMail (Development)
1. Set `mail.use.greenmail=true` in application.properties
2. Use the EmailTestController endpoints to test email sending
3. View sent emails in the console logs or via the `/api/test/email/received` endpoint

### Using Real SMTP (Production)
1. Set `mail.use.greenmail=false` in application.properties
2. Configure your SMTP server details
3. Emails will be sent to real email addresses
4. Check your email provider's sent items folder to verify emails

## Security Considerations
1. The EmailTestController is only available in development and test environments
2. Never commit real email credentials to version control
3. Consider using environment variables for sensitive information:
   ```properties
   spring.mail.username=${EMAIL_USERNAME}
   spring.mail.password=${EMAIL_PASSWORD}
   ```
4. In production, ensure proper error handling for email sending failures