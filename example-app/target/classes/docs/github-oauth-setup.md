# GitHub OAuth Setup Guide

## Overview
This application supports authentication with GitHub using OAuth 2.0. This guide will help you set up GitHub OAuth for your application.

## Steps to Configure GitHub OAuth

### 1. Create a GitHub OAuth App
1. Go to your GitHub account settings
2. Navigate to "Developer settings" > "OAuth Apps" > "New OAuth App"
3. Fill in the application details:
   - **Application name**: Your application name
   - **Homepage URL**: Your application's homepage (e.g., `http://localhost:8080`)
   - **Authorization callback URL**: `http://localhost:8080/login/oauth2/code/github`
4. Click "Register application"
5. After registration, you'll see your Client ID
6. Generate a new Client Secret by clicking "Generate a new client secret"

### 2. Configure Your Application

#### Option 1: Using Environment Variables (Recommended)
Set the following environment variables:
```
GITHUB_CLIENT_ID=your_client_id_here
GITHUB_CLIENT_SECRET=your_client_secret_here
```

#### Option 2: Update application.yml Directly
Update the `application.yml` file with your GitHub OAuth credentials:
```yaml
spring:
  security:
    oauth2:
      client:
        registration:
          github:
            clientId: your_client_id_here
            clientSecret: your_client_secret_here
            scope:
              - user:email
              - read:user
```

## Troubleshooting

### 401 Unauthorized Error
If you receive a 401 Unauthorized error when trying to log in with GitHub:

1. **Check your credentials**: Ensure your Client ID and Client Secret are correct
2. **Verify callback URL**: Make sure the Authorization callback URL in your GitHub OAuth App matches the one in your application
3. **Check scopes**: Ensure you've requested the necessary scopes (user:email, read:user)
4. **Inspect logs**: Check your application logs for more detailed error messages

### Other Issues
- **Redirect URI mismatch**: GitHub is strict about the redirect URI matching exactly what's registered
- **Rate limiting**: GitHub has rate limits for API requests
- **Token expiration**: OAuth tokens can expire; the application should handle refreshing them

## Security Considerations
- Never commit your GitHub Client Secret to version control
- Use environment variables or a secure configuration service in production
- Consider implementing PKCE (Proof Key for Code Exchange) for additional security
- Regularly rotate your Client Secret