# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |

## Reporting a Vulnerability

If you discover a security vulnerability in FalconScan, please report it by emailing [your-email@example.com].

**Please do not report security vulnerabilities through public GitHub issues.**

We will acknowledge your email within 48 hours and send a more detailed response within 5 days indicating the next steps in handling your report.

## Security Best Practices

When deploying FalconScan in production:

1. **Environment Variables**: Use environment variables for all sensitive configuration
2. **HTTPS**: Always use HTTPS in production
3. **Secret Key**: Generate a strong, unique `DJANGO_SECRET_KEY`
4. **Debug Mode**: Set `DEBUG=False` in production
5. **Database**: Use PostgreSQL instead of SQLite
6. **File Uploads**: Implement file size limits and virus scanning
7. **Rate Limiting**: Implement rate limiting on API endpoints
8. **CORS**: Configure CORS to allow only trusted origins
9. **Updates**: Keep dependencies updated regularly

## Known Security Considerations

- APK files are stored on the server - ensure proper access controls
- Decompilation process requires sufficient system resources
- JWT tokens have 1-hour expiration by default
