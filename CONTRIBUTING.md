# Contributing to FalconScan

Thank you for your interest in contributing to FalconScan! This document provides guidelines for contributing to the project.

## Code of Conduct

- Be respectful and inclusive
- Provide constructive feedback
- Focus on what is best for the community

## How to Contribute

### Reporting Bugs

1. Check if the bug has already been reported in Issues
2. Create a new issue with a clear title and description
3. Include steps to reproduce, expected behavior, and actual behavior
4. Add relevant logs, screenshots, or code snippets

### Suggesting Features

1. Check if the feature has already been suggested
2. Create a new issue with the "enhancement" label
3. Clearly describe the feature and its benefits
4. Include mockups or examples if applicable

### Pull Requests

1. Fork the repository
2. Create a new branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Test thoroughly
5. Commit with clear messages (`git commit -m 'Add amazing feature'`)
6. Push to your branch (`git push origin feature/amazing-feature`)
7. Open a Pull Request

### Development Setup

```bash
# Backend
cd backend
python -m venv venv
source venv/bin/activate  # or venv\Scripts\activate on Windows
pip install -r requirements.txt
python manage.py migrate
python manage.py runserver

# Frontend
npm install
cp .env.example .env.local
npm run dev
```

### Code Standards

- Follow PEP 8 for Python code
- Use TypeScript for frontend code
- Write meaningful commit messages
- Add comments for complex logic
- Update documentation as needed
- Write tests for new features

### Testing

- Test all changes locally before submitting
- Ensure no breaking changes to existing functionality
- Add unit tests for new features
- Verify UI changes across different screen sizes

## Questions?

Feel free to open an issue with your question or reach out to the maintainers.
