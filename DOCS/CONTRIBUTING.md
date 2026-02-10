# Contributing to Identity Hygiene Scanner

Thank you for your interest in contributing! This document provides guidelines for contributing to the project.

## 🤝 How to Contribute

### Reporting Bugs

1. **Check existing issues** to avoid duplicates
2. **Use the bug report template** when creating a new issue
3. **Include**:
   - Clear description of the problem
   - Steps to reproduce
   - Expected vs actual behavior
   - Environment details (OS, Python version, browser)
   - Screenshots if applicable

### Suggesting Features

1. **Check existing feature requests** first
2. **Open a new issue** with the "enhancement" label
3. **Describe**:
   - The problem it solves
   - Proposed solution
   - Alternative approaches considered
   - Security implications

### Security Vulnerabilities

**Do NOT open public issues for security vulnerabilities!**

See [SECURITY.md](SECURITY.md) for responsible disclosure process.

## 🔧 Development Setup

### Prerequisites

- Python 3.8 or higher
- Git
- Virtual environment tool (venv)

### Setup Steps

1. **Fork and clone**:
   ```bash
   git clone https://github.com/YOUR-USERNAME/identity-hygiene-scanner.git
   cd identity-hygiene-scanner
   ```

2. **Create virtual environment**:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

4. **Run tests**:
   ```bash
   python -m pytest tests/ -v
   ```

## 📝 Coding Standards

### Python Code Style

- Follow **PEP 8** style guide
- Use **type hints** where applicable
- Maximum line length: **88 characters** (Black formatter)
- Use **docstrings** for all functions and classes

Example:
```python
def analyze_password(password: str) -> Dict[str, Any]:
    """
    Analyze password strength.
    
    Args:
        password: The password to analyze
        
    Returns:
        Dictionary containing analysis results
        
    Raises:
        ValueError: If password is None
    """
    pass
```

### Security Requirements

**CRITICAL**: Every contribution must maintain security standards:

1. **No external dependencies** without approval
2. **No data persistence** (in-memory only)
3. **Input validation** on all user inputs
4. **Output encoding** to prevent XSS
5. **No sensitive data in logs** or error messages
6. **Security headers** must remain intact

### Testing Requirements

**All new features must include tests:**

- Unit tests for new functions
- Integration tests for new endpoints
- Security tests for input validation
- Minimum 80% code coverage

Example test:
```python
def test_password_strength_weak(self):
    """Test weak password detection"""
    result = PasswordAnalyzer.analyze("password123")
    self.assertLess(result['score'], 40)
    self.assertIn('common', ' '.join(result['issues']).lower())
```

## 🔀 Pull Request Process

### Before Submitting

1. **Create a feature branch**:
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **Make your changes** following coding standards

3. **Write tests** for new functionality

4. **Run all tests**:
   ```bash
   python -m pytest tests/ -v --cov=app
   ```

5. **Update documentation** if needed

6. **Commit with clear messages**:
   ```bash
   git commit -m "Add: Password entropy calculation improvement"
   ```

### PR Checklist

- [ ] Code follows style guidelines
- [ ] Tests written and passing
- [ ] Documentation updated
- [ ] No security vulnerabilities introduced
- [ ] No new external dependencies (or approved)
- [ ] Commit messages are clear
- [ ] Branch is up to date with main

### PR Template

```markdown
## Description
Brief description of changes

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Security improvement
- [ ] Documentation update
- [ ] Performance improvement

## Testing
Describe testing performed

## Security Considerations
Any security implications?

## Screenshots (if applicable)
Add screenshots for UI changes
```

## 🎨 Frontend Contributions

### HTML/CSS Guidelines

- **Semantic HTML**: Use appropriate tags
- **Accessibility**: ARIA labels where needed
- **Responsive design**: Mobile-first approach
- **No inline styles**: Use CSS classes
- **No external CDNs**: All assets local

### JavaScript Guidelines

- **ES6+ syntax**: Use modern JavaScript
- **No jQuery**: Vanilla JS only
- **XSS prevention**: Use textContent, not innerHTML
- **Input sanitization**: Validate all user inputs
- **Comments**: Explain complex logic

## 🧪 Testing Guidelines

### Writing Good Tests

**Test naming**:
```python
def test_[feature]_[scenario]_[expected_result](self):
    """Clear description of what is being tested"""
```

**Test structure** (AAA pattern):
```python
def test_password_check_empty_password(self):
    # Arrange
    password = ""
    
    # Act
    result = PasswordAnalyzer.analyze(password)
    
    # Assert
    self.assertEqual(result['score'], 0)
```

**Security tests**:
Every new endpoint must have tests for:
- Valid inputs
- Invalid inputs
- Empty inputs
- Maximum length inputs
- Malicious inputs (XSS, SQL injection patterns)

### Running Tests

```bash
# All tests
python -m pytest tests/

# Specific test file
python -m pytest tests/test_identity_checks.py

# Specific test
python -m pytest tests/test_identity_checks.py::TestPasswordAnalyzer::test_weak_password

# With coverage
python -m pytest tests/ --cov=app --cov-report=html

# Verbose output
python -m pytest tests/ -v

# Stop on first failure
python -m pytest tests/ -x
```

## 📚 Documentation Guidelines

### Code Documentation

**Docstrings** (Google style):
```python
def function_name(param1: str, param2: int) -> bool:
    """
    Brief description.
    
    Detailed explanation if needed.
    
    Args:
        param1: Description of param1
        param2: Description of param2
        
    Returns:
        Description of return value
        
    Raises:
        ValueError: When this happens
        
    Example:
        >>> function_name("test", 5)
        True
    """
```

**Comments**:
- Explain WHY, not WHAT
- Use for complex algorithms
- Security rationale for decisions

### README Updates

When adding features, update:
- Feature list
- Usage examples
- API documentation
- Screenshots

## 🚀 Release Process

Maintainers follow this process:

1. **Version bump** (semantic versioning)
2. **Update CHANGELOG.md**
3. **Run full test suite**
4. **Security audit**
5. **Create release notes**
6. **Tag release**
7. **Deploy to PyPI** (if applicable)

## 💡 Ideas for Contributions

### Good First Issues

- Add more common password patterns
- Improve password strength algorithms
- Add more unit tests
- Improve documentation
- Fix typos
- Add more MFA methods

### Advanced Contributions

- Implement rate limiting
- Add i18n/l10n support
- Performance optimizations
- Accessibility improvements
- Additional security features
- Browser extension

## 📜 Code of Conduct

### Our Pledge

We pledge to make participation in our project a harassment-free experience for everyone, regardless of age, body size, disability, ethnicity, gender identity, level of experience, nationality, personal appearance, race, religion, or sexual identity and orientation.

### Our Standards

**Positive behaviors**:
- Using welcoming and inclusive language
- Being respectful of differing viewpoints
- Gracefully accepting constructive criticism
- Focusing on what is best for the community

**Unacceptable behaviors**:
- Trolling, insulting/derogatory comments
- Public or private harassment
- Publishing others' private information
- Other conduct which could reasonably be considered inappropriate

### Enforcement

Instances of abusive, harassing, or otherwise unacceptable behavior may be reported to the project team. All complaints will be reviewed and investigated promptly and fairly.

## 🏆 Recognition

Contributors will be:
- Listed in CONTRIBUTORS.md
- Mentioned in release notes
- Added to project README

## ❓ Questions?

- Open a [GitHub Discussion](https://github.com/yourusername/identity-hygiene-scanner/discussions)
- Email: contributors@example.com

## 📄 License

By contributing, you agree that your contributions will be licensed under the MIT License.

---

Thank you for contributing to Identity Hygiene Scanner! 🙏
