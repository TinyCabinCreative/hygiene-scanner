# 🚀 Quick Start Guide

## Get Started in 3 Steps

### 1. Clone and Navigate
```bash
cd identity-hygiene-scanner
```

### 2. Set Up Environment

**Option A: Automated Setup (Recommended)**
```bash
chmod +x setup.sh
./setup.sh
```

**Option B: Manual Setup**
```bash
# Create virtual environment
python3 -m venv venv

# Activate it
source venv/bin/activate  # Linux/Mac
# OR
venv\Scripts\activate  # Windows

# Install dependencies
pip install -r requirements.txt

# Generate secret key
export SECRET_KEY=$(python -c 'import secrets; print(secrets.token_hex(32))')
```

### 3. Run the Application
```bash
python run.py
```

Then open your browser to: **http://127.0.0.1:5000**

## 🎯 What to Try

1. **Test Password Strength**
   - Try weak passwords: `password123`, `qwerty`, `123456`
   - Try strong passwords: `Tr0ub4dor&3!mP1e#2024`
   - See entropy calculations and crack time estimates

2. **Analyze Usernames**
   - Test: `john.doe` (detects name pattern)
   - Test: `admin123` (detects common pattern)
   - Test: `user1995` (detects year)

3. **Check MFA Readiness**
   - Review security rankings of different MFA methods
   - Assess your current setup
   - Follow the implementation checklist

## 🧪 Run Tests
```bash
python -m unittest discover tests -v
```

## 📸 Screenshots for GitHub

Take screenshots of:
1. Main interface (all three tabs)
2. Password analysis results (both weak and strong)
3. Username analysis results
4. MFA checklist and assessment

## 🔒 Security Note

**This tool runs 100% locally. Your passwords never leave your computer!**

- No external API calls
- No data storage
- No logging
- Privacy by design

## 📚 Next Steps

- Read the full [README.md](README.md) for detailed documentation
- Review [SECURITY.md](SECURITY.md) for security architecture
- Check [CONTRIBUTING.md](CONTRIBUTING.md) if you want to contribute
- See deployment options for production use

## ❓ Having Issues?

Common solutions:

**"No module named flask"**
```bash
pip install Flask
```

**"Permission denied" on setup.sh**
```bash
chmod +x setup.sh
```

**"Port already in use"**
```bash
# Change port in run.py
app.run(port=5001)
```

## 🎉 You're Ready!

Start analyzing your identity hygiene and improving your security posture!
