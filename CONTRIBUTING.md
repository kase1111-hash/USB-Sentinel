# Contributing to USB Sentinel

Thank you for your interest in contributing to USB Sentinel! This document provides guidelines and information for contributors.

## Getting Started

### Prerequisites

- Python 3.10 or higher
- Linux system (USB interception requires Linux-specific APIs)
- libusb development headers
- Node.js 18+ (for dashboard development)

### Development Setup

1. **Clone the repository**
   ```bash
   git clone https://github.com/kase1111-hash/USB-Sentinel.git
   cd USB-Sentinel
   ```

2. **Create a virtual environment**
   ```bash
   python -m venv venv
   source venv/bin/activate
   ```

3. **Install development dependencies**
   ```bash
   pip install -e ".[dev]"
   ```

4. **Install system dependencies**
   ```bash
   # Ubuntu/Debian
   sudo apt-get install libusb-1.0-0-dev libudev-dev

   # Fedora
   sudo dnf install libusb1-devel systemd-devel
   ```

5. **Set up the dashboard (optional)**
   ```bash
   cd dashboard
   npm install
   ```

## Development Workflow

### Code Style

This project uses:
- **Ruff** for Python linting and formatting
- **MyPy** for type checking
- **ESLint** for TypeScript/JavaScript

Run linters before submitting:
```bash
# Python
ruff check src/ tests/
ruff format src/ tests/

# Type checking
mypy src/sentinel --ignore-missing-imports
```

### Running Tests

```bash
# Run all tests
pytest tests/ -v

# Run with coverage
pytest tests/ -v --cov=sentinel --cov-report=html

# Run specific test file
pytest tests/test_policy.py -v
```

### Project Structure

```
src/sentinel/
├── interceptor/     # USB event capture layer
├── policy/          # Rule evaluation engine
├── analyzer/        # LLM integration
├── proxy/           # Virtual USB proxy
├── audit/           # SQLite audit logging
├── api/             # FastAPI REST API
└── core/            # Core processor logic
```

## Submitting Changes

### Pull Request Process

1. **Create a feature branch**
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **Make your changes**
   - Write clear, concise commit messages
   - Include tests for new functionality
   - Update documentation as needed

3. **Ensure quality checks pass**
   ```bash
   ruff check src/ tests/
   ruff format --check src/ tests/
   pytest tests/ -v
   ```

4. **Submit a pull request**
   - Provide a clear description of the changes
   - Reference any related issues
   - Ensure CI checks pass

### Commit Message Guidelines

Follow conventional commit format:
```
type(scope): description

[optional body]

[optional footer]
```

Types:
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Code style changes (formatting, etc.)
- `refactor`: Code refactoring
- `test`: Test additions or modifications
- `chore`: Maintenance tasks

Examples:
```
feat(policy): add support for wildcard VID matching
fix(interceptor): handle USB hub enumeration correctly
docs(readme): update installation instructions
```

## Areas for Contribution

### High Priority

- **Windows support**: Implement USB interception for Windows using WinUSB
- **macOS support**: Implement USB interception for macOS using IOKit
- **Additional LLM backends**: Support for other LLM providers (OpenAI, local models)
- **Policy templates**: Pre-built policy configurations for common use cases

### Documentation

- User guides and tutorials
- API documentation
- Architecture deep-dives

### Testing

- Additional unit tests
- Integration test scenarios
- Performance benchmarks

## Security Considerations

Since USB Sentinel is a security tool, please be especially mindful of:

- **Input validation**: All user inputs and device data must be sanitized
- **Privilege management**: Minimize required privileges where possible
- **Audit logging**: Security-relevant operations must be logged
- **Prompt injection**: LLM inputs must be protected against injection attacks

See [SECURITY.md](SECURITY.md) for reporting security vulnerabilities.

## Questions?

- Open a [GitHub Discussion](https://github.com/kase1111-hash/USB-Sentinel/discussions)
- Check existing [Issues](https://github.com/kase1111-hash/USB-Sentinel/issues)

## License

By contributing to USB Sentinel, you agree that your contributions will be licensed under the MIT License.
