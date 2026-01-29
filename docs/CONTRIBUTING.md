# Contributing to CTF-AI Ultimate

First off, thank you for considering contributing to CTF-AI Ultimate! 🎉

## How Can I Contribute?

### 🐛 Reporting Bugs

If you find a bug:
1. Check if it's already reported in [Issues](../../issues)
2. If not, create a new issue with:
   - Clear title and description
   - Steps to reproduce
   - Expected vs actual behavior
   - Your environment (OS, Python version, etc.)

### 💡 Suggesting Features

Have an idea? Great!
1. Check [Issues](../../issues) to see if it's already suggested
2. Create a new issue with:
   - Clear description of the feature
   - Why it would be useful
   - Possible implementation approach

### 🔧 Contributing Code

#### Adding New Playbooks

The easiest way to contribute! Create a JSON playbook for a specific challenge type:

```json
{
    "name": "Your Playbook Name",
    "description": "What this playbook does",
    "category": "category_name",
    "file_types": [".ext1", ".ext2"],
    "execution_strategy": "sequential",
    "methods": [
        {
            "name": "Method Name",
            "description": "What this does",
            "type": "tool",
            "tool": "tool-name",
            "args": ["{target}"],
            "timeout": 60
        }
    ]
}
```

Save to `playbooks/your_playbook.json`

#### Adding New Tools

Integrate a new security tool:

1. Add tool installation to `install.sh`
2. Create method in appropriate playbook
3. Test thoroughly
4. Submit PR

#### Improving AI Prompts

Better prompts = smarter AI! Edit:
- `modules/ai_engine.py` - System prompts
- Make prompts more specific and accurate

### 📝 Pull Request Process

1. Fork the repo
2. Create a new branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Test thoroughly
5. Commit with clear message (`git commit -m 'Add amazing feature'`)
6. Push to your fork (`git push origin feature/amazing-feature`)
7. Open a Pull Request

### ✅ Code Standards

- **Python**: Follow PEP 8
- **Comments**: Document complex logic
- **Error Handling**: Always use try-except
- **Testing**: Test with real CTF challenges

### 🎯 Priority Areas

We especially welcome contributions in:
- [ ] New playbooks for specific CTF types
- [ ] Tool integrations
- [ ] AI prompt improvements
- [ ] Documentation improvements
- [ ] Bug fixes
- [ ] Performance optimizations

### 💬 Questions?

- Open a [Discussion](../../discussions)
- Check existing [Issues](../../issues)

## Code of Conduct

Be respectful, inclusive, and collaborative. We're all here to learn and improve cybersecurity skills!

## Recognition

Contributors will be:
- Listed in README.md
- Credited in release notes
- Part of an awesome open-source community!

---

**Thank you for making CTF-AI Ultimate better!** 🚀

Happy Hacking! 🔥
