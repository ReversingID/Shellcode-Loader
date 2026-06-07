# Contributing to Shellcode-Loader

Thank you for your interest in contributing to Shellcode-Loader! This repository is an open educational resource for the cybersecurity community.

## Repository Purpose

Shellcode-Loader is a reference repository that collects techniques for loading shellcode into memory. It's designed to:
- Provide comprehensive documentation of various shellcode loading techniques
- Deliver practical implementations in C/C++
- Serve as a learning resource for security researchers and reverse engineering professionals

For more information, see [README.EN.md](README.EN.md).

## How to Contribute

### 1. Fork and Clone
Fork this repository to your GitHub account, then clone it to your local machine:
```bash
git clone https://github.com/YOUR_USERNAME/Shellcode-Loader.git
cd Shellcode-Loader
```

### 2. Create a New Branch
Create a branch with a descriptive name for your changes:
```bash
git checkout -b add/technique-name
git checkout -b fix/brief-description
git checkout -b improve/documentation
```

### 3. Make Your Changes
Follow these conventions when making changes:

#### Directory Structure and Naming Conventions
```
platform/
  └── technique/                 # allocation, storage, execution, writing, etc
      ├── README.md             # Technique documentation
      ├── source/               # Implementation (optional)
      │   ├── example.c
      │   └── example.h
      └── subtechnique/         # Sub-categories if applicable
          └── README.md
```

#### File Naming Conventions
- Use lowercase for directories. If the directory name is API function, adjust the case (lowercase or uppercase) to the function name
- Use `code` as the file name (e.g. `code.cpp`)
- Use hyphen or underscores as separators: `my-technique/`
- Avoid spaces in filenames

#### Template for New Techniques

When adding a new technique, follow this README structure:

```markdown
# [Technique Name]

### Overview
Brief explanation of the technique. What's its purpose? When is it used?

### How It Works
In-depth explanation of how the technique works. Include diagrams or flowcharts if helpful.

### Implementation
Description of the implementation, APIs used, and limitations.

### Advantages
- Advantage 1
- Advantage 2

### Disadvantages
- Disadvantage 1
- Disadvantage 2

### Code Example
```c
// Code snippet here
```

### References
- Links to API documentation
- Links to related techniques
- Papers or other resources
```

### 4. Coding Guidelines (C/C++)

#### Style Guide
- Follow GNU C style or K&R style
- Use 4 spaces for indentation (not tabs)
- Function names: lowercase with underscores (snake_case)
- Constant names: UPPERCASE with underscores
- Type names: PascalCase

#### Code Format Example
```c
#include <stdio.h>
#include <stdlib.h>
#include <windows.h>

// Constants
#define SHELLCODE_SIZE 4

// Structures
typedef struct {
    DWORD value;
    char  name[50];
} MyStruct;

// Functions
void execute_shellcode(unsigned char *shellcode, size_t size) {
    LPVOID alloc = VirtualAlloc(NULL, size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (!alloc) {
        printf("Allocation failed\n");
        return;
    }
    
    memcpy(alloc, shellcode, size);
    ((void(*)())alloc)();
    
    VirtualFree(alloc, size, MEM_RELEASE);
}
```

#### Error Handling
- Always check return values from API calls
- Provide informative error messages
- Document error conditions in comments

### 5. Documentation

#### README in Each Technique Directory
- Use Indonesian as default language
- Provide sufficient documentation for understanding
- Include working code examples
- Explain limitations and edge cases

#### Bilingual Support
- If adding new documentation, consider creating an English version
- Follow the structure of existing files

### 6. Testing and Validation

Before creating a PR:
- Compile code without warnings
- Test code on relevant platforms
- Verify implementation matches documentation
- Check for broken links in documentation

### 7. Pull Request Process

#### Before Submitting
1. Ensure your branch is up-to-date with the main branch:
   ```bash
   git fetch origin
   git rebase origin/master
   ```

2. Clean up commit history if needed:
   ```bash
   git rebase -i origin/master
   ```

3. Push to your fork:
   ```bash
   git push origin add/technique-name
   ```

#### PR Description Template
```
## Description
Brief explanation of the changes made.

## Type of Change
- [ ] New technique
- [ ] Improvement to existing code
- [ ] Documentation
- [ ] Bug fix

## Technique/Topic Modified
- Mention platform (Linux/Windows)
- Mention technique category

## Checklist
- [ ] Code compiles without warnings
- [ ] Documentation has been updated
- [ ] Links in documentation have been verified
- [ ] No broken links
```

#### Review Process
- The maintainer team will review your contribution
- There may be requests for changes or clarification
- Small changes may be accepted directly
- Larger changes will be discussed further

## License

By contributing to this repository, you agree that your contribution will be licensed under the same license as the repository. Ensure that the code you contribute does not violate any copyright or third-party licenses.

## Questions or Need Help?

If you have questions:
- Open a new issue with the `question` label
- Explain your problem or question in detail
- Provide sufficient context for understanding

## Code of Conduct

We expect all contributors to:
- Be respectful and professional
- Accept constructive criticism gracefully
- Focus on our shared goal: education and security

---

Thank you for your contribution! 🎉
