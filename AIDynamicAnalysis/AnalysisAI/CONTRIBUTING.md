# Contributing to AnalysisAI

## Code Style Guidelines

### C Language Standards
- Use C11 standard (`-std=c11`)
- Prefer POSIX APIs
- Follow existing code patterns

### Formatting
- 4-space indentation
- Maximum 100 character line length
- Add blank lines between logical sections
- Use meaningful variable names (camelCase for locals)
- Use PascalCase for types and structs

### Comments
- Add comments for complex logic
- Document function purposes
- Explain non-obvious design decisions
- Keep comments clear and concise

### Headers
Include guards:
```c
#ifndef MODULE_NAME_H
#define MODULE_NAME_H

// declarations

#endif // MODULE_NAME_H
```

## Module Structure

Each module should have:
- Header file (`.h`) with public API
- Implementation file (`.c`) with proper includes
- Clear documentation of functions
- Proper error handling

## Testing Changes

1. Build locally:
   ```bash
   make clean && make
   ```

2. Test with sample binaries:
   ```bash
   ./AnalysisAI -b /bin/ls -m openai -k $KEY
   ```

3. Verify output in session directory

## Error Handling

- Check for NULL pointers at entry points
- Free allocated memory in cleanup functions
- Return meaningful error codes (-1 for failure, 0 for success)
- Log errors to stderr
- Provide user-friendly error messages

## Memory Management

- Free all dynamically allocated memory
- Use `malloc`/`free` consistently
- No memory leaks allowed
- Document ownership of pointers in function signatures

## Pull Request Process

1. Make changes to appropriate module
2. Test thoroughly
3. Update documentation if needed
4. Ensure code compiles without warnings
5. Submit changes with clear description

## Reporting Issues

Include:
- OS and version
- Compiler version
- Steps to reproduce
- Expected vs actual behavior
- Build output/errors
