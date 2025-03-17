# Contributing to NeoProtect Notifier

First off, thank you for considering contributing to NeoProtect Notifier! It's people like you that make this tool better for everyone. This document provides guidelines and instructions for contributing to the project.

## Code of Conduct

By participating in this project, you agree to abide by our [Code of Conduct](CODE_OF_CONDUCT.md). Please read it before contributing.

## How Can I Contribute?

### Reporting Bugs

This section guides you through submitting a bug report. Following these guidelines helps maintainers understand your report, reproduce the behavior, and find related reports.

**Before Submitting A Bug Report:**

* Check the [issues](https://github.com/mscode-pl/neoprotect-notifier/issues) to see if the problem has already been reported.
* Ensure you're using the latest version.
* Determine if your bug is really a bug and not an expected behavior.

**How Do I Submit A Good Bug Report?**

Create an issue on the repository and provide the following information:

* **Use a clear and descriptive title** for the issue to identify the problem.
* **Describe the exact steps which reproduce the problem** in as much detail as possible.
* **Provide specific examples to demonstrate the steps**.
* **Describe the behavior you observed after following the steps** and point out what exactly is the problem with that behavior.
* **Explain which behavior you expected to see instead and why.**
* **Include screenshots or animated GIFs** if applicable.
* **If the problem wasn't triggered by a specific action**, describe what you were doing before the problem happened.
* **Include details about your configuration**:
    * Which version of the notifier are you using?
    * What's your operating system and version?
    * What's your Go version if built from source?

### Suggesting Enhancements

This section guides you through submitting an enhancement suggestion, including completely new features and minor improvements to existing functionality.

**Before Submitting An Enhancement Suggestion:**

* Check if the enhancement has already been suggested or implemented.
* Check if there's already a way to achieve what you're suggesting.

**How Do I Submit A Good Enhancement Suggestion?**

Create an issue on the repository and provide the following information:

* **Use a clear and descriptive title** for the issue to identify the suggestion.
* **Provide a step-by-step description of the suggested enhancement** in as much detail as possible.
* **Provide specific examples to demonstrate the steps** or point to similar features in other applications.
* **Describe the current behavior** and **explain which behavior you expected to see instead** and why.
* **Explain why this enhancement would be useful** to most users.

### Pull Requests

The process described here has several goals:

- Maintain code quality
- Fix problems that are important to users
- Enable a sustainable system for maintainers to review contributions

Please follow these steps to have your contribution considered by the maintainers:

1. **Fork the repository** and create your branch from `main`.
2. **Install development dependencies** as described in the README.
3. **Make your changes** following the coding guidelines below.
4. **Write or adapt tests** as necessary.
5. **Update documentation** to reflect any changes.
6. **Submit your pull request** against the `main` branch.

While the prerequisites above must be satisfied prior to having your pull request reviewed, the reviewer(s) may ask you to complete additional design work, tests, or other changes before your pull request can be ultimately accepted.

## Coding Guidelines

### Go Code Style

* Follow the [Go Code Review Comments](https://github.com/golang/go/wiki/CodeReviewComments)
* Format your code with `gofmt`
* Document all exported functions, types, and constants
* Organize imports alphabetically
* Use meaningful variable names
* Keep functions small and focused on a single responsibility
* Handle errors properly - don't ignore them!
* Use context for request cancellation and timeouts

### Git Commit Messages

* Use the present tense ("Add feature" not "Added feature")
* Use the imperative mood ("Move cursor to..." not "Moves cursor to...")
* Limit the first line to 72 characters or less
* Reference issues and pull requests liberally after the first line
* Consider starting the commit message with an applicable emoji:
    * 🐛 `:bug:` when fixing a bug
    * ✨ `:sparkles:` when adding a new feature
    * 📝 `:memo:` when writing docs
    * 🧹 `:broom:` when refactoring code
    * 🧪 `:test_tube:` when adding tests
    * 🔧 `:wrench:` when updating configurations

## Adding New Integrations

### Built-in Integrations

1. Create a new file in the `integrations` directory (e.g., `myintegration.go`).
2. Implement the `Integration` interface:
```go
type MyIntegration struct {
 // Your fields here
}

func (m *MyIntegration) Name() string { 
 return "myintegration" 
}

// Initialize your integration
func (m *MyIntegration) Initialize(cfg map[string]interface{}) error {
 ...
}

// Notify about a new attack
func (m *MyIntegration) NotifyNewAttack(ctx context.Context, attack *neoprotect.Attack) error {
 ...
}

// Notify about an attack update
func (m *MyIntegration) NotifyAttackUpdate(ctx context.Context, attack *neoprotect.Attack, previous *neoprotect.Attack) error {
 ...
}

// Notify about an attack ending
func (m *MyIntegration) NotifyAttackEnded(ctx context.Context, attack *neoprotect.Attack) error {
 ...
}
```
3. Register your integration in `integrations/manager.go` by adding it to the `builtIns` map in the `loadBuiltInIntegrations` function.
4. Add configuration documentation to the README.

## Testing

* Write unit tests for all new functions
* Make sure existing tests pass
* Mock external dependencies when appropriate
* Test edge cases and error conditions
* Aim for good test coverage

## Financial Contributions

If you'd like to support this project financially, you can donate to the project maintainers or the MsCode Team. For more information, please contact us directly.

## Questions?

If you have any questions, please create an issue or contact a project maintainer directly.

---

Thank you for your interest in contributing to NeoProtect Notifier! We look forward to your contributions.