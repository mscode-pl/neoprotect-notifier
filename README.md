# NeoProtect Attack Notifier 🛡️

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Go Report Card](https://goreportcard.com/badge/github.com/mscode-pl/neoprotect-notifier)](https://goreportcard.com/report/github.com/mscode-pl/neoprotect-notifier)
[![Go Version](https://img.shields.io/github/go-mod/go-version/mscode-pl/neoprotect-notifier)](https://go.dev/)

A real-time monitoring and notification system for DDoS attacks detected by the NeoProtect API. Stay informed instantly about threats to your infrastructure through customizable alerts.

## 📋 Features

- **Real-time attack monitoring** - Detect new attacks, updates, and ended attacks as they happen
- **Multiple integration options** - Built-in support for Discord, webhooks, emails, and console notifications
- **Modular architecture** - Easily extend with custom integrations using the plugin system
- **Complete or focused monitoring** - Monitor all IP addresses or only specific ones
- **Detailed attack information** - Get comprehensive data including attack signatures, traffic peaks, and duration
- **Lightweight and efficient** - Minimal resource footprint with optimized API interactions

## 🔔 Integration Expansion

| Integration        |       Status       | Priority | Notes                                           |
|:-------------------|:------------------:|:--------:|:------------------------------------------------|
| 🤖 Discord Bot     | 🟡 Partially Ready |   High   | Fully implemented and tested (without commands) |
| 📢 Discord Webhook | 🟡 Partially Ready |  Medium  | Needs thorough testing                          |
| 📨 Telegram        |   🔲 Not Started   |  Medium  | Planned                                         |
| 📧 SMTP Email      |   🔲 Not Started   |  Medium  | Planned                                         |
| 📱 SMS Alerts      |   🔲 Not Started   |   Low    | Planned                                         |
| 🌐 Custom Webhook  | 🟡 Partially Ready |   Low    | Basic implementation requires refinement        |

## 🛠️ Platform & Infrastructure Improvements

| Feature                   |     Status     | Priority | Impact                               |
|:--------------------------|:--------------:|:--------:|:-------------------------------------|
| 🐳 Docker Support         | 🔲 Not Started |   Low    | Improve deployment flexibility       |
| 🧪 Comprehensive Testing  | 🔲 Not Started | Critical | Ensure system reliability            |
| 🔗 Attack Context Linking | 🔲 Not Started |  Medium  | Provide links to attack in dashboard |

## 🎨 User Experience Enhancements

| Feature                          |   Status   | Priority | Goal                                  |
|:---------------------------------|:----------:|:--------:|:--------------------------------------|
| 🌈 Enhanced Console Output       | 🟡 Partial |   Low    | Implement rich, colorful logging      |
| 🖌️ Discord Notification Styling | 🟡 Partial |  Medium  | Improve visual presentation of alerts |

## 🚀 Prioritization Legend
- 🔲 Not Started
- 🟡 Partially Complete
- ✅ Completed
- 🔥 High Priority
- 🌟 Medium Priority
- 💡 Low Priority

**Last Updated**: 17 March 2024 01:10 Europe/Warsaw

## 🚀 Quick Start

### Installation

**Option 1: Download pre-built binary**

Download the latest release for your operating system from our [GitHub Releases page](https://github.com/mscode-pl/neoprotect-notifier/releases).

```bash
# Make the binary executable (Linux/macOS)
chmod +x neoprotect-notifier

# Run the application
./neoprotect-notifier -config=config.json
```

**Option 2: Build from source**

```bash
# Clone the repository
git clone https://github.com/mscode-pl/neoprotect-notifier.git
cd neoprotect-notifier

# Build the application
go build -o neoprotect-notifier
```

### Configuration

Create a `config.json` file in the application directory:

```json
{
   "apiKey": "your-neoprotect-api-key",
   "apiEndpoint": "https://api.neoprotect.net/v2",
   "pollIntervalSeconds": 60,
   "monitorMode": "all",
   "specificIPs": [
      "192.168.1.1"
   ],
   "enabledIntegrations": [
      "discord",
      "webhook",
      "console"
   ],
   "integrationConfigs": {
      "discord": {
         "webhookUrl": "https://discord.com/api/webhooks/YOUR/DISCORD/WEBHOOK",
         "username": "NeoProtect Monitor"
      }
   }
}
```

### Running the Application

```bash
./neoprotect-notifier -config=config.json
```

## 🔧 Configuration Options

| Option                | Description                                       | Default                         |
|:----------------------|:--------------------------------------------------|:--------------------------------|
| `apiKey`              | Your NeoProtect API key                           | *Required*                      |
| `apiEndpoint`         | NeoProtect API URL                                | `https://api.neoprotect.net/v2` |
| `pollIntervalSeconds` | How often to check for attacks (in seconds)       | `60`                            |
| `monitorMode`         | Monitoring mode (`all` or `specific`)             | `all`                           |
| `specificIPs`         | List of IPs to monitor when using `specific` mode | `[]`                            |
| `enabledIntegrations` | List of integrations to enable                    | `[]`                            |
| `integrationConfigs`  | Configuration for each integration                | `{}`                            |

## 📢 Available Integrations

### Console

Simple console notifications with colored output.

```json
"console": {
  "logPrefix": "NEOPROTECT",
  "formatJson": false,
  "colorEnabled": true
}
```

### Discord (Webhook)

Send notifications to Discord channels.

```json
"discord": {
  "webhookUrl": "https://discord.com/api/webhooks/YOUR/DISCORD/WEBHOOK",
  "username": "NeoProtect Monitor",
  "avatarUrl": "https://example.com/avatar.png"
}
```

### Discord Bot

Send notifications to Discord channels, edits embeds for updates and ends.
Some commands are available for the bot, like `!attack <id>` to get more information about an attack.

```json
"discord_bot": {
   "token": "YOUR_DISCORD_BOT_TOKEN",
   "clientId": "YOUR_DISCORD_CLIENT_ID",
   "guildId": "YOUR_DISCORD_GUILD_ID",
   "channelId": "YOUR_DISCORD_CHANNEL_ID"
}
```

### Webhook

Send notifications to a custom HTTP endpoint.

```json
"webhook": {
  "url": "https://your-webhook-endpoint.com/notify",
  "headers": {
    "Authorization": "Bearer your-token-here",
    "Content-Type": "application/json"
  },
  "timeout": 10
}
```

## 🧩 Creating Custom Integrations

You can extend the system with custom integrations:

1. **Built-in Integration**:
   - Create a new file in the `integrations` package
   - Implement the `Integration` interface
   - Register it in the `integrations/manager.go` file

2. **Plugin Integration**: (Coming Soon)
   - Create a Go file with an exported `Integration` variable
   - Build it as a plugin: `go build -buildmode=plugin -o ./integrations/myplugin.so myplugin.go`
   - Add the plugin name to `enabledIntegrations` in config

## 🐳 Docker Support (Coming Soon)

```bash
# Build the Docker image
docker build -t neoprotect-notifier .

# Run with Docker
docker run -v $(pwd)/config.json:/app/config.json neoprotect-notifier
```

Or use docker-compose:

```yaml
version: '3'
services:
  neoprotect-notifier:
    build: .
    restart: unless-stopped
    volumes:
      - ./config.json:/app/config.json
```

## 🤝 Contributing

Contributions are welcome! Here's how you can help:

1. Fork the repository
2. Create a feature branch: `git checkout -b my-new-feature`
3. Commit your changes: `git commit -am 'Add some feature'`
4. Push to the branch: `git push origin my-new-feature`
5. Submit a pull request

Please read our [contributing guidelines](CONTRIBUTING.md) for more details.

## 🔖 Creating Releases

This project uses GitHub Actions to automatically build and publish releases for multiple platforms. To create a new release:

1. Update the version number in your code if applicable
2. Create and push a new tag with semver format:
   ```bash
   git tag v1.0.0
   git push origin v1.0.0
   ```
3. GitHub Actions will automatically:
   - Build binaries for Linux, macOS, and Windows (both amd64 and arm64 where applicable)
   - Create SHA256 checksums for all binaries
   - Package the binaries with example config files
   - Create a new release with all assets attached

The release will include:
- Linux binaries (amd64, arm64)
- macOS binaries (amd64, arm64)
- Windows binaries (amd64)
- Example configuration file
- SHA256 checksums for verification

---

**Made with ❤️ by [MsCode Team](https://mscode.pl)**