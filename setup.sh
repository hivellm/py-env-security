#!/bin/bash

# CMMV-Hive Setup Script
# This script sets up the development environment for BIP-02 implementation

set -e

echo "🚀 CMMV-Hive BIP-02 Setup Script"
echo "================================="

# Check if pnpm is installed
if ! command -v pnpm &> /dev/null; then
    echo "❌ pnpm is not installed. Please install pnpm first:"
    echo "npm install -g pnpm"
    exit 1
fi

echo "✅ pnpm found: $(pnpm --version)"

# Check Node.js version
NODE_VERSION=$(node --version | cut -d'v' -f2)
REQUIRED_VERSION="18.0.0"

if ! command -v node &> /dev/null; then
    echo "❌ Node.js is not installed. Please install Node.js 18+ first."
    exit 1
fi

echo "✅ Node.js found: v$NODE_VERSION"

# Install dependencies
echo "📦 Installing dependencies..."
pnpm install

# Build shared types first
echo "🏗️  Building shared types..."
pnpm --filter @cmmv-hive/shared-types build

# Setup Git hooks
echo "🔧 Setting up Git hooks..."
if [ -d ".git" ]; then
    pnpm husky install
    echo "✅ Git hooks configured"
else
    echo "⚠️  Not a Git repository, skipping Git hooks setup"
fi

# Run initial linting
echo "🔍 Running initial lint check..."
pnpm lint

# Run initial tests
echo "🧪 Running initial tests..."
pnpm test

echo ""
echo "🎉 Setup completed successfully!"
echo ""
echo "Next steps:"
echo "1. Run 'pnpm dev' to start development mode"
echo "2. Run 'pnpm test:watch' to start test watching"
echo "3. Check the implementation plan: bips/BIP-02/BIP-02-implementation-plan.md"
echo ""
echo "Happy coding! 🚀"