#!/bin/bash

# Deploy Firestore Security Rules
echo "🔒 Deploying Firestore Security Rules..."

# Check if Firebase CLI is installed
if ! command -v firebase &> /dev/null; then
    echo "❌ Firebase CLI not found. Please install it first:"
    echo "npm install -g firebase-tools"
    exit 1
fi

# Deploy only the Firestore rules
firebase deploy --only firestore:rules

echo "✅ Firestore Security Rules deployed successfully!"
echo ""
echo "📋 Rules Summary:"
echo "- Admin users can archive incidents (isDeleted: true)"
echo "- Admin users can modify: isDeleted, assignedTeam, status, containmentRequested, urgency"
echo "- Assigned analysts can modify their own incidents"
echo "- Delete operations are disabled (soft delete only)"
echo "- Team-based read access maintained"
