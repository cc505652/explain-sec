# 🔐 Authentication Setup Guide

## Quick Login (Recommended)

The application now includes **Quick Login buttons** that automatically create test users if they don't exist:

### 🎯 One-Click Login Options

1. **Login as Admin** (Blue button)
   - Email: `admin@test.com`
   - Password: `test1234`
   - Role: `admin`
   - Access: SOC Manager Console

2. **Login as Analyst** (Red button)
   - Email: `analyst@test.com`
   - Password: `Test@1234`
   - Role: `analyst`
   - Access: SOC Analyst Console

3. **Login as Student** (Green button)
   - Email: `student@test.com`
   - Password: `test1234`
   - Role: `student`
   - Access: Submit Issue + Issue List

## 🔧 Manual Login

You can also use the regular login form with the same credentials.

## 🚀 What Happens Behind the Scenes

- **First Time**: If user doesn't exist, the system automatically creates them
- **Subsequent Logins**: Direct authentication
- **Role Assignment**: Automatically set based on the test account
- **Firestore Document**: User profile created in `users/{uid}` collection

## 🛠 Development Notes

- Users are created in Firebase Authentication
- User roles are stored in Firestore
- Auto-creation only works for the test accounts above
- New users (outside test accounts) default to `student` role

## 🔍 Troubleshooting

If you see authentication errors:
1. Use the Quick Login buttons (recommended)
2. Check browser console for detailed error messages
3. Ensure Firebase is properly configured
4. Try refreshing the page and logging in again

---

**🎉 Ready to test! Use the Quick Login buttons for instant access.**
