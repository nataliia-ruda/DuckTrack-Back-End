# DuckTrack (Back-End)

DuckTrack is a web application that helps users store, organize, and track job applications in one place. It provides a clear overview of application statuses, progress, and key metrics throughout the job-search process.

This repository contains the back-end part of the application, responsible for authentication, data storage, and business logic served over a REST API.

Frontend repository: https://github.com/nataliia-ruda/DuckTrack-Front-End

## Features

- User authentication (registration, login, logout, session management)
- Email verification flow for new accounts
- Password reset via email (forgot/reset password)
- Account deletion requests with email confirmation
- CRUD operations for job applications
- Interview tracking linked to applications (create, update, delete)
- Employer information lookup
- User profile retrieval and updates
- Scheduled background jobs (node-cron) for:
  - Daily application status checks
  - Daily interview reminders
  - Hourly cleanup of expired tokens

## Technologies

- Node.js + Express (REST API)
- MySQL (mysql2) — data storage
- express-session + express-mysql-session — session-based authentication
- bcrypt — password hashing
- nodemailer — transactional emails (verification, password reset, account deletion)
- node-cron — scheduled background jobs
- dotenv — environment configuration
- cors — cross-origin request handling

## Getting Started

```
git clone https://github.com/nataliia-ruda/DuckTrack-Back-End.git
cd DuckTrack-Back-End
npm install
```

