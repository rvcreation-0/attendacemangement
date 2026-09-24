# Webcraft Attendance System

The supplied Webcraft attendance portal is served with MongoDB-backed state. The MongoDB connection string stays on the server and is never sent to the browser.

## Start

1. Install packages: `npm install`
2. Copy `.env.example` to `.env`, then set `MONGODB_URI` to the MongoDB URL supplied separately.
3. Run `npm start` and open `http://localhost:4173`.

## Deploy to Netlify

This project is configured to deploy the browser app and Express API together:

1. Push the project to GitHub, GitLab, or Bitbucket.
2. In Netlify, choose **Add new project** and import the repository.
3. Keep the build settings from `netlify.toml` (`public` as the publish directory and `netlify/functions` as the functions directory).
4. Add `MONGODB_URI` in **Project configuration > Environment variables**. Add `MONGODB_DB` only if the default database name is not suitable.
5. Deploy the site. Netlify routes `/api/*` to the Express function automatically.

The local `npm start` workflow remains available. The deployed site requires a MongoDB connection because accounts, sessions, batches, and attendance records are stored server-side.

There are no demo accounts or sample records. On the first visit, create the initial administrator with a unique email and a password of at least 8 characters. Passwords are salted and hashed with Node's `scrypt` before storage in MongoDB.

Sign-in is limited to five attempts per email/IP address every 15 minutes. Sessions are HTTP-only cookies stored server-side in MongoDB and expire after seven days. Admins have full access, teachers can write attendance only for assigned batches, and students are read-only.
